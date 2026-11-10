"""Loopback-only FastAPI adapter. Private operations remain in this client process."""

from __future__ import annotations
import argparse
import asyncio
from io import BytesIO
from ipaddress import IPv4Address, IPv4Network

import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
import segno
import uvicorn
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message as ASGIMessage, Receive, Scope, Send
from pydantic import BaseModel, ConfigDict, Field
from client.runtime import Client
from client.storage import private_lock
from protocol.identity import canonical, valid_name

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 65_536
LAN_RANGES = tuple(
    IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Contact(StrictModel):
    peer: str = Field(min_length=1, max_length=32)


class ContactCard(StrictModel):
    name: str = Field(min_length=1, max_length=32)
    public: str = Field(max_length=3000)
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class Trust(Contact):
    fingerprint: str = Field(min_length=64, max_length=100)
    replace: bool = False
    previous_fingerprint: str | None = None


class Message(Contact):
    session_id: str = Field(min_length=64, max_length=64)
    text: str = Field(min_length=1, max_length=16384)


class Scenario(StrictModel):
    scenario: str


class Benchmark(StrictModel):
    trials: int = Field(default=30, ge=2, le=1000)
    delay_ms: int = Field(default=0, ge=0, le=250)
    profile: Literal["localhost", "moderate", "constrained"] | None = None


class LocalBoundary:
    def __init__(self, app: ASGIApp, *, port: int, token: str):
        self.app = app
        self.hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.origins = {f"http://{host}" for host in self.hosts}
        self.token = token.encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)

        async def secured_send(message: ASGIMessage) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).update(
                    {
                        "Cache-Control": "no-store",
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                        "Referrer-Policy": "no-referrer",
                        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                    }
                )
            await send(message)

        async def reject(detail: str, status: int) -> None:
            await JSONResponse({"detail": detail}, status)(scope, receive, secured_send)

        if request.headers.get("host") not in self.hosts or (
            request.client
            and request.client.host not in {"127.0.0.1", "::1", "testclient"}
        ):
            await reject("Local client Host or address rejected", 403)
            return
        origin = request.headers.get("origin")
        if origin is not None and origin not in self.origins:
            await reject("Untrusted local API origin", 403)
            return
        if request.headers.get("sec-fetch-site") in {"cross-site", "same-site"}:
            await reject("Cross-origin local API request rejected", 403)
            return
        if request.method in {"GET", "HEAD"}:
            await self.app(scope, receive, secured_send)
            return
        supplied = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(supplied.encode(), self.token):
            await reject("Missing local application token", 403)
            return
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            await reject("JSON content type required", 415)
            return
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            length = -1
        if length < 0:
            await reject("Invalid content length", 400)
            return
        if length > MAX_BODY:
            await reject("Request too large", 413)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_BODY:
                await reject("Request too large", 413)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        payload: bytes | None = bytes(body)

        async def bounded_receive() -> ASGIMessage:
            nonlocal payload
            if payload is None:
                return await receive()
            result = {"type": "http.request", "body": payload, "more_body": False}
            payload = None
            return result

        await self.app(scope, bounded_receive, secured_send)


def create_app(
    name="Alice",
    port=8001,
    data_dir=None,
    contacts_dir=None,
    relay="ws://127.0.0.1:8765",
    policy_path=None,
):
    local = Client(
        name,
        Path(data_dir or ROOT / ".runtime" / name),
        Path(contacts_dir or ROOT / ".runtime/contacts"),
        relay,
        policy_path,
    )
    token = secrets.token_urlsafe(32)
    reports = Path(os.environ.get("CRYTOSAGE_REPORT_DIR", ROOT / "reports")).resolve()
    benchmarks = reports / ("benchmarks-" + local.identity.name)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(local.run())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app = FastAPI(
        title="Crytosage local client",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.client = local

    app.add_middleware(LocalBoundary, port=port, token=token)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        return JSONResponse(
            {
                "detail": [
                    {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
                    for error in exc.errors()
                ]
            },
            422,
        )

    @app.exception_handler(ValueError)
    async def rejected(request, exc):
        return JSONResponse({"detail": str(exc)}, 400)

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "client/static/index.html")

    @app.get("/api/state")
    async def state():
        async with local.lock:
            return {**local.state(), "csrf_token": token}

    @app.get("/api/contact-card.json")
    async def export_contact():
        return JSONResponse(
            local.contact_card(),
            headers={
                "Content-Disposition": f'attachment; filename="{local.identity.name}-contact.json"'
            },
        )

    @app.get("/api/contact-card.svg")
    def contact_qr():
        card = canonical(local.contact_card())
        output = BytesIO()
        segno.make_qr(card, error="L", boost_error=False).save(
            output, kind="svg", scale=4, light="white"
        )
        return Response(output.getvalue(), media_type="image/svg+xml")

    @app.post("/api/contacts")
    async def import_contact(body: ContactCard):
        async with local.lock:
            local.import_contact(body.model_dump())
        return {"name": body.name}

    @app.post("/api/trust")
    async def trust(body: Trust):
        async with local.lock:
            local.trust(
                body.peer, body.fingerprint, body.replace, body.previous_fingerprint
            )
        return {"status": "verified"}

    @app.post("/api/connect")
    async def establish(body: Contact):
        return await local.establish(body.peer)

    @app.post("/api/message")
    async def message(body: Message):
        return await local.send(body.text, body.peer, body.session_id)

    @app.post("/api/message/{message_id}/retry")
    async def retry(message_id: str, body: dict):
        if body:
            raise ValueError("Retry does not accept options")
        return await local.retry(message_id)

    @app.post("/api/rekey")
    async def rekey(body: dict):
        if body:
            raise ValueError("Re-key does not accept options")
        if not local.peer.session:
            raise ValueError("No session to re-key")
        remote = local.peer.session.peer
        local.event("rekey", "Fresh signed post-quantum handshake requested")
        return await local.establish(remote)

    @app.get("/api/attacks")
    async def attack_catalog():
        from attacks.simulator import CATALOG

        return CATALOG

    @app.get("/api/policy")
    async def get_policy():
        from policy.manager import safe_defaults

        return {
            "policy": local.peer.policy,
            "defaults": safe_defaults(),
            "pending_effect": "new_sessions_only",
        }

    @app.post("/api/policy")
    async def update_policy(body: dict):
        from policy.manager import save_policy

        if set(body) != {"policy", "confirm_restrictions"}:
            raise ValueError("Policy and explicit confirmation are required")
        async with local.lock:
            local.peer.policy = save_policy(
                local.policy_path,
                body["policy"],
                local.peer.policy,
                body["confirm_restrictions"],
            )
        local.event("policy", "Policy saved for new sessions")
        return {"policy": local.peer.policy, "pending_effect": "new_sessions_only"}

    @app.post("/api/policy/reset")
    async def reset_policy(body: dict):
        from policy.manager import save_policy, safe_defaults

        if set(body) - {"confirm_restrictions"}:
            raise ValueError("Invalid reset options")
        async with local.lock:
            local.peer.policy = save_policy(
                local.policy_path,
                safe_defaults(),
                local.peer.policy,
                body.get("confirm_restrictions", False),
            )
        local.event("policy", "Safe default policy restored for new sessions")
        return {"policy": local.peer.policy, "pending_effect": "new_sessions_only"}

    @app.get("/api/export/{name}")
    async def export(name: str):
        paths = {
            "benchmarks.json": benchmarks / "results.json",
            "benchmarks.csv": benchmarks / "trials.csv",
            "benchmarks.html": benchmarks / "report.html",
            "benchmarks.zip": benchmarks / "report.zip",
            "security.html": reports / "security-tests.html",
            "security.json": reports / "security-tests.json",
        }
        if name not in paths or not paths[name].is_file():
            return JSONResponse(
                {"detail": "Report is unavailable; run the relevant evaluation first"},
                404,
            )
        return FileResponse(paths[name], filename=name)

    @app.post("/api/attack")
    async def attack(body: Scenario):
        from attacks.simulator import run_scenario

        result = await asyncio.to_thread(run_scenario, body.scenario)
        local.attack_results.append(result)
        local.event(
            "attack",
            f"Isolated lab: {body.scenario}: {result.get('reason', 'No result')}",
        )
        return result

    @app.post("/api/benchmark")
    async def benchmark(body: Benchmark):
        if local.benchmark_busy:
            raise ValueError("A benchmark is already running")
        local.benchmark_busy = True
        try:
            from benchmarks.runner import run
            from benchmarks.protocol_adapter import factory

            callback, directory = await asyncio.to_thread(
                factory, delay_ms=body.delay_ms, profile=body.profile
            )
            try:
                local.benchmarks = await asyncio.to_thread(
                    run,
                    body.trials,
                    benchmarks,
                    handshake_factory=callback,
                )
            finally:
                directory.cleanup()
            local.peer.measurements = local.benchmarks["selection_measurements"]
            local.event(
                "benchmark",
                f"{body.trials} real trials per available level-3 KEM completed",
            )
            return local.benchmarks
        finally:
            local.benchmark_busy = False

    @app.get("/api/benchmarks")
    async def results():
        return local.benchmarks or {"algorithms": [], "status": "not_run"}

    @app.get("/api/report")
    async def report():
        from client.reports import test_results

        return {
            **test_results(reports / "tests.xml"),
            "attacks": local.attack_results,
            "benchmark": local.benchmarks,
            "events": list(local.events),
            "prototype": True,
        }

    app.mount(
        "/static",
        StaticFiles(directory=ROOT / "client/static", check_dir=False),
        name="static",
    )
    return app


def local_relay_url(value: str, *, lan: bool = False) -> bool:
    try:
        url = urlsplit(value)
        address = IPv4Address(url.hostname or "")
        permitted = str(address) == "127.0.0.1" or (
            lan and any(address in network for network in LAN_RANGES)
        )
        return (
            url.scheme == "ws"
            and permitted
            and url.port is not None
            and url.port > 0
            and url.username is None
            and url.password is None
            and url.path in ("", "/")
            and not url.query
            and not url.fragment
        )
    except ValueError:
        return False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--data-dir", type=Path)
    p.add_argument("--contacts-dir", type=Path)
    p.add_argument("--relay", default="ws://127.0.0.1:8765")
    p.add_argument("--policy", type=Path)
    p.add_argument(
        "--lan", action="store_true", help="Allow a relay at a private IPv4 address"
    )
    a = p.parse_args()
    if not local_relay_url(a.relay, lan=a.lan):
        p.error(
            "Use a ws://127.0.0.1 relay URL, or pass --lan for a private IPv4 relay"
        )
    try:
        data_dir = a.data_dir or ROOT / ".runtime" / valid_name(a.name)
        with private_lock(
            data_dir / ".client.lock", "This profile is already open in another client"
        ):
            uvicorn.run(
                create_app(a.name, a.port, data_dir, a.contacts_dir, a.relay, a.policy),
                host="127.0.0.1",
                port=a.port,
                access_log=False,
            )
    except (ValueError, OSError) as exc:
        p.exit(1, f"Client startup failed: {exc}\n")


if __name__ == "__main__":
    main()
