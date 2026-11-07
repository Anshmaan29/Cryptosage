"""Loopback-only FastAPI adapter. Private operations remain in this client process."""

from __future__ import annotations
import argparse
import asyncio
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
import uvicorn
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from client.runtime import Client

ROOT = Path(__file__).resolve().parents[1]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Contact(StrictModel):
    peer: str = Field(min_length=1, max_length=32)


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
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{host}" for host in allowed}

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(local.run())
        yield
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

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.headers.get("host") not in allowed or (
            request.client
            and request.client.host not in {"127.0.0.1", "::1", "testclient"}
        ):
            return JSONResponse(
                {"detail": "Local client Host or address rejected"}, 403
            )
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            return JSONResponse({"detail": "Untrusted local API origin"}, 403)
        if request.headers.get("sec-fetch-site") in {"cross-site", "same-site"}:
            return JSONResponse(
                {"detail": "Cross-origin local API request rejected"}, 403
            )
        if request.method not in {"GET", "HEAD"}:
            supplied = request.headers.get("x-csrf-token", "")
            if not secrets.compare_digest(supplied, token):
                return JSONResponse({"detail": "Missing local application token"}, 403)
            if (
                request.headers.get("content-type", "").split(";")[0]
                != "application/json"
            ):
                return JSONResponse({"detail": "JSON content type required"}, 415)
            try:
                length = int(request.headers.get("content-length", "0"))
            except ValueError:
                return JSONResponse({"detail": "Invalid content length"}, 400)
            if length < 0:
                return JSONResponse({"detail": "Invalid content length"}, 400)
            if length > 65536 or len(await request.body()) > 65536:
                return JSONResponse({"detail": "Request too large"}, 413)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    @app.exception_handler(ValueError)
    async def rejected(request, exc):
        return JSONResponse({"detail": str(exc)}, 400)

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "client/static/index.html")

    @app.get("/api/state")
    async def state():
        return {**local.state(), "csrf_token": token}

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
        item = next((m for m in local.messages if m.get("id") == message_id), None)
        if not item or item.get("status") != "failed":
            raise ValueError("Only failed messages can be resent")
        session = local.peer.session
        if not session or session.peer != item.get("peer"):
            raise ValueError(
                "Establish a new session with this contact before resending"
            )
        return await local.send(item["text"], session.peer, session.session_id)

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
            "benchmarks.json": ROOT
            / "reports"
            / ("benchmarks-" + local.identity.name)
            / "results.json",
            "benchmarks.csv": ROOT
            / "reports"
            / ("benchmarks-" + local.identity.name)
            / "trials.csv",
            "benchmarks.html": ROOT
            / "reports"
            / ("benchmarks-" + local.identity.name)
            / "report.html",
            "benchmarks.zip": ROOT
            / "reports"
            / ("benchmarks-" + local.identity.name)
            / "report.zip",
            "security.html": ROOT / "reports/security-tests.html",
            "security.json": ROOT / "reports/security-tests.json",
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
                factory, delay_ms=body.delay_ms
            )
            try:
                local.benchmarks = await asyncio.to_thread(
                    run,
                    body.trials,
                    ROOT / "reports" / ("benchmarks-" + name),
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
            **test_results(ROOT / "reports/tests.xml"),
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


def local_relay_url(value: str) -> bool:
    try:
        url = urlsplit(value)
        return (
            url.scheme == "ws"
            and url.hostname == "127.0.0.1"
            and url.port is not None
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
    a = p.parse_args()
    if not local_relay_url(a.relay):
        p.error("The research demo relay must use a loopback ws://127.0.0.1 URL")
    uvicorn.run(
        create_app(a.name, a.port, a.data_dir, a.contacts_dir, a.relay, a.policy),
        host="127.0.0.1",
        port=a.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
