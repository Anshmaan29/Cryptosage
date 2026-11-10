"""Read-only, bounded metadata view for the native relay."""

from collections import deque
from datetime import datetime, timezone
from html import escape
import re

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

FIELDS = ("time", "type", "from", "to", "bytes", "session", "counter", "ciphertext")
TYPES = {"offer", "response", "finish", "ack", "message", "delivery"}
ROUTING_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")


class Observer:
    def __init__(self) -> None:
        self.entries: deque[dict] = deque(maxlen=100)

    def record(self, packet: dict, raw: str | bytes) -> None:
        kind, sender, recipient = (packet.get(key) for key in ("type", "from", "to"))
        if (
            not isinstance(kind, str)
            or kind not in TYPES
            or not all(
                isinstance(name, str) and ROUTING_NAME.fullmatch(name)
                for name in (sender, recipient)
            )
        ):
            return
        sid, counter, ciphertext = (
            packet.get(key) for key in ("sid", "counter", "ciphertext")
        )
        preview = (
            ciphertext[:32]
            if kind in {"message", "response"} and isinstance(ciphertext, str)
            else ""
        )
        self.entries.append(
            {
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "type": kind,
                "from": sender,
                "to": recipient,
                "bytes": len(raw.encode() if isinstance(raw, str) else raw),
                "session": sid[:12]
                if isinstance(sid, str) and re.fullmatch(r"[0-9a-f]{64}", sid)
                else "",
                "counter": counter
                if type(counter) is int and 0 <= counter < 100
                else "",
                "ciphertext": preview
                if re.fullmatch(r"[A-Za-z0-9+/=]{0,32}", preview)
                else "",
            }
        )

    def app(self, port: int) -> FastAPI:
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        origins = {f"http://{host}" for host in hosts}
        headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }

        @app.get("/", response_class=HTMLResponse)
        async def index(request: Request):
            if (
                request.headers.get("host") not in hosts
                or request.headers.get("origin") not in origins | {None}
                or request.headers.get("sec-fetch-site") == "cross-site"
                or (
                    request.headers.get("sec-fetch-site") == "same-site"
                    and request.headers.get("sec-fetch-mode") != "navigate"
                )
            ):
                return HTMLResponse(
                    "Open the relay view directly on loopback.", 403, headers
                )
            columns = "".join(f"<th scope=col>{label}</th>" for label in FIELDS)
            rows = "".join(
                "<tr>"
                + "".join(f"<td>{escape(str(entry[field]))}</td>" for field in FIELDS)
                + "</tr>"
                for entry in reversed(self.entries)
            )
            return HTMLResponse(
                "<!doctype html><html lang=en><meta charset=utf-8>"
                '<meta name=viewport content="width=device-width,initial-scale=1">'
                "<meta http-equiv=refresh content=3><title>What the relay sees</title>"
                "<h1>What the relay sees</h1>"
                "<p>Up to 100 recent envelopes. Ciphertext previews contain up to 32 base64 characters. Refreshes every 3 seconds.</p>"
                f"<table><thead><tr>{columns}</tr></thead><tbody>{rows}</tbody></table>",
                headers=headers,
            )

        return app
