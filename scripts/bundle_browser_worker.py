"""Bundle only the public browser runtime and liboqs license for Cloudflare."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from shutil import copyfile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".build/browser-site"
FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.mjs": ("app.mjs", "text/javascript; charset=utf-8"),
    "/lab.mjs": ("lab.mjs", "text/javascript; charset=utf-8"),
    "/protocol.mjs": ("protocol.mjs", "text/javascript; charset=utf-8"),
    "/crypto.mjs": ("crypto.mjs", "text/javascript; charset=utf-8"),
    "/liboqs.mjs": ("liboqs.mjs", "text/javascript; charset=utf-8"),
    "/liboqs.wasm": ("liboqs.wasm", "application/wasm"),
    "/licenses/liboqs.txt": ("liboqs-license.txt", "text/plain; charset=utf-8"),
}


def build() -> None:
    for filename in (
        "index.html",
        "styles.css",
        "favicon.svg",
        "app.mjs",
        "lab.mjs",
        "protocol.mjs",
        "crypto.mjs",
    ):
        copyfile(ROOT / "browser" / filename, BUILD / filename)
    copyfile(ROOT / ".build/liboqs/LICENSE.txt", BUILD / "liboqs-license.txt")
    assets = {}
    for route, (name, content_type) in FILES.items():
        path = BUILD / name
        value = (
            base64.b64encode(path.read_bytes()).decode("ascii")
            if content_type == "application/wasm"
            else path.read_text()
        )
        assets[route] = [content_type, value]
    template = (ROOT / "browser/worker.mjs").read_text()
    marker = "/* ASSETS */ {}"
    if template.count(marker) != 1:
        raise ValueError("Expected one public asset marker")
    (ROOT / ".build/browser-worker.mjs").write_text(
        template.replace(marker, json.dumps(assets))
    )


if __name__ == "__main__":
    build()
