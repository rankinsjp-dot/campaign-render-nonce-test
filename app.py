"""Disposable nonce fixture only. No Engine, persistence, outbound calls or identity trust."""
import hmac
import json
import os
import secrets
import sys
from wsgiref.simple_server import WSGIRequestHandler, make_server

VERSION = "wo013-pq1-nonce-1"

def create_app(secret):
    if not isinstance(secret, str) or not 32 <= len(secret) <= 256 or not secret.isascii() or secret.strip() != secret:
        raise ValueError("BRIDGE_SECRET must be 32-256 ASCII characters without edge whitespace")
    expected = ("Bearer " + secret).encode("ascii")

    def app(env, start_response):
        def reply(status, payload):
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            start_response(status, [("Content-Type", "application/json"),
                ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff")])
            return [data]
        if env.get("REQUEST_METHOD") != "GET":
            return reply("405 Method Not Allowed", {"error": "method_not_allowed"})
        if env.get("QUERY_STRING") or env.get("CONTENT_LENGTH", "") not in ("", "0") or env.get("HTTP_TRANSFER_ENCODING"):
            return reply("400 Bad Request", {"error": "body_or_query_not_allowed"})
        path = env.get("PATH_INFO", "")
        if path == "/healthz":
            return reply("200 OK", {"status": "ok"})
        if path != "/nonce":
            return reply("404 Not Found", {"error": "not_found"})
        supplied = env.get("HTTP_AUTHORIZATION", "")
        if not isinstance(supplied, str) or len(supplied) > 263 or not supplied.isascii() or not hmac.compare_digest(supplied.encode("ascii"), expected):
            return reply("401 Unauthorized", {"error": "unauthorized"})
        # No request identity/header/body is echoed or used for owner authorization.
        return reply("200 OK", {"nonce": secrets.token_hex(16), "version": VERSION})
    return app

class QuietHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass  # Never log headers, credential values, paths or query strings.
    def handle(self):
        self.connection.settimeout(5)
        super().handle()

def main():
    try:
        app = create_app(os.environ.get("BRIDGE_SECRET"))
        port = int(os.environ.get("PORT", "10000"))
        if not 1 <= port <= 65535:
            raise ValueError("invalid PORT")
    except (ValueError, TypeError):
        print("Invalid required BRIDGE_SECRET or PORT configuration", file=sys.stderr)
        return 2
    # Single process, standard-library demo server; TLS terminates at Render.
    with make_server("0.0.0.0", port, app, handler_class=QuietHandler) as server:
        server.serve_forever()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
