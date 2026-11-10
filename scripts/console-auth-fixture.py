#!/usr/bin/env python3
"""Loopback-only UI fixture; does not test OIDC, cookies, grants or real login.

Run instead of the API on port 8080 while Vite is on 5173. The managed-in
scenario presents synthetic session metadata and accepts only a CSRF-bearing
logout, so the console's session presentation can be checked independently.
"""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["managed-in", "managed-out", "development"], required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    csrf = "c" * 43

    class Fixture(BaseHTTPRequestHandler):
        signed_in = args.mode == "managed-in"

        def reply(self, status, body=None):
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/auth/config":
                self.reply(200, {"managed_login": args.mode != "development", "development_tokens": args.mode == "development"})
            elif self.path == "/auth/session":
                if Fixture.signed_in:
                    self.reply(200, {"authenticated": True, "csrf_token": csrf, "expires_at": int(time.time()) + 600})
                else:
                    self.reply(401, {"error": {"code": "unauthorized"}})
            elif self.path == "/v1/approvals" and Fixture.signed_in:
                self.reply(200, [])
            else:
                self.reply(404, {"error": {"code": "not_found"}})

        def do_POST(self):
            if self.path == "/auth/logout":
                valid = (self.headers.get("Origin") == "http://127.0.0.1:5173"
                         and self.headers.get("X-CSRF-Token") == csrf
                         and self.headers.get("Authorization") is None)
                print("fixture logout csrf=" + ("accepted" if valid else "rejected"), flush=True)
                if valid:
                    Fixture.signed_in = False
                    self.reply(204)
                else:
                    self.reply(403, {"error": {"code": "invalid_csrf_or_origin"}})
            else:
                self.reply(404, {"error": {"code": "not_found"}})

        def log_message(self, *_):
            pass

    print(f"Synthetic console presentation fixture on 127.0.0.1:{args.port}; mode={args.mode}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Fixture)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
