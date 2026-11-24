#!/usr/bin/env python3
"""
practice_server.py - a deliberately broken practice API for testing api_access_check.py.

Run it on YOUR computer, on localhost only:
    python3 practice_server.py
Then open another terminal and run the checker against http://localhost:8000.

Test users (use these tokens in the config):
    token-alice  -> user 1 (normal user)
    token-bob    -> user 2 (normal user)
    token-admin  -> user 3 (admin)

Some routes are BROKEN on purpose. See ANSWER_KEY.md for the list.
"""

import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))

USERS = {
    1: {"name": "alice", "role": "user", "email": "alice@practice.local"},
    2: {"name": "bob", "role": "user", "email": "bob@practice.local"},
    3: {"name": "admin", "role": "admin", "email": "admin@practice.local"},
}
TOKENS = {"token-alice": 1, "token-bob": 2, "token-admin": 3}
ORDERS = {
    101: {"owner": 1, "item": "keyboard"},
    102: {"owner": 2, "item": "mouse"},
}


class PracticeHandler(BaseHTTPRequestHandler):
    def _cors(self):
        # Lets the browser checker page call this API from another origin.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _current_user(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        return TOKENS.get(token)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        uid = self._current_user()

        # Serve the browser checker page at http://localhost:8000/
        if path in ("", "/checker", "/index.html"):
            with open(os.path.join(HERE, "checker.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # BUG 1 (broken authentication): no login check at all.
        if path == "/api/profile":
            target = uid or 1
            return self._send(200, {"id": target, **USERS[target]})

        # BUG 2 (broken function-level access): any logged-in user gets the admin list.
        if path == "/api/admin/users":
            if uid is None:
                return self._send(401, {"error": "login required"})
            return self._send(200, [{"id": k, **v} for k, v in USERS.items()])

        # BUG 3 (broken object-level access, BOLA): any logged-in user can read any user.
        m = re.fullmatch(r"/api/users/(\d+)", path)
        if m:
            if uid is None:
                return self._send(401, {"error": "login required"})
            i = int(m.group(1))
            if i not in USERS:
                return self._send(404, {"error": "not found"})
            return self._send(200, {"id": i, **USERS[i]})

        # CORRECT example (no bug): orders are only shown to their owner or an admin.
        m = re.fullmatch(r"/api/orders/(\d+)", path)
        if m:
            if uid is None:
                return self._send(401, {"error": "login required"})
            order = ORDERS.get(int(m.group(1)))
            if order is None:
                return self._send(404, {"error": "not found"})
            if order["owner"] != uid and USERS[uid]["role"] != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, order)

        self._send(404, {"error": "no such route"})

    def log_message(self, format, *args):
        pass  # keep the terminal quiet


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), PracticeHandler)
    print("Practice API running at http://localhost:8000  (Ctrl+C to stop)")
    server.serve_forever()
