FROM python:3.13-slim

WORKDIR /src

RUN apt update
RUN apt install -y git


COPY <<'EOF' main.py
"""Example vulnerable web app for testing llmpuffin audits."""

import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@example.com')")
    return conn


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/user":
            # Intentional SQL injection vulnerability
            user_id = params.get("id", ["1"])[0]
            db = get_db()
            cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
            row = cursor.fetchone()
            if row:
                # Intentional information disclosure: returns raw DB row
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(str(row).encode())
            else:
                self.send_response(404)
                self.end_headers()

        elif parsed.path == "/debug":
            # Intentional debug endpoint left in production
            import os
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(str(dict(os.environ)).encode())

        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
EOF

RUN git init
RUN git add .
RUN git config --global user.email "you@example.com"
RUN git config --global user.name "Your Name"
RUN git commit -m "Initial commit"
RUN git remote add origin https://github.com/example/git.git
