#!/usr/bin/env python3
"""
A deliberately dishonest web server for testing pipegaurd's disguise checks.

It only listens on 127.0.0.1 (your own machine) and only serves text.
Nothing is ever executed - pipegaurd just analyzes what it receives.

    python3 tests/disguise_server.py          # then, in another terminal:
    pipegaurd http://127.0.0.1:8000/          # lists the test URLs
"""
import http.server
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
PORT = 8000

with open(os.path.join(SAMPLES, "disguised_robots.txt"), "rb") as f:
    DISGUISED = f.read()
with open(os.path.join(SAMPLES, "evil_ssh_backdoor.sh"), "rb") as f:
    BACKDOOR = f.read()
REAL_ROBOTS = b"User-agent: *\nAllow: /\nDisallow: /v1/login\n\nSitemap: https://www.example.com/sitemap.xml\n"
FAKE_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 200

# path: (content type, extra headers, body, what it demonstrates)
ROUTES = {
    "/robots.txt": ("text/plain", {}, DISGUISED,
                    "commands hidden in a robots.txt         -> MASK001 + the real findings"),
    "/real-robots.txt": ("text/plain", {}, REAL_ROBOTS,
                         "a genuine robots.txt                    -> no disguise findings"),
    "/logo.png": ("image/png", {}, BACKDOOR,
                  "script served with Content-Type image/png -> MASK001 (was skipped before v0.4.0)"),
    "/report.pdf": ("application/pdf", {"Content-Disposition": 'attachment; filename="update.sh"'}, BACKDOOR,
                    "URL says .pdf, server sends update.sh  -> MASK001 + MASK002"),
    "/invoice.pdf.sh": ("text/plain", {}, BACKDOOR,
                        "double extension                       -> MASK004"),
    "/installer.sh": ("text/x-sh", {}, FAKE_ELF,
                      "named .sh but it's a Linux binary      -> MASK003"),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ROUTES:
            ctype, headers, body, _ = ROUTES[self.path]
        else:
            ctype, headers = "text/plain", {}
            lines = ["Test URLs (run each with pipegaurd):", ""]
            lines += ["  pipegaurd http://127.0.0.1:%d%-18s %s" % (PORT, p, r[3]) for p, r in ROUTES.items()]
            body = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("  served", self.path)


if __name__ == "__main__":
    print("Dishonest test server on http://127.0.0.1:%d/  (Ctrl+C to stop)" % PORT)
    http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()