#!/usr/bin/env python3
"""An Azure-shaped blob endpoint that verifies the SharedKey signature it receives.

    fake_blob.py <port> <log> <account> <base64-key> [--status 201]

It rebuilds the canonical string from the request and compares the HMAC — a wrong canonical string in the atom shows
up here as a 403 with the expected-vs-got signature in the log, instead of a bare 403 in production.
"""
import base64
import hashlib
import hmac
import http.server
import json
import sys

port, log_path, account, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
status = 201
args = sys.argv[5:]
while args:
    if args.pop(0) == "--status":
        status = int(args.pop(0))


def expected_signature(verb, content_length, content_type, ms_headers, resource):
    fields = [verb, "", "", str(content_length), "", content_type, "", "", "", "", "", ""]
    text = "\n".join(fields) + "\n"
    for name in sorted(ms_headers):
        if name.startswith("x-ms-"):
            text += f"{name.lower()}:{ms_headers[name].strip()}\n"
    text += resource
    digest = hmac.new(base64.b64decode(key), text.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii"), text


class Handler(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        ms_headers = {k: v for k, v in self.headers.items() if k.lower().startswith("x-ms-")}
        resource = "/" + account + self.path
        expected, signed_text = expected_signature("PUT", length, self.headers.get("Content-Type", ""),
                                                   ms_headers, resource)
        authorization = self.headers.get("Authorization", "")
        got = authorization.split(":", 1)[1] if ":" in authorization else ""
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps({
                "path": self.path,
                "signatureOk": got == expected,
                "canonical": signed_text,
                "contentType": self.headers.get("Content-Type"),
                "blobType": self.headers.get("x-ms-blob-type"),
                "ifNoneMatch": self.headers.get("If-None-Match"),
                "size": len(body),
            }) + "\n")
        if got != expected:
            self.send_response(403)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(b"<Error><Code>AuthenticationFailed</Code></Error>")
            return
        self.send_response(status)
        self.send_header("ETag", '"0x8D1"')
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
