"""Local HTTP fixture for Android interop tests; never uses the user's Gateway.

Runs the shipped Core, HTTP routes, schema validation, password credential store,
and Ed25519 verifier. Only the host secret-store provider is a test double.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import mkdtemp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.adapter import AccountPasswordVerifier, create_gateway_request_verifier
from open_android_intelligence_gateway.admin import HostApiCompatibility, create_admin_service
from open_android_intelligence_gateway.core import create_gateway_core
from open_android_intelligence_gateway.http import create_gateway_exposure
from open_android_intelligence_gateway.local_keys import LocalMasterKeyStore
from test_support import make_secret_store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    storage = Path(mkdtemp(prefix="oai-android-interop-"))
    # Exercise the deployed key source when the operator configures one; the
    # in-process test double stays for the plain unit runs.
    key_file = os.environ.get("OAI_GATEWAY_MASTER_KEY_FILE")
    secret_store = LocalMasterKeyStore(key_file) if key_file else make_secret_store()
    core = create_gateway_core(storage, secret_store=secret_store)
    core.credential_verifier = AccountPasswordVerifier(core)
    compatibility = HostApiCompatibility("1.0.0", "1.0.0", "0123456789abcdef0123456789abcdef01234567")
    admin = create_admin_service(core=core, host_version="1.0.0", host_api=compatibility)
    created = admin.create_account({"accountId": "alice", "password": "android-fixture-only", "localConfirmation": True})
    if not created.get("ok", created.get("success", False)):
        # Preserve the real Admin response for diagnosing fixture setup.
        if "error" in created:
            raise RuntimeError(created)
    exposure = create_gateway_exposure("host-route", core=core, host_version="1.0.0", host_api=compatibility,
                                       verify_request=create_gateway_request_verifier(core))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self): self.dispatch()
        def do_POST(self): self.dispatch()
        def do_PUT(self): self.dispatch()
        def do_DELETE(self): self.dispatch()
        # Conversation rename (contract section 7) travels as PATCH; without this
        # handler the fixture would answer 501 and hide a real client defect.
        def do_PATCH(self): self.dispatch()

        def dispatch(self):
            content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            request = {"method": self.command, "url": self.path, "target": self.path,
                       "headers": dict(self.headers), "rawHeaders": tuple(self.headers.items()), "body": content}
            path = self.path.partition("?")[0]
            route = next((r for r in exposure.routes if
                          (r.match == "exact" and r.path == path) or
                          (r.match == "prefix" and path.startswith(r.path))), None)
            result = route._handle_raw(request) if route else {"statusCode": 404, "body": {"error": {"code": "NOT_FOUND"}}}
            status = result["statusCode"]
            body = result["body"]
            if path.endswith("/events") and status == 200 and "text/event-stream" in self.headers.get("Accept", ""):
                encoded = b": fixture connected\n\n"
                mime = "text/event-stream"
            else:
                encoded = json.dumps(body, ensure_ascii=False).encode()
                mime = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            print(json.dumps({"method": self.command, "path": path, "status": status,
                              "error": body.get("error", {}).get("code")}), file=sys.stderr, flush=True)

        def log_message(self, *_): pass

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
