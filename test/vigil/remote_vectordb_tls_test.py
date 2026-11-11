"""TLS options of images/vigil-llm/remote_vectordb.py ([vectordb] ca_file,
tls_server_name), against a local HTTPS server with a self-signed
certificate issued for an IP the test never connects to: a Vigil outside
the cluster entering an ingress through a node address and verifying the
certificate of the ingress IP.

Stdlib + the openssl CLI; no Chroma, no network.
  python3 test/vigil/remote_vectordb_tls_test.py
"""
import http.server
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "images", "vigil-llm"))
from remote_vectordb import RemoteVectorDB, RemoteVectorDBError  # noqa: E402

CERT_IP = "10.66.51.11"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"auth": "%s"}' % self.headers.get("Authorization", "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class TLSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.cert = os.path.join(cls.dir.name, "tls.crt")
        key = os.path.join(cls.dir.name, "tls.key")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-days", "1", "-keyout", key, "-out", cls.cert, "-subj", "/CN=test ingress",
             "-addext", f"subjectAltName=IP:{CERT_IP}", "-addext", "basicConstraints=critical,CA:TRUE"],
            check=True, capture_output=True)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, key)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"https://127.0.0.1:{cls.server.server_address[1]}/chroma"
        os.environ["TLS_TEST_TOKEN"] = "t" * 40

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.dir.cleanup()

    def db(self, **kw):
        return RemoteVectorDB(model="unused", chroma_url=self.url, embed_fn=lambda ts: [[0.0] for _ in ts],
                              token_env="TLS_TEST_TOKEN", timeout_s="3", **kw)

    def test_pinned_name_and_ca_verify_and_send_the_token(self):
        got = self.db(ca_file=self.cert, tls_server_name=CERT_IP)._request("GET", self.url + "/api/v2/heartbeat")
        self.assertEqual(got["auth"], "Bearer " + "t" * 40)

    def test_name_mismatch_fails_closed_without_retrying(self):
        start = time.time()
        with self.assertRaises(RemoteVectorDBError):
            self.db(ca_file=self.cert)._request("GET", self.url + "/api/v2/heartbeat")  # cert is not for 127.0.0.1
        self.assertLess(time.time() - start, 2)

    def test_untrusted_certificate_fails_closed(self):
        with self.assertRaises(RemoteVectorDBError):
            self.db(tls_server_name=CERT_IP)._request("GET", self.url + "/api/v2/heartbeat")  # system CAs only

    def test_wrong_pinned_name_fails_closed(self):
        with self.assertRaises(RemoteVectorDBError):
            self.db(ca_file=self.cert, tls_server_name="10.66.51.12")._request("GET", self.url + "/api/v2/heartbeat")


if __name__ == "__main__":
    unittest.main()
