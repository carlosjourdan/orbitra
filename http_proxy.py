#!/usr/bin/env python3
"""
Local HTTP proxy with request/response logging for network diagnostics.
Forwards all traffic through the upstream proxy defined in GLOBAL_AGENT_HTTP_PROXY.

Listens on: 127.0.0.1:18080
Logs to:    logs/http_proxy.log  (and stdout)
"""

import http.server
import http.client
import socketserver
import os
import sys
import logging
import urllib.parse
import socket
import ssl
import threading
import time

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PROXY] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "http_proxy.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("http_proxy")

# Dedicated logger for all proxy hosts/calls (append-only, one line per request)
_hosts_handler = logging.FileHandler(os.path.join(LOG_DIR, "proxy_hosts.log"))
_hosts_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
hosts_log = logging.getLogger("proxy_hosts")
hosts_log.addHandler(_hosts_handler)
hosts_log.setLevel(logging.INFO)
hosts_log.propagate = False

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18080

UPSTREAM_PROXY_URL = os.environ.get("GLOBAL_AGENT_HTTP_PROXY", "")


def parse_proxy_url(url):
    """Parse proxy URL into (host, port, auth_header)."""
    if not url:
        return None, None, None
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or 80
    auth_header = None
    if parsed.username:
        import base64
        credentials = f"{urllib.parse.unquote(parsed.username)}"
        if parsed.password:
            credentials += f":{urllib.parse.unquote(parsed.password)}"
        auth_header = "Basic " + base64.b64encode(credentials.encode()).decode()
    return host, port, auth_header


UPSTREAM_HOST, UPSTREAM_PORT, UPSTREAM_AUTH = parse_proxy_url(UPSTREAM_PROXY_URL)


class DiagnosticProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP proxy handler that logs and forwards requests."""

    timeout = 30

    def log_message(self, format, *args):
        log.info("%s - %s", self.address_string(), format % args)

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling."""
        target = self.path
        host = target.split(":")[0]
        log.info("CONNECT %s from %s", target, self.address_string())
        hosts_log.info("CONNECT host=%s target=%s client=%s", host, target, self.address_string())
        start = time.monotonic()

        try:
            if UPSTREAM_HOST:
                # Tunnel through upstream proxy
                upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=15)
                connect_req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                if UPSTREAM_AUTH:
                    connect_req += f"Proxy-Authorization: {UPSTREAM_AUTH}\r\n"
                connect_req += "\r\n"
                upstream.sendall(connect_req.encode())

                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = upstream.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                status_line = response.split(b"\r\n")[0].decode(errors="replace")
                status_code = int(status_line.split()[1])

                if status_code != 200:
                    elapsed = (time.monotonic() - start) * 1000
                    log.warning("CONNECT %s FAILED upstream=%s (%.0fms)", target, status_line, elapsed)
                    hosts_log.info("CONNECT host=%s status=FAILED upstream=%s elapsed=%.0fms", host, status_line, elapsed)
                    self.send_error(502, f"Upstream proxy refused: {status_line}")
                    upstream.close()
                    return
            else:
                # Direct connection
                host, port = target.split(":")
                upstream = socket.create_connection((host, int(port)), timeout=15)

            # Tunnel established
            elapsed = (time.monotonic() - start) * 1000
            log.info("CONNECT %s OK (%.0fms)", target, elapsed)
            hosts_log.info("CONNECT host=%s status=OK elapsed=%.0fms", host, elapsed)
            self.send_response(200, "Connection Established")
            self.end_headers()

            # Bidirectional forwarding
            self._tunnel(self.connection, upstream)
            upstream.close()

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            log.error("CONNECT %s ERROR: %s (%.0fms)", target, e, elapsed)
            hosts_log.info("CONNECT host=%s status=ERROR error=%s elapsed=%.0fms", host, e, elapsed)
            self.send_error(502, str(e))

    def _tunnel(self, client, remote):
        """Bidirectional data forwarding."""
        client.setblocking(False)
        remote.setblocking(False)
        sockets = [client, remote]
        while True:
            import select
            readable, _, exceptional = select.select(sockets, [], sockets, 30)
            if exceptional:
                break
            if not readable:
                break
            for sock in readable:
                other = remote if sock is client else client
                try:
                    data = sock.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
                except (ConnectionError, OSError):
                    return

    def _proxy_request(self):
        """Forward an HTTP request (GET, POST, etc.)."""
        url = self.path
        parsed_url = urllib.parse.urlparse(url)
        req_host = parsed_url.hostname or url
        log.info("%s %s from %s", self.command, url, self.address_string())
        hosts_log.info("%s host=%s url=%s client=%s", self.command, req_host, url, self.address_string())
        start = time.monotonic()

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        try:
            if UPSTREAM_HOST:
                conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=15)
                headers = dict(self.headers)
                if UPSTREAM_AUTH:
                    headers["Proxy-Authorization"] = UPSTREAM_AUTH
                conn.request(self.command, url, body=body, headers=headers)
            else:
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                port = parsed.port or 80
                path = parsed.path
                if parsed.query:
                    path += "?" + parsed.query
                conn = http.client.HTTPConnection(host, port, timeout=15)
                headers = dict(self.headers)
                conn.request(self.command, path, body=body, headers=headers)

            resp = conn.getresponse()
            resp_body = resp.read()
            elapsed = (time.monotonic() - start) * 1000

            log.info("%s %s -> %d (%d bytes, %.0fms)",
                     self.command, url, resp.status, len(resp_body), elapsed)
            hosts_log.info("%s host=%s status=%d bytes=%d elapsed=%.0fms",
                           self.command, req_host, resp.status, len(resp_body), elapsed)

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding",):
                    self.send_header(key, val)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            conn.close()

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            log.error("%s %s ERROR: %s (%.0fms)", self.command, url, e, elapsed)
            hosts_log.info("%s host=%s status=ERROR error=%s elapsed=%.0fms", self.command, req_host, e, elapsed)
            self.send_error(502, str(e))

    do_GET = _proxy_request
    do_POST = _proxy_request
    do_PUT = _proxy_request
    do_DELETE = _proxy_request
    do_PATCH = _proxy_request
    do_HEAD = _proxy_request
    do_OPTIONS = _proxy_request


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), DiagnosticProxyHandler)
    upstream_info = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}" if UPSTREAM_HOST else "DIRECT"
    log.info("HTTP proxy listening on %s:%d -> upstream %s", LISTEN_HOST, LISTEN_PORT, upstream_info)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down HTTP proxy")
        server.shutdown()


if __name__ == "__main__":
    main()
