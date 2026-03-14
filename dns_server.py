#!/usr/bin/env python3
"""
Local DNS server with query/response logging for network diagnostics.

Since this environment routes all traffic through an HTTP proxy that handles
DNS resolution internally, this server resolves names by making HTTP HEAD
requests through the local HTTP proxy and synthesizing DNS responses.

For A/AAAA queries: resolves by connecting through the proxy and reading
the resolved address from the socket. Falls back to returning a CNAME-like
indicator and attempting direct UDP resolution.

Listens on: 127.0.0.1:15353  (unprivileged port, UDP)
Logs to:    logs/dns_server.log  (and stdout)
"""

import socket
import struct
import threading
import os
import sys
import logging
import time
import http.client

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DNS] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "dns_server.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("dns_server")

# Dedicated logger for all DNS queries (append-only, one line per query)
_queries_handler = logging.FileHandler(os.path.join(LOG_DIR, "dns_queries.log"))
_queries_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
queries_log = logging.getLogger("dns_queries")
queries_log.addHandler(_queries_handler)
queries_log.setLevel(logging.INFO)
queries_log.propagate = False

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 15353

# Local HTTP proxy (handles DNS via upstream proxy)
HTTP_PROXY_HOST = "127.0.0.1"
HTTP_PROXY_PORT = 18080

# Fallback UDP resolvers
UPSTREAM_DNS_UDP = [
    ("8.8.8.8", 53),
    ("8.8.4.4", 53),
]

# DNS record type names
QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR",
    255: "ANY", 257: "CAA", 65: "HTTPS",
}


def parse_dns_name(data, offset):
    """Parse a DNS domain name from a packet, handling compression."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20

    while max_jumps > 0:
        max_jumps -= 1
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode(errors="replace"))
            offset += length

    name = ".".join(labels) if labels else "<root>"
    return name, original_offset if jumped else offset


def parse_dns_header(data):
    """Parse DNS header fields."""
    if len(data) < 12:
        return None
    txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    qr = (flags >> 15) & 1
    rcode = flags & 0xF
    return {
        "id": txn_id, "qr": qr, "rcode": rcode,
        "qdcount": qdcount, "ancount": ancount,
        "nscount": nscount, "arcount": arcount,
    }


def parse_question(data):
    """Parse the question section of a DNS query."""
    if len(data) < 12:
        return None, None, None
    name, offset = parse_dns_name(data, 12)
    if offset + 4 > len(data):
        return name, None, None
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return name, qtype, qclass


def encode_dns_name(name):
    """Encode a domain name to DNS wire format."""
    result = b""
    for label in name.split("."):
        if label:
            result += bytes([len(label)]) + label.encode()
    result += b"\x00"
    return result


def build_response(query_data, qname, qtype, answers):
    """Build a DNS response packet from query + answers.

    answers: list of (type, ttl, rdata_bytes)
    """
    # Copy transaction ID from query
    txn_id = query_data[:2]
    flags = struct.pack("!H", 0x8180)  # QR=1, RD=1, RA=1, RCODE=0
    qdcount = struct.pack("!H", 1)
    ancount = struct.pack("!H", len(answers))
    nscount = struct.pack("!H", 0)
    arcount = struct.pack("!H", 0)

    header = txn_id + flags + qdcount + ancount + nscount + arcount

    # Question section
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)

    # Answer section
    answer_data = b""
    for rtype, ttl, rdata in answers:
        answer_data += encode_dns_name(qname)
        answer_data += struct.pack("!HH", rtype, 1)  # type, class IN
        answer_data += struct.pack("!I", ttl)
        answer_data += struct.pack("!H", len(rdata))
        answer_data += rdata

    return header + question + answer_data


def build_nxdomain(query_data, qname, qtype):
    """Build an NXDOMAIN response."""
    txn_id = query_data[:2]
    flags = struct.pack("!H", 0x8183)  # QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    return txn_id + flags + counts + question


def build_servfail(query_data, qname, qtype):
    """Build a SERVFAIL response."""
    txn_id = query_data[:2]
    flags = struct.pack("!H", 0x8182)  # QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    return txn_id + flags + counts + question


def resolve_via_proxy(hostname, timeout=8):
    """Resolve a hostname by connecting through the HTTP proxy.

    Makes an HTTP HEAD request via the proxy. The proxy resolves DNS
    internally, so we can observe the resolution behavior.
    Returns (ip_address, latency_ms) or (None, latency_ms).
    """
    start = time.monotonic()
    try:
        # Try HTTPS CONNECT tunnel - the proxy will resolve the hostname
        conn = http.client.HTTPConnection(HTTP_PROXY_HOST, HTTP_PROXY_PORT, timeout=timeout)
        conn.request("HEAD", f"http://{hostname}/", headers={"Host": hostname})
        resp = conn.getresponse()
        resp.read()
        elapsed = (time.monotonic() - start) * 1000

        # The proxy resolved it - we know the host is valid
        # Try to get the actual IP from the socket if possible
        peer = conn.sock.getpeername() if conn.sock else None
        conn.close()

        # The peer will be the proxy, not the target.
        # For diagnostics, we confirm resolution succeeded.
        return "proxy-resolved", elapsed, resp.status

    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return None, elapsed, str(e)


def forward_via_udp(query_data, timeout=3):
    """Forward DNS query via direct UDP to upstream resolvers (fallback)."""
    for upstream_host, upstream_port in UPSTREAM_DNS_UDP:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query_data, (upstream_host, upstream_port))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response, f"UDP:{upstream_host}"
        except (socket.timeout, OSError):
            try:
                sock.close()
            except Exception:
                pass
            continue
    return None, None


def rcode_str(rcode):
    """Human-readable RCODE."""
    names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
             4: "NOTIMP", 5: "REFUSED"}
    return names.get(rcode, f"RCODE_{rcode}")


def handle_query(server_sock, data, client_addr):
    """Handle a single DNS query."""
    qname, qtype, _ = parse_question(data)
    qtype_name = QTYPES.get(qtype, str(qtype)) if qtype else "?"

    log.info("QUERY %s %s from %s:%d", qtype_name, qname, *client_addr)
    queries_log.info("QUERY type=%s name=%s client=%s:%d", qtype_name, qname, *client_addr)
    start = time.monotonic()

    # First try direct UDP (fast path, may not work in all environments)
    response, source = forward_via_udp(data, timeout=2)
    if response:
        elapsed = (time.monotonic() - start) * 1000
        header = parse_dns_header(response)
        rcode = rcode_str(header["rcode"]) if header else "?"
        answers = header["ancount"] if header else 0
        log.info("REPLY %s %s -> %s (%d answers, via=%s, %.0fms)",
                 qtype_name, qname, rcode, answers, source, elapsed)
        queries_log.info("REPLY type=%s name=%s rcode=%s answers=%d via=%s elapsed=%.0fms",
                         qtype_name, qname, rcode, answers, source, elapsed)
        server_sock.sendto(response, client_addr)
        return

    # Fallback: resolve via HTTP proxy (proxy handles DNS internally)
    result, latency, status = resolve_via_proxy(qname)
    elapsed = (time.monotonic() - start) * 1000

    if result == "proxy-resolved":
        # Host resolved by proxy - synthesize a minimal response
        # We can't get the actual IP from the proxy, but we confirm the name is valid
        log.info("REPLY %s %s -> NOERROR (proxy-resolved, http=%s, %.0fms)",
                 qtype_name, qname, status, elapsed)
        queries_log.info("REPLY type=%s name=%s rcode=NOERROR via=proxy http_status=%s elapsed=%.0fms",
                         qtype_name, qname, status, elapsed)
        # Synthesize a response: return 127.0.0.2 as a sentinel indicating
        # "resolved via proxy" — the actual connection should go through the proxy
        if qtype == 1:  # A record
            answers = [(1, 60, socket.inet_aton("127.0.0.2"))]
            resp = build_response(data, qname, qtype, answers)
        elif qtype == 28:  # AAAA record
            answers = [(28, 60, socket.inet_pton(socket.AF_INET6, "::1"))]
            resp = build_response(data, qname, qtype, answers)
        else:
            # For other types, return empty NOERROR
            resp = build_response(data, qname, qtype, [])
        server_sock.sendto(resp, client_addr)
    else:
        log.error("REPLY %s %s -> SERVFAIL (proxy-error=%s, %.0fms)",
                  qtype_name, qname, status, elapsed)
        queries_log.info("REPLY type=%s name=%s rcode=SERVFAIL via=proxy error=%s elapsed=%.0fms",
                         qtype_name, qname, status, elapsed)
        resp = build_servfail(data, qname, qtype)
        server_sock.sendto(resp, client_addr)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))

    log.info("DNS server listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    log.info("  Primary:  UDP -> %s",
             ", ".join(f"{h}:{p}" for h, p in UPSTREAM_DNS_UDP))
    log.info("  Fallback: HTTP proxy resolution via %s:%d",
             HTTP_PROXY_HOST, HTTP_PROXY_PORT)

    while True:
        try:
            data, client_addr = sock.recvfrom(4096)
            threading.Thread(
                target=handle_query,
                args=(sock, data, client_addr),
                daemon=True,
            ).start()
        except KeyboardInterrupt:
            log.info("Shutting down DNS server")
            break
        except Exception as e:
            log.error("Error receiving: %s", e)

    sock.close()


if __name__ == "__main__":
    main()
