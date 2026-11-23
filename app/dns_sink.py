"""
dns_sink.py - Minimal DNS server that resolves selected domains locally and forwards all other queries unchanged.

The vehicle resolves mothership.vn.teslamotors.com to the PC running mitmproxy,
so its HTTP requests on port 4567 reach the local reverse proxy.

    python dns_sink.py --ip 192.168.137.1 --redirect mothership.vn.teslamotors.com
    python dns_sink.py --ip 192.168.1.23 --upstream 223.5.5.5 --port 53

Use --port 5353 for testing. The vehicle accepts only an IP address, so use port 53 for deployment.
On Windows, binding UDP port 53 does not require administrator privileges.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import threading
import time

LOG_LOCK = threading.Lock()


def local_ip_for(peer_ip: str) -> str | None:
    """Return the local interface IP that the client can reach.

    In Windows hotspot mode, the vehicle is on 192.168.137.0/24, while the PC
    uses 192.168.199.x upstream. Using a fixed startup IP can return the wrong subnet.
    Use the peer address to select the local interface for hotspot, LAN, or loopback traffic.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer_ip, 9))
        ip = s.getsockname()[0]
        return ip if ip and not ip.startswith("0.") else None
    except OSError:
        return None
    finally:
        s.close()


def qname_of(data: bytes) -> tuple[str, int]:
    i = 12
    labels = []
    while True:
        ln = data[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:
            raise ValueError("compressed qname in question")
        labels.append(data[i + 1 : i + 1 + ln].decode("latin1"))
        i += 1 + ln
    qname = ".".join(labels)
    return qname, i + 4  # + qtype(2) + qclass(2)


def build_answer(query: bytes, qend: int, ip: str, ttl: int = 60) -> bytes:
    txid = query[:2]
    header = txid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    question = query[12:qend]
    rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return header + question + rr


def build_empty(query: bytes, qend: int) -> bytes:
    txid = query[:2]
    header = txid + struct.pack(">HHHHH", 0x8180, 1, 0, 0, 0)
    return header + query[12:qend]


def build_nxdomain(query: bytes, qend: int) -> bytes:
    txid = query[:2]
    header = txid + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0)
    return header + query[12:qend]


class DnsSink:
    def __init__(self, ip: str, redirect: set[str], upstream: list[str], port: int, log_path: str):
        self.ip = ip
        self.redirect = redirect
        self.health_name = os.environ.get("FSD_DNS_HEALTH_NAME")
        self.upstream = upstream
        self.port = port
        self.log_path = log_path
        self.count = 0

    def log(self, rec: dict) -> None:
        line = json.dumps(rec, ensure_ascii=False)
        with LOG_LOCK:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass

    def forward(self, data: bytes) -> bytes | None:
        for up in self.upstream:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2.0)
                s.sendto(data, (up, 53))
                reply, _ = s.recvfrom(4096)
                s.close()
                return reply
            except OSError:
                continue
        return None

    def handle(self, sock: socket.socket) -> None:
        while True:
            try:
                data, peer = sock.recvfrom(4096)
            except OSError:
                return
            try:
                name, qend = qname_of(data)
            except Exception:
                continue
            qtype = struct.unpack(">H", data[qend - 4 : qend - 2])[0] if len(data) >= qend else 0
            key = name.rstrip(".").lower()
            if peer[0] == "127.0.0.1" and key == self.health_name and qtype == 1:
                sock.sendto(build_answer(data, qend, self.ip), peer)
                continue

            hit = key in self.redirect
            self.count += 1
            if hit:
                answer_ip = local_ip_for(peer[0]) or self.ip
                if qtype == 1:  # A
                    reply = build_answer(data, qend, answer_ip)
                elif qtype == 28:  # Return an empty AAAA answer so the client uses an A query.
                    reply = build_empty(data, qend)
                else:
                    reply = build_empty(data, qend)
                sock.sendto(reply, peer)
                self.log({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "q": key, "type": qtype,
                          "action": "REDIRECT", "ip": answer_ip, "peer": peer[0]})
                print(f"[dns] REDIRECT {key} type={qtype} -> {answer_ip} (client {peer[0]})", flush=True)
            else:
                reply = self.forward(data)
                if reply:
                    sock.sendto(reply, peer)
                self.log({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "q": key, "type": qtype,
                          "action": "FORWARD", "peer": peer[0]})

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind(("0.0.0.0", self.port))
        print(f"[dns] listening udp/{self.port} | {self.ip} <- {sorted(self.redirect)} | upstream={self.upstream}", flush=True)
        for _ in range(4):
            threading.Thread(target=self.handle, args=(sock,), daemon=True).start()
        while True:
            time.sleep(3600)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="Local IP address reachable by the vehicle")
    ap.add_argument("--redirect", action="append", default=None, help="Domain to redirect (repeatable)")
    ap.add_argument("--upstream", default=None, help="Comma-separated upstream DNS servers (default: 223.5.5.5,1.1.1.1)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--log", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "dns.jsonl"))
    ap.add_argument("--no-forward", action="store_true", help="Return NXDOMAIN for every domain outside the redirect list")
    args = ap.parse_args()

    redirect = {d.rstrip(".").lower() for d in (args.redirect or ["mothership.vn.teslamotors.com"])}
    upstream = [u.strip() for u in (args.upstream or "223.5.5.5,1.1.1.1").split(",") if u.strip()]
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    DnsSink(args.ip, redirect, upstream, args.port, args.log).run()


if __name__ == "__main__":
    main()
