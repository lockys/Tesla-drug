"""svc/stack.py - Background supervisor for the DNS sink, reverse proxy (4567), and proxy (8080)

  - Check ports every eight seconds and restart failed processes
  - Write child process logs to logs\\<name>.log
  - Installed at C:\\fsd-mitm\\svc\\stack.py

Start in the background so it continues after the terminal closes:
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
      CommandLine = '"C:\\fsd-mitm\\venv\\Scripts\\python.exe" "C:\\fsd-mitm\\svc\\stack.py"'
      CurrentDirectory = 'C:\\fsd-mitm'
  }
"""
from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / "venv" / "Scripts"
PY = VENV / "python.exe"
DUMP = VENV / "mitmdump.exe"
LOGS = ROOT / "logs"
CONFDIR = ROOT / "certs2"
PAYLOAD = ROOT / "payload.json"
ADDON = ROOT / "fsd_mock.py"
DNS_PORT = 53
DNS_HEALTH_NAME = f"{uuid.uuid4().hex}.fsd-dns.invalid"
IGNORE = r"^(hermes-prd|hermes-stream-prd|telemetry-prd)\.vn\.cloud\.tesla\.cn(?::\d+)?$"

LOGS.mkdir(parents=True, exist_ok=True)
proc: dict[str, subprocess.Popen] = {}

# The launcher, scheduled task, and manual startup can run at the same time.
# Only the process that acquires the lock starts the DNS, reverse proxy, proxy, and dashboard.
LOCK_PORT = 45799
_lock_sock: socket.socket | None = None


def acquire_single_instance() -> bool:
    global _lock_sock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
    except OSError:
        s.close()
        return False
    _lock_sock = s
    return True


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOGS / "stack.log", "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def tcp_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return True
    except OSError:
        return False


def udp_open(port: int) -> bool:
    """Check UDP port availability on Windows by trying to bind it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def spawn(name: str, argv: list[str], env_extra: dict | None = None) -> None:
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["FSD_MOCK_LOG_DIR"] = str(LOGS)
    env["FSD_MOCK_JSON"] = str(PAYLOAD)
    env["FSD_MOCK_LOG_ALL"] = "1"
    if env_extra:
        env.update(env_extra)
    fh = open(LOGS / f"{name}.log", "ab", buffering=0)
    fh.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} start {name} =====\n".encode())
    # Keep console children hidden so watchdog restarts do not open terminal popups.
    p = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         env=env, cwd=str(ROOT), creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW))
    proc[name] = p
    log(f"started {name} pid={p.pid}")


def common_mitm() -> list[str]:
    return ["-s", str(ADDON), "--set", f"confdir={CONFDIR}", "--set", "ssl_insecure=true",
            "--set", "connection_strategy=lazy", "--set", "block_global=false",
            "--ignore-hosts", IGNORE, "--emudhra"]


LAST_IP: dict[str, str | None] = {"ip": None}


def dns_responding(ip: str) -> bool:
    transaction = int.from_bytes(os.urandom(2), "big")
    labels = [label.encode("ascii") for label in DNS_HEALTH_NAME.split(".")]
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00\x00\x01\x00\x01"
    query = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + question
    expected = (
        struct.pack("!6H", transaction, 0x8180, 1, 1, 0, 0)
        + question
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton(ip)
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.25)
            sock.connect(("127.0.0.1", DNS_PORT))
            sock.send(query)
            return sock.recv(4096) == expected
    except OSError:
        return False


def ensure_dns(ip: str) -> str:
    if "dns" in proc:
        return "listening" if dns_responding(ip) else "not_responding"
    if udp_open(DNS_PORT):
        return "port_in_use"

    spawn("dns", [str(PY), str(ROOT / "dns_sink.py"), "--ip", ip,
                  "--port", str(DNS_PORT), "--redirect", "mothership.vn.teslamotors.com"],
          env_extra={"FSD_DNS_HEALTH_NAME": DNS_HEALTH_NAME})
    return "starting"


def ensure(ip: str) -> str:
    for name, child in list(proc.items()):
        if child.poll() is not None:
            log(f"{name} exited rc={child.returncode}")
            proc.pop(name)


    # Update the IP returned by DNS when the Wi-Fi network or subnet changes.
    if LAST_IP["ip"] and LAST_IP["ip"] != ip:
        log(f"local ip changed {LAST_IP['ip']} -> {ip} | restarting dns sink")
        old = proc.pop("dns", None)
        if old is not None:
            try:
                old.terminate()
                old.wait(timeout=5)
            except Exception:
                pass
        time.sleep(1)
    LAST_IP["ip"] = ip

    dns_status = ensure_dns(ip)

    if not tcp_open(4567):
        spawn("reverse", [str(DUMP), *common_mitm(), "--mode", "reverse:http://192.0.2.1:4567",
                          "--listen-host", "0.0.0.0", "--listen-port", "4567",
                          "--set", "keep_host_header=true"])

    if not tcp_open(8080):
        spawn("proxy", [str(DUMP), *common_mitm(), "--mode", "regular@8080", "--listen-host", "0.0.0.0"])

    if not tcp_open(8899):
        spawn("web", [str(PY), str(ROOT / "web" / "server.py"), "--port", "8899"])

    return dns_status


def main() -> None:
    if not acquire_single_instance():
        log("another stack.py instance is already running; exiting (single-instance lock)")
        return
    ip = local_ip()
    log(f"stack up | local ip={ip} | dns->{ip} | reverse=4567 | proxy=8080")
    previous_dns_status = None
    while True:
        try:
            ip = local_ip()
            dns_status = ensure(ip)
            if dns_status != previous_dns_status:
                if dns_status == "port_in_use":
                    log(f"UDP {DNS_PORT} is unavailable; project DNS has not started")
                elif dns_status == "not_responding":
                    log("Project DNS did not answer its local health check")
            previous_dns_status = dns_status
            with open(LOGS / "stack_state.json", "w", encoding="utf-8") as fh:
                json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                           "ip": ip,
                           "tcp4567": tcp_open(4567),
                           "tcp8080": tcp_open(8080),
                           "udp53": dns_status == "listening",
                           "dns_status": dns_status,
                           "children": {k: v.pid for k, v in proc.items()}}, fh, ensure_ascii=False)
        except Exception as exc:  # Keep the supervisor running after an error.
            log(f"ensure error: {type(exc).__name__}: {exc}")
        time.sleep(8)


if __name__ == "__main__":
    main()
