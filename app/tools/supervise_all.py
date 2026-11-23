#!/usr/bin/env python
# -*- coding: utf-8 -*-
r"""supervise_all.py - Component watchdog for console-free operation with pythonw

  Component             Health check                 Restart command
  Stack supervisor      Port 4567 is listening       svc\stack.py
  HTTPS interception    Port 443 is listening        mitmdump.exe (reverse proxy for api-prd with fsd_mock)
  ARP redirection        Log updated within 120 s     tools\arp_mitm.py
  Dashboard              Port 8900 is listening       web\fsd_panel.py

Checks run every 30 seconds. Logs are written to logs\supervise.log.
"""
import os
import socket
import subprocess
import time
from datetime import datetime

ROOT = r"C:\fsd-mitm"
BIN = os.path.join(ROOT, "venv", "Scripts")
PYW = os.path.join(BIN, "pythonw.exe")
MITMDUMP = os.path.join(BIN, "mitmdump.exe")
LOGS = os.path.join(ROOT, "logs")
LOG = os.path.join(LOGS, "supervise.log")
ARP_LOG = os.path.join(LOGS, "arp_mitm.log")
NO_WIN = 0x08000000 if os.name == "nt" else 0
INTERVAL = 30


def log(msg):
    line = "%s %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def port_open(port):
    s = socket.socket()
    s.settimeout(0.6)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def spawn(exe, args, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    subprocess.Popen([exe] + args, cwd=ROOT, env=env, creationflags=NO_WIN,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def main():
    log("supervisor start")
    while True:
        try:
            if not port_open(4567):
                log("Port 4567 is not listening. Starting the stack supervisor.")
                spawn(PYW, [os.path.join(ROOT, "svc", "stack.py")])
                time.sleep(8)

            fresh = False
            try:
                fresh = (time.time() - os.path.getmtime(ARP_LOG)) < 120
            except OSError:
                fresh = False
            if not fresh:
                log("ARP redirection stopped. Restarting it.")
                spawn(PYW, [os.path.join(ROOT, "tools", "arp_mitm.py"),
                            "--target", "192.168.199.95", "--gateway", "192.168.199.1",
                            "--our-ip", "192.168.199.148", "--answer", "192.168.199.148",
                            "--iface", "Wi-Fi", "--duration", "7200", "--rst-dst", "52.81.9.181"])
                time.sleep(8)

            if not port_open(443):
                log("Port 443 is not listening. Starting HTTPS interception.")
                spawn(MITMDUMP, ["-s", os.path.join(ROOT, "fsd_mock.py"),
                                 "--set", "confdir=" + os.path.join(ROOT, "certs2"),
                                 "--set", "ssl_insecure=true",
                                 "--set", "connection_strategy=lazy",
                                 "--set", "block_global=false", "--emudhra",
                                 "--mode", "reverse:https://api-prd.vn.cloud.tesla.cn@443"],
                      {"FSD_MOCK_LOG_DIR": LOGS,
                       "FSD_MOCK_JSON": os.path.join(ROOT, "payload.json"),
                       "FSD_MOCK_LOG_ALL": "1",
                       "FSD_MOCK_MODE_FILE": os.path.join(ROOT, "mode.json"),
                       "PYTHONUNBUFFERED": "1"})
                time.sleep(10)

            if not port_open(8900):
                log("Port 8900 is not listening. Starting the dashboard.")
                spawn(PYW, [os.path.join(ROOT, "web", "fsd_panel.py"), "--port", "8900"])
                time.sleep(5)
        except Exception as exc:
            log("supervisor error: %r" % (exc,))
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
