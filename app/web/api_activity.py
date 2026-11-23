"""Read api-prd observations from the dashboard's existing log records."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


API_HOST = re.compile(r"(?:^|\.)api-prd(?:-[a-z0-9-]+)?(?:\.|$)", re.IGNORECASE)


def recent_api_activity(dns_rows, request_rows, local_ips):
    """Return the latest observation for each source and destination."""
    activity = []
    for source, rows, client_key in (
        ("DNS", dns_rows, "peer"),
        ("HTTP request", request_rows, "client"),
    ):
        seen = set()
        for row in reversed(rows):
            if not isinstance(row, dict):
                continue
            client = row.get(client_key)
            if not isinstance(client, str) or not client or client.removeprefix("::ffff:") in local_ips:
                continue
            if source == "DNS":
                destination = host = str(row.get("q") or "").lower().rstrip(".")
            else:
                if row.get("kind") not in {"FLOW", "HIT", "OBSERVE", "NEAR_MISS"}:
                    continue
                try:
                    url = urlsplit(str(row.get("url") or ""))
                    host = url.hostname or ""
                    if url.scheme not in {"http", "https"} or url.username is not None:
                        continue
                    destination = urlunsplit((url.scheme, url.netloc, url.path, "", ""))
                except ValueError:
                    continue
            key = (client, destination)
            if not API_HOST.search(host) or key in seen:
                continue
            activity.append({"source": source, "client": client, "destination": destination,
                             "ts": str(row.get("ts") or "")})
            seen.add(key)
            if len(seen) == 12:
                break
    return sorted(activity, key=lambda entry: entry["ts"], reverse=True)
