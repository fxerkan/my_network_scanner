#!/usr/bin/env python3
"""Install the MyNeS InfluxDB datasource and dashboard into Grafana (idempotent).

    GRAFANA_URL=http://localhost:3000 GRAFANA_AUTH=admin:<password> \
    MYNES_INFLUX_URL=http://<influx-host>:8086 python3 deploy/grafana/provision.py

Stdlib only. Credentials come from the environment and are never written
anywhere. The datasource URL must be reachable *from Grafana*: if Grafana runs
in a bridge-networked container, 127.0.0.1 is the container itself - use the
host's LAN IP. A Grafana API token works too: GRAFANA_TOKEN=<token>.

Note: Grafana locks an account for a few minutes after repeated wrong
passwords, and the right password then also fails - do not retry in a loop.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DS_UID = "mynes-influx"
DS_NAME = "MyNeS InfluxDB"


def _call(method: str, path: str, body=None):
    url = os.environ.get("GRAFANA_URL", "http://localhost:3000").rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if os.environ.get("GRAFANA_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GRAFANA_TOKEN']}"
    elif os.environ.get("GRAFANA_AUTH"):
        headers["Authorization"] = "Basic " + base64.b64encode(os.environ["GRAFANA_AUTH"].encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return resp.getcode(), json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300]


def datasource() -> dict:
    db = os.environ.get("MYNES_INFLUX_DB", "mynes")
    ds = {
        "name": DS_NAME, "uid": DS_UID, "type": "influxdb", "access": "proxy",
        "url": os.environ.get("MYNES_INFLUX_URL", "http://localhost:8086"),
        "database": db, "isDefault": False,
        "jsonData": {"version": "InfluxQL", "dbName": db, "httpMode": "GET", "timeInterval": "1m"},
    }
    if os.environ.get("MYNES_INFLUX_USER"):
        ds["user"] = os.environ["MYNES_INFLUX_USER"]
        ds["secureJsonData"] = {"password": os.environ.get("MYNES_INFLUX_PASSWORD", "")}
    return ds


def main() -> int:
    code, _ = _call("GET", "/api/org")
    if code != 200:
        print(f"Grafana login failed (HTTP {code}) - check GRAFANA_URL / GRAFANA_AUTH", file=sys.stderr)
        return 1

    ds = datasource()
    code, _ = _call("GET", f"/api/datasources/uid/{DS_UID}")
    code, res = (_call("PUT", f"/api/datasources/uid/{DS_UID}", ds) if code == 200
                 else _call("POST", "/api/datasources", ds))
    print(f"datasource {DS_NAME}: HTTP {code}")
    code, health = _call("GET", f"/api/datasources/uid/{DS_UID}/health")
    print(f"datasource health: HTTP {code} {health}")

    dash = json.loads((HERE / "mynes-dashboard.json").read_text(encoding="utf-8"))
    code, res = _call("POST", "/api/dashboards/db",
                      {"dashboard": dash, "overwrite": True, "message": "deploy/grafana/provision.py"})
    print(f"dashboard: HTTP {code} {res}")
    return 0 if code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
