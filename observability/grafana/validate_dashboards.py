"""Runs every panel query of the provisioned dashboards through Grafana's /api/ds/query and reports errors/rows.

python observability/grafana/validate_dashboards.py [--grafana http://localhost:3000] [--trace <trace id>]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

DASH = Path(__file__).parent / "dashboards"


def post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}") | {"_status": e.code}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--grafana", default="http://localhost:3000")
    ap.add_argument("--trace", default="")
    a = ap.parse_args()
    bad = 0
    for f in sorted(DASH.glob("*.json")):
        d = json.loads(f.read_text())
        t = d["time"]
        print(f"== {d['title']}")
        variables = {"trace_id": a.trace}
        for v in d["templating"]["list"]:
            body = {"from": "now-7d", "to": "now", "queries": [{"refId": "V", "datasource": v["datasource"],
                                                              "editorType": "sql", "format": 1,
                                                              "rawSql": v["query"]}]}
            r = post(f"{a.grafana}/api/ds/query", body)["results"]["V"]
            err = r.get("error")
            frames = r.get("frames") or []
            n = len(frames[0]["data"]["values"][0]) if frames and frames[0]["data"]["values"] else 0
            print(f"  var {v['name']:<10} {'ERROR ' + err[:200] if err else f'{n} options'}")
            bad += bool(err)
            # the ClickHouse plugin takes column 1 as the value and column 2 as the label
            if n and not variables.get(v["name"]):
                variables[v["name"]] = frames[0]["data"]["values"][0][0]
        for p in d["panels"]:
            for tq in p.get("targets", []):
                sql = tq["rawSql"]
                for k, val in variables.items():
                    sql = sql.replace("${" + k + "}", val).replace("$" + k, val)
                body = {"from": t["from"] if "T" not in t["from"] else str(_ms(t["from"])),
                        "to": t["to"] if "T" not in t["to"] else str(_ms(t["to"])),
                        "queries": [{**tq, "rawSql": sql}]}
                if body["from"].startswith("now"):
                    body["from"] = "now-7d"
                res = post(f"{a.grafana}/api/ds/query", body)
                r = (res.get("results") or {}).get(tq["refId"], {})
                err = r.get("error") or res.get("message")
                frames = r.get("frames") or []
                rows = sum(len(fr["data"]["values"][0]) if fr["data"]["values"] else 0 for fr in frames)
                status = f"ERROR {err[:300]}" if err else f"{rows} rows"
                if err:
                    bad += 1
                print(f"  {p['type']:<10} {p['title'][:70]:<70} {status}")
    print("FAILED" if bad else "all queries OK")
    return 1 if bad else 0


def _ms(iso: str) -> int:
    from datetime import datetime

    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


if __name__ == "__main__":
    sys.exit(main())
