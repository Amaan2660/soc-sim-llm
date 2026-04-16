import os
import json
import requests
from flask import Flask, render_template, jsonify, request
from datetime import datetime, timezone, timedelta
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from datetime import datetime, timezone

START_TIME = datetime.now(timezone.utc)

app = Flask(__name__)

OPENSEARCH_URL  = os.environ.get("OPENSEARCH_URL", "https://wazuh.indexer:9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS", "SecretPassword")

# Wazuh stores alerts in a daily rolling index
ALERTS_INDEX = "wazuh-alerts-4.x-*"


def parse_wazuh_time(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")


def os_get(path: str, body: dict) -> dict:
    """POST a query to OpenSearch and return parsed JSON."""
    url = f"{OPENSEARCH_URL}/{path}"
    resp = requests.post(
        url, json=body,
        auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify=False, timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_alerts(hours: int = 24, rule_group: str = "", search: str = "") -> list[dict]:
    time_cutoff = START_TIME
    since = time_cutoff.isoformat()

    must = [{"range": {"timestamp": {"gte": since}}}]

    must.append({
    "terms": {
        "rule.id": ["100010", "100020", "100030", "100040", "100011", "100012"]
    }
})

    if rule_group and rule_group.lower() != "all":
        groups = [g.strip() for g in rule_group.split(",") if g.strip()]
        if groups:
            must.append({"terms": {"rule.groups": groups}})

   # query = {
   #     "size": 200,
   #     "sort": [{"timestamp": {"order": "desc"}}],
   #     "query": {"bool": {"must": must}},
   # }
    query = {
        "size": 500,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
    }

    try:
        raw = os_get(f"{ALERTS_INDEX}/_search", query)
    except Exception as e:
        return [{"_error": str(e)}]

    alerts = []
    for hit in raw.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        data = src.get("data", {})
        rule = src.get("rule", {})

        alerts.append({
            "id":           hit["_id"],
            "timestamp":    src.get("timestamp", ""),
            "rule_id":      rule.get("id", ""),
            "rule_level":   rule.get("level", 0),
            "rule_desc":    rule.get("description", ""),
            "rule_groups":  rule.get("groups", []),
            "src_ip":       data.get("src_ip", ""),
            "method":       data.get("method", ""),
            "path":         data.get("path", ""),
            "status_code":       data.get("status_code", ""),
            "user_agent":   data.get("user_agent", ""),
            "query":        data.get("query", ""),
            "request_body": data.get("request_body", ""),
            "host":         data.get("host", src.get("agent", {}).get("name", "")),
            # AI verdict placeholder — populated later
            "ai_verdict":   src.get("ai_verdict", None),
        })

    return alerts


def fetch_stats() -> dict:
    """Summary counts for the dashboard header."""
    time_cutoff = START_TIME.isoformat()

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": time_cutoff}}},
                    {
                        "terms": {
                            "rule.id": ["100010", "100020", "100030", "100040"]
                        }
                    }
                ]
            }
        },
        "aggs": {
            "by_level": {
                "range": {
                    "field": "rule.level",
                    "ranges": [
                        {"key": "low", "from": 0, "to": 7},
                        {"key": "medium", "from": 7, "to": 11},
                        {"key": "high", "from": 11, "to": 100},
                    ],
                }
            },
            "by_group": {
                "terms": {"field": "rule.groups", "size": 10}
            },
        },
    }


    try:
        raw = os_get(f"{ALERTS_INDEX}/_search", query)
        buckets_level = {
            b["key"]: b["doc_count"]
            for b in raw["aggregations"]["by_level"]["buckets"]
        }
        buckets_group = {
            b["key"]: b["doc_count"]
            for b in raw["aggregations"]["by_group"]["buckets"]
        }
        total = raw["hits"]["total"]["value"]
        return {"total": total, "by_level": buckets_level, "by_group": buckets_group}
    except Exception as e:
        return {"error": str(e)}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    hours      = int(request.args.get("hours", 24))
    rule_group = request.args.get("group", "")
    search     = request.args.get("search", "")
    alerts = fetch_alerts(hours=hours, rule_group=rule_group, search=search)
    print("hours=", hours, "group=", rule_group, "search=", search, flush=True)
    return jsonify(alerts)



@app.route("/api/stats")
def api_stats():
    return jsonify(fetch_stats())

@app.route("/api/reset")
def reset():
    global START_TIME
    START_TIME = datetime.now(timezone.utc)
    return {"status": "reset"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
