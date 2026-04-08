import json
import random
import uuid
from datetime import datetime, timezone
import os

log_path = "/app/data/raw_logs/system_logs.jsonl"
os.makedirs("/app/data/raw_logs", exist_ok=True)

users = ["alice", "bob", "charlie"]
processes = ["chrome.exe", "teams.exe", "python.exe"]


def make_event():
    return {
        "log_type": "soc_sim",
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "log_generator",
        "event_type": "process_start",
        "category": "system_process",
        "host": "workstation01",
        "user": random.choice(users),
        "process_name": random.choice(processes),
        "command_line": "normal process",
        "message": "Process execution"
    }


with open(log_path, "a") as f:
    for _ in range(20):
        f.write(json.dumps(make_event()) + "\n")

print("Generated 20 baseline system logs.")