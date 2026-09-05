import json
from collections import defaultdict

LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

def parse_logs(log_path=LOG_PATH):
    """Lit le log JSON de Cowrie et regroupe les evenements par IP source."""
    profiles = defaultdict(lambda: {
        "protocols": set(),
        "connections": 0,
        "login_attempts": [],
        "commands": [],
        "first_seen": None,
        "last_seen": None,
    })

    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = event.get("src_ip")
            if not ip:
                continue

            ts = event.get("timestamp")
            profile = profiles[ip]

            if profile["first_seen"] is None or ts < profile["first_seen"]:
                profile["first_seen"] = ts
            if profile["last_seen"] is None or ts > profile["last_seen"]:
                profile["last_seen"] = ts

            eventid = event.get("eventid", "")

            if eventid == "cowrie.session.connect":
                profile["connections"] += 1
                profile["protocols"].add(event.get("protocol", "unknown"))

            elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
                profile["login_attempts"].append({
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "success": eventid == "cowrie.login.success",
                    "timestamp": ts,
                })

            elif eventid == "cowrie.command.input":
                profile["commands"].append({
                    "input": event.get("input"),
                    "timestamp": ts,
                })

    return profiles


if __name__ == "__main__":
    profiles = parse_logs()
    print(f"Nombre d'IP uniques observees : {len(profiles)}")
    for ip, data in list(profiles.items())[:3]:
        print(f"\n{ip}: {data['connections']} connexions, "
              f"{len(data['login_attempts'])} tentatives de login, "
              f"{len(data['commands'])} commandes")
