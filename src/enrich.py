import requests
import time
import os
import json
from parser import parse_logs

API_KEY_PATH = os.path.expanduser("~/.abuseipdb_key")
OUTPUT_PATH = "reports/ip_enrichment.json"

def load_api_key():
    with open(API_KEY_PATH, "r") as f:
        return f.read().strip()

def check_ip(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.RequestException as e:
        print(f"Erreur reseau pour {ip}: {e}")
        return None

    if response.status_code != 200:
        print(f"Erreur API pour {ip}: statut {response.status_code}")
        return None

    data = response.json().get("data", {})
    return {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore"),
        "country": data.get("countryCode"),
        "total_reports": data.get("totalReports"),
        "isp": data.get("isp"),
        "is_tor": data.get("isTor"),
    }


def enrich_all_ips(ip_list, api_key, delay=1.0):
    results = {}
    total = len(ip_list)
    for i, ip in enumerate(ip_list, start=1):
        print(f"[{i}/{total}] Verification de {ip}...")
        result = check_ip(ip, api_key)
        if result:
            results[ip] = result
        time.sleep(delay)
    return results


if __name__ == "__main__":
    api_key = load_api_key()
    profiles = parse_logs()
    ip_list = list(profiles.keys())

    print(f"{len(ip_list)} IP a enrichir, ca va prendre environ {len(ip_list)} secondes...")
    results = enrich_all_ips(ip_list, api_key)

    os.makedirs("reports", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nTermine. {len(results)} IP enrichies, sauvegardees dans {OUTPUT_PATH}")
