import json
from collections import Counter

ENRICHMENT_PATH = "reports/ip_enrichment.json"

def load_enrichment(path=ENRICHMENT_PATH):
    with open(path, "r") as f:
        return json.load(f)


def summarize(data):
    countries = Counter()
    high_risk = []
    tor_count = 0

    for ip, info in data.items():
        country = info.get("country") or "Inconnu"
        countries[country] += 1

        score = info.get("abuse_score") or 0
        if score >= 90:
            high_risk.append((ip, score, country, info.get("isp")))

        if info.get("is_tor"):
            tor_count += 1

    print(f"Total IP analysees : {len(data)}")
    print(f"IP via Tor : {tor_count}")
    print(f"\nTop 10 pays d'origine :")
    for country, count in countries.most_common(10):
        print(f"  {country}: {count} IP")

    print(f"\nIP a tres haut risque (score >= 90) : {len(high_risk)}")
    high_risk.sort(key=lambda x: x[1], reverse=True)
    for ip, score, country, isp in high_risk[:10]:
        print(f"  {ip} | score {score} | {country} | {isp}")


if __name__ == "__main__":
    data = load_enrichment()
    summarize(data)
