import json
from collections import Counter
from datetime import datetime
from parser import parse_logs
from mitre import analyze_commands

ENRICHMENT_PATH = "reports/ip_enrichment.json"
OUTPUT_PATH = "reports/threat_report.html"


def load_enrichment(path=ENRICHMENT_PATH):
    with open(path, "r") as f:
        return json.load(f)


def build_report():
    profiles = parse_logs()
    enrichment = load_enrichment()
    technique_counts, technique_examples = analyze_commands(profiles)

    total_ips = len(enrichment)
    total_connections = sum(p["connections"] for p in profiles.values())
    total_commands = sum(len(p["commands"]) for p in profiles.values())

    countries = Counter()
    high_risk = []
    for ip, info in enrichment.items():
        countries[info.get("country") or "Inconnu"] += 1
        score = info.get("abuse_score") or 0
        if score >= 90:
            high_risk.append((ip, score, info.get("country"), info.get("isp")))
    high_risk.sort(key=lambda x: x[1], reverse=True)

    techniques_sorted = sorted(technique_counts.items(), key=lambda x: -x[1])

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport Threat Intelligence - Honeypot Cowrie</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }}
  h1 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 12px; }}
  h2 {{ color: #7dd3fc; margin-top: 40px; }}
  .stats {{ display: flex; gap: 20px; margin: 24px 0; flex-wrap: wrap; }}
  .stat-card {{ background: #1e293b; border-radius: 8px; padding: 20px 28px; min-width: 160px; }}
  .stat-value {{ font-size: 32px; font-weight: bold; color: #38bdf8; }}
  .stat-label {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid #1e293b; font-size: 14px; }}
  th {{ color: #7dd3fc; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
  .badge-haute {{ background: #7f1d1d; color: #fecaca; }}
  .badge-moyenne {{ background: #78350f; color: #fed7aa; }}
  .badge-faible {{ background: #14532d; color: #bbf7d0; }}
  .score-high {{ color: #f87171; font-weight: bold; }}
  code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; color: #fbbf24; font-size: 12px; }}
  .footer {{ margin-top: 50px; color: #64748b; font-size: 12px; }}
</style>
</head>
<body>

<h1>Rapport Threat Intelligence - Honeypot Cowrie</h1>
<p style="color:#94a3b8">Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}</p>

<div class="stats">
  <div class="stat-card"><div class="stat-value">{total_ips}</div><div class="stat-label">IP uniques observees</div></div>
  <div class="stat-card"><div class="stat-value">{total_connections}</div><div class="stat-label">Connexions totales</div></div>
  <div class="stat-card"><div class="stat-value">{total_commands}</div><div class="stat-label">Commandes executees</div></div>
  <div class="stat-card"><div class="stat-value">{len(high_risk)}</div><div class="stat-label">IP a haut risque (score >= 90)</div></div>
</div>

<h2>Repartition geographique</h2>
<table>
<tr><th>Pays</th><th>Nombre d'IP</th></tr>
{''.join(f"<tr><td>{c}</td><td>{n}</td></tr>" for c, n in countries.most_common(10))}
</table>

<h2>Top 10 des IP les plus malveillantes</h2>
<table>
<tr><th>IP</th><th>Score</th><th>Pays</th><th>Hebergeur</th></tr>
{''.join(f'<tr><td><code>{ip}</code></td><td class="score-high">{score}</td><td>{country}</td><td>{isp}</td></tr>' for ip, score, country, isp in high_risk[:10])}
</table>

<h2>Techniques MITRE ATT&CK observees</h2>
<table>
<tr><th>Severite</th><th>Technique</th><th>Nom</th><th>Occurrences</th><th>Exemple</th></tr>
{''.join(f'<tr><td><span class="badge badge-{sev.lower()}">{sev}</span></td><td><code>{tid}</code></td><td>{name}</td><td>{count}</td><td><code>{list(technique_examples[(tid, name, sev)])[0][:70] if technique_examples[(tid, name, sev)] else ""}</code></td></tr>' for (tid, name, sev), count in techniques_sorted)}
</table>

<div class="footer">Honeypot Cowrie deploye sur VPS OVHcloud - Analyse automatisee via script Python (parsing logs + AbuseIPDB + mapping MITRE ATT&CK)</div>

</body>
</html>
"""

    with open(OUTPUT_PATH, "w") as f:
        f.write(html)

    print(f"Rapport genere : {OUTPUT_PATH}")


if __name__ == "__main__":
    build_report()
