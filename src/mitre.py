import re
from collections import defaultdict
from parser import parse_logs

# Regles de mapping : (motif regex, technique MITRE, nom, severite)
RULES = [
    (r"\bwhoami\b", "T1033", "System Owner/User Discovery", "FAIBLE"),
    (r"\buname\b", "T1082", "System Information Discovery", "FAIBLE"),
    (r"/etc/passwd", "T1552.001", "Unsecured Credentials: Credentials In Files", "MOYENNE"),
    (r"\bwget\b|\bcurl\b|\btftp\b", "T1105", "Ingress Tool Transfer", "HAUTE"),
    (r"\bbusybox\b", "T1059.004", "Command and Scripting Interpreter: Unix Shell", "MOYENNE"),
    (r"\bcrontab\b|/etc/cron", "T1053.003", "Scheduled Task/Job: Cron", "HAUTE"),
    (r"\bchmod\b.*\+x|\bchmod 777\b", "T1222.002", "File and Directory Permissions Modification", "MOYENNE"),
    (r"\bcat /proc/cpuinfo\b|\bnproc\b", "T1082", "System Information Discovery", "FAIBLE"),
    (r"\bkillall\b|\bpkill\b", "T1489", "Service Stop", "MOYENNE"),
    (r"\becho\b.*(xsec|shell|root)", "T1059.004", "Command and Scripting Interpreter (fingerprinting)", "FAIBLE"),
    (r"\bshell\b|\blinuxshell\b|\benable\b", "T1059.004", "Command and Scripting Interpreter: Unix Shell", "FAIBLE"),
]


def classify_command(cmd_text):
    """Retourne la liste des techniques MITRE detectees dans une commande."""
    matches = []
    for pattern, technique_id, technique_name, severity in RULES:
        if re.search(pattern, cmd_text, re.IGNORECASE):
            matches.append((technique_id, technique_name, severity))
    return matches


def analyze_commands(profiles):
    """Parcourt tous les profils IP et compte les techniques MITRE observees."""
    technique_counts = defaultdict(int)
    technique_examples = defaultdict(set)

    for ip, profile in profiles.items():
        for cmd in profile["commands"]:
            cmd_text = cmd.get("input", "") or ""
            for technique_id, technique_name, severity in classify_command(cmd_text):
                technique_counts[(technique_id, technique_name, severity)] += 1
                technique_examples[(technique_id, technique_name, severity)].add(cmd_text[:60])

    return technique_counts, technique_examples


if __name__ == "__main__":
    profiles = parse_logs()
    counts, examples = analyze_commands(profiles)

    print("Techniques MITRE ATT&CK observees :\n")
    for (technique_id, name, severity), count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"[{severity}] {technique_id} - {name} : {count} occurrences")
        for ex in list(examples[(technique_id, name, severity)])[:2]:
            print(f"    exemple: {ex}")
