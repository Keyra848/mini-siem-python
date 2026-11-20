from collections import defaultdict
from datetime import timedelta
from typing import List, Dict
from src.parser import LogEvent

def detect_bruteforce(
    events: List[LogEvent],
    threshold: int = 5,
    window_seconds: int = 120
) -> List[Dict]:
    failed_attempts = defaultdict(list)
    alerts = []
    alerted_ips = set()

    for event in events:
        if event.status != "Failed":
            continue

        ip = event.ip
        failed_attempts[ip].append(event.timestamp)

        # Ne garder que les tentatives dans la fenêtre glissante
        cutoff = event.timestamp - timedelta(seconds=window_seconds)
        failed_attempts[ip] = [t for t in failed_attempts[ip] if t >= cutoff]

        if len(failed_attempts[ip]) >= threshold and ip not in alerted_ips:
            alerts.append({
                "rule": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": ip,
                "attempts": len(failed_attempts[ip]),
                "detected_at": event.timestamp.isoformat(),
            })
            alerted_ips.add(ip)

    return alerts