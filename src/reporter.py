import json
from pathlib import Path
from typing import List, Dict

def print_alerts(alerts: List[Dict]) -> None:
    if not alerts:
        print("[OK] Aucune activité suspecte détectée.")
        return

    print(f"\n[!] {len(alerts)} alerte(s) détectée(s) :\n" + "-" * 50)
    for alert in alerts:
        print(
            f"[{alert['severity']}] {alert['rule']}\n"
            f"  IP source  : {alert['source_ip']}\n"
            f"  Tentatives : {alert['attempts']}\n"
            f"  Détecté à  : {alert['detected_at']}\n"
            + "-" * 50
        )

def export_json(alerts: List[Dict], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    print(f"[+] Rapport JSON exporté dans : {path}")