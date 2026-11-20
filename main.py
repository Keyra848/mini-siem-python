import argparse
from pathlib import Path
from src.parser import parse_line
from src.detector import detect_bruteforce
from src.reporter import print_alerts, export_json

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini-SIEM Python : analyseur de logs SSH."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Chemin vers le fichier de logs"
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=5, help="Nombre d'échecs avant alerte (défaut: 5)"
    )
    parser.add_argument(
        "-w", "--window", type=int, default=120, help="Fenêtre de temps en secondes (défaut: 120)"
    )
    parser.add_argument(
        "-o", "--output", help="Chemin d'export JSON optionnel (ex: reports/alerts.json)"
    )
    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.is_file():
        print(f"[ERREUR] Fichier introuvable : {log_path}")
        return

    events = []
    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    print(f"[*] {len(events)} événements SSH parsés depuis {log_path}")

    alerts = detect_bruteforce(
        events, threshold=args.threshold, window_seconds=args.window
    )
    print_alerts(alerts)

    if args.output:
        export_json(alerts, args.output)

if __name__ == "__main__":
    main()