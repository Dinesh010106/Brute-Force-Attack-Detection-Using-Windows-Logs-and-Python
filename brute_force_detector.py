
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "sample_failed_logins.csv"
REPORT_FILE = BASE_DIR / "report" / "brute_force_report.txt"

THRESHOLD = 5
WINDOW_MINUTES = 5


def detect_brute_force():
    attempts = defaultdict(deque)
    alerts = []

    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    try:
        with LOG_FILE.open(
            "r", newline="", encoding="utf-8-sig"
        ) as file:
            rows = list(csv.DictReader(file))

        rows.sort(
            key=lambda row: datetime.strptime(
                row["timestamp"].strip(),
                "%Y-%m-%d %H:%M:%S"
            )
        )

        for row in rows:
            if row["event_id"].strip() != "4625":
                continue

            username = row["username"].strip() or "Unknown"
            source_ip = row["source_ip"].strip() or "Unknown"

            timestamp = datetime.strptime(
                row["timestamp"].strip(),
                "%Y-%m-%d %H:%M:%S"
            )

            key = (username, source_ip)
            window = attempts[key]

            cutoff = timestamp - timedelta(
                minutes=WINDOW_MINUTES
            )

            while window and window[0] < cutoff:
                window.popleft()

            window.append(timestamp)

            if len(window) == THRESHOLD:
                alert = (
                    f"ALERT: {THRESHOLD} failed logins within "
                    f"{WINDOW_MINUTES} minutes | "
                    f"Username: {username} | "
                    f"Source IP: {source_ip} | "
                    f"Time: {timestamp}"
                )
                alerts.append(alert)
                print(alert)

    except (OSError, KeyError, ValueError) as error:
        print(f"Error processing logs: {error}")
        return

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as report:
        report.write("BRUTE-FORCE DETECTION REPORT\n")
        report.write("=" * 32 + "\n\n")
        report.write(
            f"Rule: {THRESHOLD} failed logins in "
            f"{WINDOW_MINUTES} minutes\n\n"
        )

        if alerts:
            report.write("\n".join(alerts))
            report.write(
                "\n\nRepeated failures detected. "
                "Further investigation is required.\n"
            )
        else:
            report.write("No threshold-based alerts detected.\n")

    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    detect_brute_force()
