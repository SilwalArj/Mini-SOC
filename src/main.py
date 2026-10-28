
import argparse

from parser import parse_log_file
from detector import detect_brute_force
from database import (
    create_tables,
    insert_event,
    insert_alert,
    get_events,
    get_alerts,
    update_alert_status,
)


def run_pipeline():
    log_file = "logs/sample_auth.log"

    parsed_events = parse_log_file(log_file)

    inserted_events = sum(
        insert_event(event) for event in parsed_events
    )

    all_events = get_events()
    detected_alerts = detect_brute_force(all_events)

    inserted_alerts = sum(
        insert_alert(alert) for alert in detected_alerts
    )

    print("\n--- Mini SOC Summary ---")
    print(f"Events parsed: {len(parsed_events)}")
    print(f"New events stored: {inserted_events}")
    print(f"Events in database: {len(all_events)}")
    print(f"Alerts detected: {len(detected_alerts)}")
    print(f"New alerts stored: {inserted_alerts}")


def show_alerts(severity=None):
    alerts = get_alerts(severity)

    if not alerts:
        print("No alerts found.")
        return

    for alert in alerts:
        alert_id, timestamp, alert_type, severity, ip, description, status = alert

        print(
            f"ID: {alert_id} | "
            f"{severity} | {alert_type} | "
            f"IP: {ip} | Status: {status}"
        )
        print(f"Time: {timestamp}")
        print(f"Description: {description}")
        print("-" * 60)


def change_status(alert_id, status):
    updated = update_alert_status(alert_id, status)

    if updated:
        print(f"Alert {alert_id} updated to {status.upper()}.")
    else:
        print(f"Alert ID {alert_id} was not found.")


def main():
    create_tables()

    parser = argparse.ArgumentParser(
        description="Mini SOC Security Monitoring CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "run",
        help="Parse logs, detect threats, and store results",
    )

    alerts_parser = subparsers.add_parser(
        "alerts",
        help="List stored security alerts",
    )
    alerts_parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter alerts by severity",
    )

    status_parser = subparsers.add_parser(
        "status",
        help="Update an alert's investigation status",
    )
    status_parser.add_argument("id", type=int)
    status_parser.add_argument(
        "value",
        choices=["NEW", "INVESTIGATING", "RESOLVED"],
    )

    args = parser.parse_args()

    if args.command == "run":
        print("Mini SOC starting...")
        run_pipeline()

    elif args.command == "alerts":
        show_alerts(args.severity)

    elif args.command == "status":
        change_status(args.id, args.value)


if __name__ == "__main__":
    main()
