
from datetime import datetime, timedelta

from alerts import create_alert


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 5


def detect_brute_force(events):
    failed_events = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILED"
    ]

    # Parse each timestamp once and group events by source IP.
    events_by_ip = {}

    for event in failed_events:
        event_time = datetime.strptime(
            event.timestamp,
            TIMESTAMP_FORMAT,
        )

        events_by_ip.setdefault(event.source_ip, []).append(
            (event_time, event)
        )

    alerts = []

    for source_ip, timestamped_events in events_by_ip.items():
        # Detection should not depend on the input list's order.
        timestamped_events.sort(key=lambda item: item[0])

        left = 0
        alerted = False

        for right, (current_time, current_event) in enumerate(
            timestamped_events
        ):
            # Keep only events within the inclusive 60-second window.
            while (
                current_time - timestamped_events[left][0]
                > timedelta(seconds=WINDOW_SECONDS)
            ):
                left += 1

            attempts = right - left + 1

            if attempts >= FAILURE_THRESHOLD:
                alert = create_alert(
                    alert_type="BRUTE_FORCE",
                    severity="HIGH",
                    source_ip=source_ip,
                    username=current_event.username,
                    attempts=attempts,
                    description=(
                        f"Possible brute-force attack: "
                        f"{attempts} failed login attempts "
                        f"within {WINDOW_SECONDS} seconds"
                    ),
                )

                alerts.append(alert)
                alerted = True
                break

    return alerts
