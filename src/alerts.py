from datetime import datetime


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
}


def create_alert(
    alert_type,
    severity,
    source_ip,
    username,
    description,
    attempts,
):
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}")

    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "username": username,
        "attempts": attempts,
        "description": description,
        "status": "NEW",
    }

    return alert


if __name__ == "__main__":
    alert = create_alert(
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="192.168.1.42",
        username="admin",
        description="Possible brute-force attack",
        attempts=5,
    )

    print(alert)