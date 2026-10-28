import re
from models import Event

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<severity>\w+) "
    r"(?P<event_type>\w+) "
    r"user=(?P<username>\S+) "
    r"ip=(?P<source_ip>\S+)$"
)

def parse_log_line(line):
    line = line.strip()
    match = LOG_PATTERN.match(line)

    if not match:
        raise ValueError(f"Invalid log format: {line}")

    event = Event(
        timestamp =match.group("timestamp"),
        event_type = match.group("event_type"),
        username = match.group("username"),
        source_ip = match.group("source_ip"),
        severity = match.group("severity"),
        raw_log = line,
    )

    return event

def parse_log_file(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):

            if not line.strip():
                continue

            try:
                event = parse_log_line(line)
                events.append(event)

            except ValueError as error:
                print(f"Warning: Could not parse line {line_number}: {error}")

    return events

if __name__ == "__main__":
    log_file = "logs/sample_auth.log"

    events = parse_log_file(log_file)

    for event in events:
        print(event)