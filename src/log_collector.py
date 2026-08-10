"""
Security log collector.

Reads local security logs and converts each valid log entry
into structured data for further analysis.
"""

from pathlib import Path
import re


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+ \S+)\s+"
    r"(?P<level>\S+)\s+"
    r"(?P<category>\S+)\s+"
    r"user=(?P<user>\S+)\s+"
    r"source_ip=(?P<source_ip>\S+)\s+"
    r"action=(?P<action>\S+)\s+"
    r"status=(?P<status>\S+)$"
)


def parse_log_line(line):
    """Parse a single log line into structured data."""

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    return match.groupdict()


def load_logs(log_file):
    """Load and parse security logs from a file."""

    path = Path(log_file)

    if not path.exists():
        raise FileNotFoundError("Log file not found: " + log_file)

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            event = parse_log_line(line)

            if event:
                event["line_number"] = line_number
                events.append(event)

    return events


if __name__ == "__main__":
    log_path = "logs/sample_security.log"

    events = load_logs(log_path)

    print("Loaded {} security events.".format(len(events)))

    for event in events:
        print(event)
