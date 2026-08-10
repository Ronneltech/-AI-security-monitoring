"""
AI Security Monitoring System.

Runs the complete defensive security monitoring pipeline.
"""

import json

from log_collector import load_logs
from detector import detect_threats
from ai_analyzer import analyze_alerts
from alert_manager import generate_report, save_report


CONFIG_FILE = "config/settings.json"


def load_config():
    """Load monitoring configuration from JSON."""
    with open(CONFIG_FILE, "r") as file:
        return json.load(file)


def main():
    """Run the complete security monitoring pipeline."""

    config = load_config()

    log_file = config["monitoring"]["log_file"]
    report_file = config["reporting"]["report_file"]

    print("Starting AI Security Monitoring System...")
    print()

    print("Loading security logs...")
    events = load_logs(log_file)
    print("Loaded {} security events.".format(len(events)))
    print()

    print("Running security detection rules...")
    alerts = detect_threats(events)
    print("Detected {} security alerts.".format(len(alerts)))
    print()

    print("Running AI-assisted analysis...")
    analyses = analyze_alerts(alerts)
    print("Analyzed {} security alerts.".format(len(analyses)))
    print()

    print("Generating security report...")
    report = generate_report(analyses)

    save_report(report, report_file)

    print("Report saved to:")
    print(report_file)
    print()

    print("Security monitoring complete.")


if __name__ == "__main__":
    main()
