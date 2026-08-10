"""
AI Security Monitoring System.

Runs the complete defensive security monitoring pipeline.
"""

from log_collector import load_logs
from detector import detect_threats
from ai_analyzer import analyze_alerts
from alert_manager import generate_report, save_report


LOG_FILE = "logs/sample_security.log"
REPORT_FILE = "reports/security_report.txt"


def main():
    """Run the complete security monitoring pipeline."""

    print("Starting AI Security Monitoring System...")
    print()

    print("Loading security logs...")
    events = load_logs(LOG_FILE)
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

    save_report(report, REPORT_FILE)

    print("Report saved to:")
    print(REPORT_FILE)
    print()

    print("Security monitoring complete.")


if __name__ == "__main__":
    main()
