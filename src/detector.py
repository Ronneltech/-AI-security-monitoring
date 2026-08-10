"""
Security detection engine.

Identifies suspicious patterns in structured security events.
"""

from collections import defaultdict


def detect_failed_login_bursts(events, threshold=5):
    """
    Detect repeated failed logins from the same user and source IP.

    Returns a list of security alerts.
    """

    failures = defaultdict(list)

    for event in events:
        if (
            event.get("action") == "login"
            and event.get("status") == "failed"
        ):
            key = (
                event.get("user"),
                event.get("source_ip"),
            )

            failures[key].append(event)

    alerts = []

    for (user, source_ip), failed_events in failures.items():
        if len(failed_events) >= threshold:
            alerts.append(
                {
                    "type": "brute_force_suspected",
                    "severity": "HIGH",
                    "user": user,
                    "source_ip": source_ip,
                    "failed_attempts": len(failed_events),
                    "message": (
                        "Multiple failed login attempts detected "
                        "for the same account and source IP."
                    ),
                }
            )

    return alerts


def detect_privilege_activity(events):
    """
    Detect privilege-change activity.

    Returns a list of alerts for privilege-related events.
    """

    alerts = []

    for event in events:
        if event.get("action") == "privilege_change":
            alerts.append(
                {
                    "type": "privilege_change",
                    "severity": "MEDIUM",
                    "user": event.get("user"),
                    "source_ip": event.get("source_ip"),
                    "status": event.get("status"),
                    "message": (
                        "Privilege-related activity detected "
                        "and should be reviewed."
                    ),
                }
            )

    return alerts


def detect_threats(events):
    """Run all detection rules."""

    alerts = []

    alerts.extend(detect_failed_login_bursts(events))
    alerts.extend(detect_privilege_activity(events))

    return alerts
