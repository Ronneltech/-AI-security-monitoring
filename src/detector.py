from collections import defaultdict


def detect_failed_login_bursts(events, threshold=5):
    """Detect repeated failed logins from the same user and IP."""

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


def correlate_privilege_events(events):
    """Correlate privilege-change attempts and approvals."""

    activity = defaultdict(list)

    for event in events:
        if event.get("action") == "privilege_change":
            key = (
                event.get("user"),
                event.get("source_ip"),
            )

            activity[key].append(event)

    alerts = []

    for (user, source_ip), events_for_user in activity.items():
        statuses = {
            event.get("status")
            for event in events_for_user
        }

        if "attempted" in statuses and "approved" in statuses:
            alerts.append(
                {
                    "type": "correlated_privilege_activity",
                    "severity": "MEDIUM",
                    "user": user,
                    "source_ip": source_ip,
                    "message": (
                        "A privilege-change attempt was followed "
                        "by an approved privilege change for the "
                        "same account and source IP."
                    ),
                }
            )

    return alerts


def detect_threats(events, threshold=5):
    """Run all security detection and correlation rules."""

    alerts = []

    alerts.extend(
        detect_failed_login_bursts(events, threshold)
    )

    alerts.extend(
        correlate_privilege_events(events)
    )

    return alerts
