"""
AI-assisted security event analyzer.

This module provides structured security analysis of alerts.
The current implementation uses a local rule-based analysis
layer so the project can operate without external AI services.
"""



def analyze_alert(alert):
    """Analyze a single security alert."""

    alert_type = alert.get("type")
    severity = alert.get("severity")

    if alert_type == "brute_force_suspected":
        return {
            "classification": "Potential Brute-Force Activity",
            "risk": "HIGH",
            "explanation": (
                "Multiple failed authentication attempts were detected "
                "for the same account and source IP."
            ),
            "recommendations": [
                "Review the source IP address.",
                "Verify whether the successful login was legitimate.",
                "Review authentication logs for additional activity.",
                "Consider temporarily protecting the affected account "
                "according to organizational policy.",
            ],
        }

    if alert_type == "privilege_change":
        return {
            "classification": "Privilege-Related Activity",
            "risk": severity,
            "explanation": (
                "A privilege-related event was detected and should "
                "be reviewed to confirm that the activity was authorized."
            ),
            "recommendations": [
                "Verify that the privilege change was authorized.",
                "Review the affected account.",
                "Check surrounding security events.",
            ],
        }

    return {
        "classification": "Unclassified Security Event",
        "risk": severity or "UNKNOWN",
        "explanation": (
            "The event requires additional investigation."
        ),
        "recommendations": [
            "Review the event details.",
            "Investigate related activity.",
        ],
    }


def analyze_alerts(alerts):
    """Analyze a collection of security alerts."""

    results = []

    for alert in alerts:
        analysis = analyze_alert(alert)

        results.append(
            {
                "alert": alert,
                "analysis": analysis,
            }
        )

    return results
