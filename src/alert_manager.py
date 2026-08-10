"""
Security alert manager.

Generates a readable security monitoring report
from detected alerts and AI-assisted analysis.
"""


from datetime import datetime


def generate_report(analyses):
    """Generate a formatted security monitoring report."""

    lines = []

    lines.append("=" * 60)
    lines.append("SECURITY MONITORING REPORT")
    lines.append("=" * 60)
    lines.append(
        "Generated: {}".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )
    lines.append("Alerts analyzed: {}".format(len(analyses)))
    lines.append("")

    for number, item in enumerate(analyses, start=1):
        alert = item["alert"]
        analysis = item["analysis"]

        lines.append("-" * 60)
        lines.append("ALERT #{}".format(number))
        lines.append("-" * 60)

        lines.append("Type: {}".format(alert.get("type")))
        lines.append("Severity: {}".format(alert.get("severity")))
        lines.append("User: {}".format(alert.get("user")))
        lines.append("Source IP: {}".format(alert.get("source_ip")))
        lines.append(
            "Classification: {}".format(
                analysis.get("classification")
            )
        )
        lines.append(
            "Risk: {}".format(
                analysis.get("risk")
            )
        )

        lines.append("")
        lines.append("Explanation:")
        lines.append(analysis.get("explanation", ""))

        lines.append("")
        lines.append("Recommendations:")

        for recommendation in analysis.get("recommendations", []):
            lines.append("- {}".format(recommendation))

        lines.append("")

    lines.append("=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)


def save_report(report, output_file):
    """Save a security report to a text file."""

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(report)
