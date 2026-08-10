import json


def test_settings_file():
    with open("config/settings.json", "r") as file:
        config = json.load(file)

    assert config["detection"]["failed_login_threshold"] == 5
    assert config["reporting"]["report_file"] == "reports/security_report.txt"
    assert config["monitoring"]["log_file"] == "logs/sample_security.log"
