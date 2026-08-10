from src.detector import detect_threats


def test_brute_force_detection():
    events = [
        {
            "user": "admin",
            "source_ip": "10.0.0.55",
            "action": "login",
            "status": "failed",
        }
        for _ in range(5)
    ]

    alerts = detect_threats(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "brute_force_suspected"
    assert alerts[0]["severity"] == "HIGH"


def test_privilege_correlation():
    events = [
        {
            "user": "service_account",
            "source_ip": "10.0.0.99",
            "action": "privilege_change",
            "status": "attempted",
        },
        {
            "user": "service_account",
            "source_ip": "10.0.0.99",
            "action": "privilege_change",
            "status": "approved",
        },
    ]

    alerts = detect_threats(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "correlated_privilege_activity"


def test_normal_login_creates_no_alert():
    events = [
        {
            "user": "alice",
            "source_ip": "10.0.0.15",
            "action": "login",
            "status": "success",
        }
    ]

    alerts = detect_threats(events)

    assert len(alerts) == 0
