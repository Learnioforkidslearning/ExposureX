import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from services import risk_score, analyse_url, DEMO

def test_unknown_is_not_zero():
    s, lvl, _ = risk_score([], None); assert s > 0

def test_cap_and_level():
    s, lvl, f = risk_score(DEMO * 5, {"mfa": False, "reuse": True}); assert 0 <= s <= 100 and lvl in ("HIGH", "CRITICAL")

def test_repeated_org_counted():
    _, _, f = risk_score(DEMO); assert [x for x in f if x["factor"].startswith("Repeated")][0]["points"] > 0

def test_url_ip_and_http():
    assert analyse_url("http://192.168.1.5/login")["risk"] == "HIGH"

def test_url_clean_not_called_safe():
    assert "safe" in analyse_url("https://example.com")["note"].lower()
