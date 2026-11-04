"""Risk engine, URL analyser and demo data for ExposureX (rule-based, explainable)."""
import re
from urllib.parse import urlparse

SENSITIVE = {"passwords", "password", "credit cards", "bank account numbers", "social security numbers",
             "government issued ids", "security questions and answers", "payment histories", "health"}

DEMO = [  # CLEARLY SAMPLE DATA - not a real lookup
    {"breach": "DemoShop", "domain": "demoshop.example", "date": "2019", "data": ["Email addresses", "Passwords"]},
    {"breach": "SampleForum", "domain": "sampleforum.example", "date": "2022", "data": ["Email addresses", "Usernames", "IP addresses"]},
    {"breach": "DemoShop (second incident)", "domain": "demoshop.example", "date": "2024", "data": ["Email addresses", "Phone numbers"]},
]

def risk_score(breaches, practices=None):
    """Return (score, level, factors). practices: dict of yes/no answers; missing = unknown."""
    practices = practices or {}
    n = len(breaches)
    f = []
    p = min(25, n * 5); f.append(("Number of exposure incidents", p, 25, f"{n} incident(s) x 5 points, capped at 25"))
    years = []
    for b in breaches:
        m = re.search(r"(19|20)\d{2}", str(b.get("date") or ""))
        if m: years.append(int(m.group()))
    if years:
        age = 2026 - max(years); p = 20 if age <= 1 else 14 if age <= 3 else 8 if age <= 6 else 3
        why = f"Most recent reported year {max(years)}"
    else:
        p, why = 10, "No dates reported: neutral 10/20 (unknown is not treated as zero risk)"
    f.append(("Recency of exposures", p, 20, why))
    cats = {c.strip().lower() for b in breaches for c in b.get("data", [])}
    hits = cats & SENSITIVE
    f.append(("Sensitive data categories", min(25, len(hits) * 9), 25, f"Sensitive categories reported: {sorted(hits) or 'none'}"))
    orgs = [(b.get("domain") or b.get("breach", "")).lower() for b in breaches]
    rep = len(orgs) - len(set(orgs))
    f.append(("Repeated exposure across services", min(15, rep * 7), 15, f"{rep} repeated organisation record(s)"))
    bad = {"mfa": False, "reuse": True, "update": False, "manager": False, "recovery": False}
    p = 0.0
    for k, risky_if in bad.items():
        v = practices.get(k)
        p += 1.5 if v is None else (3 if v == risky_if else 0)
    f.append(("User-reported security practices", round(p), 15, "Unanswered questions count as half risk"))
    score = min(100, sum(x[1] for x in f))
    level = "LOW" if score < 25 else "MODERATE" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    return score, level, [dict(factor=a, points=b, max=c, why=d) for a, b, c, d in f]

def recommendations(breaches, practices=None):
    practices, out = practices or {}, []
    cats = {c.lower() for b in breaches for c in b.get("data", [])}
    if cats & {"passwords", "password"}:
        out.append(("high", "Change affected passwords", "Password data was reported. Change it on the affected services and anywhere it was reused."))
    if practices.get("mfa") is not True:
        out.append(("high", "Enable multi-factor authentication", "MFA blocks most attacks that rely on a stolen password."))
    if practices.get("reuse") is not False:
        out.append(("high", "Stop reusing passwords", "Use a unique password per site."))
    if len(breaches) > 1:
        out.append(("medium", "Review accounts on affected services", "Several incidents were returned. Check login activity and settings."))
    if practices.get("manager") is not True:
        out.append(("medium", "Use a password manager", "It makes unique strong passwords practical."))
    if practices.get("recovery") is not True:
        out.append(("low", "Review recovery email and phone", "Make sure only you control them."))
    return [dict(priority=p, title=t, description=d) for p, t, d in out]

def analyse_url(url):
    """Pattern-based check only. The URL is NEVER fetched."""
    u = url.strip()
    host = (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()
    r = []
    if not u.lower().startswith("https://"): r.append("Not using HTTPS")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): r.append("Host is a raw IP address")
    if "@" in u.split("//")[-1].split("/")[0]: r.append("Contains '@' which can hide the real destination")
    if host.count(".") >= 4: r.append("Unusually many subdomains")
    if host.startswith("xn--") or ".xn--" in host: r.append("Punycode domain (possible look-alike characters)")
    if host.count("-") >= 3: r.append("Many hyphens in domain")
    if len(u) > 100: r.append("Very long URL")
    if any(w in host for w in ("login", "verify", "secure", "update", "account", "bank", "upi")) and host.count(".") >= 2:
        r.append("Sensitive keyword used in a subdomain")
    if host.rsplit(".", 1)[-1] in ("zip", "mov", "tk", "xyz", "top", "click"): r.append("TLD often abused in scams")
    level = "LOW" if not r else "MODERATE" if len(r) == 1 else "HIGH"
    return dict(host=host, risk=level, reasons=r or ["No suspicious pattern found"],
                note="Rule-based check only. 'Low' does not mean safe. Never enter passwords after clicking an unexpected link.")
