"""Domain registration via RDAP: expiry date and registrar lock."""

from datetime import datetime, timezone

import requests

from ..result import FAIL, PASS, WARN, Result, error

RDAP_BOOTSTRAP = "https://rdap.org/domain/{}"


def _registrar(data):
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    return item[3]
    return "your registrar"


def check_registration(ctx):
    domain = ctx.cfg.root
    try:
        resp = requests.get(RDAP_BOOTSTRAP.format(domain), timeout=ctx.cfg.net["http_timeout"],
                            headers={"Accept": "application/rdap+json"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [error("registration", domain, "RDAP lookup failed", f"{type(e).__name__}: {e}")]

    registrar = _registrar(data)
    out = []
    expiry = next((ev.get("eventDate") for ev in data.get("events", []) if ev.get("eventAction") == "expiration"), None)
    if not expiry:
        out.append(error("registration.expiry", domain, "RDAP response has no expiration date"))
    else:
        exp = datetime.fromisoformat(expiry.replace("Z", "+00:00")).astimezone(timezone.utc)
        days = (exp - ctx.now).days
        t = ctx.cfg.thresholds
        title = f"Domain expires {exp.date()} ({days} days, {registrar})"
        fix = f"Log in to {registrar} and renew {domain} (turn on auto-renew while you're there)."
        why = "If the domain lapses, all mail and the website stop, and someone else can register it."
        if days <= t["domain_expiry_fail_days"]:
            out.append(Result("registration.expiry", domain, FAIL, title, why=why, fix=fix, observed=str(exp.date())))
        elif days <= t["domain_expiry_warn_days"]:
            out.append(Result("registration.expiry", domain, WARN, title, why=why, fix=fix, observed=str(exp.date())))
        else:
            out.append(Result("registration.expiry", domain, PASS, title, observed=str(exp.date())))

    statuses = [s.lower() for s in data.get("status", [])]
    if any("transfer prohibited" in s for s in statuses):
        out.append(Result("registration.lock", domain, PASS, "Registrar transfer lock is on",
                          detail=", ".join(statuses), observed="locked"))
    else:
        out.append(Result("registration.lock", domain, WARN, "Registrar transfer lock is off",
                          detail=", ".join(statuses) or "(no statuses)",
                          why="Without clientTransferProhibited, a hijacked registrar login can move your domain away quickly.",
                          fix=f"Log in to {registrar} and turn on 'Domain lock' / 'Transfer lock' for {domain}.",
                          observed="unlocked"))
    return out
