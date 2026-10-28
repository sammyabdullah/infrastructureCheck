"""Per-mailbox Gmail settings (read-only: get/list calls under gmail.readonly)."""

from datetime import datetime, timezone

from ..google_api import GMAIL_READONLY, execute, explain
from ..result import FAIL, INFO, PASS, WARN, Result, error

WHY_FWD = ("Silent forwarding is the most common sign of a compromised mailbox: an attacker copies your mail "
           "out and can hide replies.")


def _api_error(check, mailbox, exc):
    title, detail = explain(exc, GMAIL_READONLY)
    return error(check, mailbox, title, detail)


def _settings_link(tab):
    return f"Gmail (logged in as that mailbox) > Settings (gear) > See all settings > {tab}"


def check_auto_forwarding(ctx, mailbox):
    try:
        af = execute(ctx.google.gmail(mailbox).users().settings().getAutoForwarding(userId="me"))
    except Exception as e:
        return [_api_error("gmail.autoforward", mailbox, e)]
    if not af.get("enabled"):
        return [Result("gmail.autoforward", mailbox, PASS, "Auto-forwarding off", observed="off")]
    to = af.get("emailAddress", "?").lower()
    observed = f"on -> {to} ({af.get('disposition', '')})"
    if to in ctx.cfg["allowed_forwarding"]:
        return [Result("gmail.autoforward", mailbox, INFO, f"Auto-forwarding to approved {to}", observed=observed)]
    return [Result("gmail.autoforward", mailbox, FAIL, f"Auto-forwarding ON to {to}",
                   why=WHY_FWD,
                   fix=f"{_settings_link('Forwarding and POP/IMAP')}: select 'Disable forwarding' and Save. If you didn't "
                       "set this up, also reset the password and review Security > Your devices. (If it's intended, add "
                       "the address to allowed_forwarding in config.json.)",
                   observed=observed)]


def check_forwarding_addresses(ctx, mailbox):
    try:
        resp = execute(ctx.google.gmail(mailbox).users().settings().forwardingAddresses().list(userId="me"))
    except Exception as e:
        return [_api_error("gmail.fwd_addresses", mailbox, e)]
    addrs = sorted(a["forwardingEmail"].lower() for a in resp.get("forwardingAddresses", []))
    unknown = [a for a in addrs if a not in ctx.cfg["allowed_forwarding"]]
    if unknown:
        return [Result("gmail.fwd_addresses", mailbox, WARN, "Forwarding address(es) registered: " + ", ".join(unknown),
                       why="A registered forwarding address can be switched on (or used by a filter) at any time.",
                       fix=f"{_settings_link('Forwarding and POP/IMAP')}: open the forwarding address dropdown and "
                           "'Remove' each address you don't recognize.",
                       observed=",".join(addrs))]
    return [Result("gmail.fwd_addresses", mailbox, PASS, "No unexpected forwarding addresses", observed=",".join(addrs))]


def describe_filter(f):
    c = f.get("criteria", {})
    crit = ", ".join(f"{k}={v}" for k, v in c.items()) or "(all mail)"
    return crit


def _norm(text):
    return "".join(ch for ch in text.lower() if ch.isalnum())


def check_filters(ctx, mailbox):
    try:
        resp = execute(ctx.google.gmail(mailbox).users().settings().filters().list(userId="me"))
    except Exception as e:
        return [_api_error("gmail.filters", mailbox, e)]
    # Filters you've approved (config allowed_filter_terms) may archive/delete/spam
    # mail; a filter that forwards is still judged against allowed_forwarding.
    approved_terms = [_norm(t) for t in ctx.cfg.get("allowed_filter_terms", []) if _norm(t)]
    flagged, approved, worst = [], 0, PASS
    for f in resp.get("filter", []):
        action = f.get("action", {})
        add, remove = action.get("addLabelIds", []), action.get("removeLabelIds", [])
        reasons = []
        fwd = action.get("forward")
        if fwd:
            reasons.append(f"forwards to {fwd}")
            if fwd.lower() not in ctx.cfg["allowed_forwarding"]:
                worst = FAIL
        if "TRASH" in add:
            reasons.append("auto-deletes")
        if "SPAM" in add:
            reasons.append("sends to spam")
        if "INBOX" in remove:
            reasons.append("skips inbox (auto-archive)")
        if reasons and not fwd and any(t in _norm(describe_filter(f)) for t in approved_terms):
            approved += 1
            continue
        if reasons:
            flagged.append(f"[{describe_filter(f)}] {', '.join(reasons)}")
            if worst != FAIL:
                worst = WARN
    if not flagged:
        note = f" ({approved} approved archive filter(s) not counted)" if approved else ""
        return [Result("gmail.filters", mailbox, PASS,
                       f"{len(resp.get('filter', []))} filter(s), none unexpected hide or forward mail{note}",
                       observed="(none)")]
    return [Result("gmail.filters", mailbox, worst, f"{len(flagged)} filter(s) forward, delete or archive mail",
                   detail=" | ".join(flagged),
                   why="Filters like these can hide replies and bounces from you, and attackers use them to conceal "
                       "a compromise.",
                   fix=f"{_settings_link('Filters and Blocked Addresses')}: delete any listed filter you didn't create "
                       "on purpose.",
                   observed=" | ".join(sorted(flagged)))]


def check_delegates(ctx, mailbox):
    try:
        resp = execute(ctx.google.gmail(mailbox).users().settings().delegates().list(userId="me"))
    except Exception as e:
        return [_api_error("gmail.delegates", mailbox, e)]
    delegates = sorted(d["delegateEmail"].lower() for d in resp.get("delegates", []))
    unknown = [d for d in delegates if d not in ctx.cfg["allowed_delegates"]]
    if unknown:
        return [Result("gmail.delegates", mailbox, WARN, "Mailbox delegate(s): " + ", ".join(unknown),
                       why="Delegates can read, send and delete mail as this mailbox.",
                       fix=f"{_settings_link('Accounts')} > 'Grant access to your account': click 'delete' next to each "
                           "delegate you don't recognize (or add them to allowed_delegates in config.json).",
                       observed=",".join(delegates))]
    return [Result("gmail.delegates", mailbox, PASS, "No unexpected delegates", observed=",".join(delegates))]


def check_send_as(ctx, mailbox):
    try:
        resp = execute(ctx.google.gmail(mailbox).users().settings().sendAs().list(userId="me"))
    except Exception as e:
        return [_api_error("gmail.sendas", mailbox, e)]
    aliases = sorted(s["sendAsEmail"].lower() for s in resp.get("sendAs", []))
    allowed = set(ctx.cfg["allowed_send_as"]) | {mailbox}
    unknown = [a for a in aliases if a not in allowed]
    relays = sorted(s["sendAsEmail"].lower() for s in resp.get("sendAs", []) if s.get("smtpMsa"))
    out = []
    if unknown:
        out.append(Result("gmail.sendas", mailbox, WARN, "Unrecognized send-as alias(es): " + ", ".join(unknown),
                          why="Mail sent as an unexpected address may not be covered by your SPF/DKIM and can signal "
                              "account misuse.",
                          fix=f"{_settings_link('Accounts')} > 'Send mail as': click 'delete' next to each alias you don't "
                              "use (or add it to allowed_send_as in config.json).",
                          observed=",".join(aliases)))
    else:
        out.append(Result("gmail.sendas", mailbox, PASS, f"{len(aliases)} send-as address(es), all recognized",
                          observed=",".join(aliases)))
    if relays:
        out.append(Result("gmail.sendas_smtp", mailbox, INFO, "Send-as via external SMTP: " + ", ".join(relays),
                          detail="This alias sends through another provider's server, not Google's.",
                          observed=",".join(relays)))
    return out


def check_vacation(ctx, mailbox):
    try:
        v = execute(ctx.google.gmail(mailbox).users().settings().getVacation(userId="me"))
    except Exception as e:
        return [_api_error("gmail.vacation", mailbox, e)]
    if not v.get("enableAutoReply"):
        return [Result("gmail.vacation", mailbox, PASS, "Vacation responder off", observed="off")]
    now_ms = ctx.now.timestamp() * 1000
    start, end = int(v.get("startTime", 0) or 0), int(v.get("endTime", 0) or 0)
    if end and end < now_ms:
        return [Result("gmail.vacation", mailbox, PASS, "Vacation responder ended", observed="off")]
    if start and start > now_ms:
        when = datetime.fromtimestamp(start / 1000, tz=timezone.utc).date()
        return [Result("gmail.vacation", mailbox, INFO, f"Vacation responder scheduled from {when}", observed="scheduled")]
    until = f" until {datetime.fromtimestamp(end / 1000, tz=timezone.utc).date()}" if end else " (no end date)"
    return [Result("gmail.vacation", mailbox, WARN, "Vacation responder is ON" + until,
                   detail=f"Subject: {v.get('responseSubject', '')}",
                   why="Every inbound message (including replies to your outreach) gets an auto-reply; "
                       "easy to forget it's on.",
                   fix=f"{_settings_link('General')} > Vacation responder: select 'Vacation responder off' and Save.",
                   observed="on")]
