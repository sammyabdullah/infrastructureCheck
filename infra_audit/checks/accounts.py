"""Account-level checks across all mailboxes: Admin SDK security status,
sending activity, and hard bounces from HardBounceCheck's database."""

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from ..google_api import DIRECTORY_USER_READONLY, GMAIL_READONLY, execute, explain
from ..result import FAIL, INFO, PASS, WARN, Result, error


# ---------------------------------------------------------------- Admin SDK

def check_directory(ctx):
    g = ctx.cfg["google"]
    if not g.get("directory_scope_approved"):
        return [Result("directory.skipped", ctx.cfg.root, INFO,
                       "Account security checks skipped (Admin SDK scope not approved)",
                       detail="2-Step Verification, last login, suspended/archived and admin status need the "
                              "admin.directory.user.readonly scope, which your service account doesn't have yet. "
                              "See README 'Scopes' to approve it.")]
    admin = g.get("admin_email")
    if not admin:
        return [error("directory", ctx.cfg.root, "google.admin_email is not set in config.json")]
    try:
        svc = ctx.google.directory(admin)
    except Exception as e:
        return [error("directory", ctx.cfg.root, *explain(e, DIRECTORY_USER_READONLY))]
    out = []
    for mailbox in ctx.cfg["mailboxes"]:
        try:
            u = execute(svc.users().get(userKey=mailbox, projection="basic"))
        except Exception as e:
            out.append(error("directory.user", mailbox, *explain(e, DIRECTORY_USER_READONLY)))
            continue
        out.extend(_grade_user(ctx, mailbox, u))
    return out


def _grade_user(ctx, mailbox, u):
    out = []
    user_page = "Google Admin console > Directory > Users > " + mailbox
    if u.get("primaryEmail", "").lower() != mailbox:
        out.append(Result("directory.alias", mailbox, INFO, f"{mailbox} is an alias of {u.get('primaryEmail')}",
                          observed=u.get("primaryEmail")))

    if not u.get("isEnrolledIn2Sv"):
        out.append(Result("directory.2sv", mailbox, FAIL, "2-Step Verification NOT enrolled",
                          why="A phished password alone gives full access to send as you, which is how most "
                              "mailbox takeovers start.",
                          fix="Sign in as this user and enroll at myaccount.google.com > Security > 2-Step Verification.",
                          observed="not-enrolled"))
    elif not u.get("isEnforcedIn2Sv"):
        out.append(Result("directory.2sv", mailbox, WARN, "2-Step Verification enrolled but not enforced",
                          why="The user (or an attacker with the password) can switch 2SV off.",
                          fix="Google Admin console > Security > Authentication > 2-step verification: check "
                              "'Allow users to turn on 2-Step Verification' and set Enforcement to On.",
                          observed="enrolled"))
    else:
        out.append(Result("directory.2sv", mailbox, PASS, "2-Step Verification enrolled and enforced", observed="enforced"))

    if u.get("suspended") or u.get("archived"):
        state = "suspended" if u.get("suspended") else "archived"
        out.append(Result("directory.state", mailbox, FAIL, f"Account is {state}",
                          detail=u.get("suspensionReason", ""),
                          why="It can't send or receive; mail to it bounces, which hurts your sender reputation.",
                          fix=f"{user_page} > Reactivate (if this is unexpected, check Security > Alert center first).",
                          observed=state))
    else:
        out.append(Result("directory.state", mailbox, PASS, "Account active", observed="active"))

    last = u.get("lastLoginTime", "")
    if not last or last.startswith("1970"):
        out.append(Result("directory.login", mailbox, WARN, "Account has never signed in",
                          why="Unused accounts are an easy takeover target and nobody would notice.",
                          fix=f"Sign in once and set up 2SV, or suspend it at {user_page} if it's not needed.",
                          observed="never"))
    else:
        when = datetime.fromisoformat(last.replace("Z", "+00:00"))
        days = (ctx.now - when).days
        if days > ctx.cfg.thresholds["last_login_warn_days"]:
            out.append(Result("directory.login", mailbox, WARN, f"Last sign-in {days} days ago ({when.date()})",
                              why="A dormant account that still sends (or could be used to send) is a takeover risk.",
                              fix=f"Confirm who uses it; review {user_page} > Security for app passwords and OAuth grants."))
        else:
            out.append(Result("directory.login", mailbox, PASS, f"Last sign-in {when.date()}"))

    if u.get("isAdmin") or u.get("isDelegatedAdmin"):
        role = "super admin" if u.get("isAdmin") else "delegated admin"
        out.append(Result("directory.admin", mailbox, INFO, f"Has {role} rights", observed=role))
    else:
        out.append(Result("directory.admin", mailbox, INFO, "Not an admin", observed="user"))
    return out


# ---------------------------------------------------------- sending activity

def _count_sent(svc, after_ts, before_ts):
    q = f"in:sent after:{int(after_ts)} before:{int(before_ts)}"
    total, token = 0, None
    while True:
        resp = execute(svc.users().messages().list(
            userId="me", q=q, maxResults=500, pageToken=token, fields="messages/id,nextPageToken"))
        total += len(resp.get("messages", []))
        token = resp.get("nextPageToken")
        if not token:
            return total


def _daily_counts(ctx, mailbox, day_starts, today_start):
    """Sent counts for each full local day in `day_starts`, plus today so far."""
    svc = ctx.google.gmail(mailbox)
    counts = [_count_sent(svc, d.timestamp(), (d + timedelta(days=1)).timestamp()) for d in day_starts]
    today = _count_sent(svc, today_start.timestamp(), ctx.now.timestamp() + 60)
    return counts, today


def find_spikes(counts, multiplier, min_count, min_history=3):
    """Indexes of days whose count exceeds `multiplier` x the average of the days before it."""
    spikes = []
    for i in range(min_history, len(counts)):
        avg = sum(counts[:i]) / i
        if counts[i] >= min_count and counts[i] > multiplier * avg:
            spikes.append((i, avg))
    return spikes


def check_sending_activity(ctx):
    t = ctx.cfg.thresholds
    n = int(t["activity_days"])
    local_now = ctx.now.astimezone()
    today_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_starts = [today_start - timedelta(days=n - i) for i in range(n)]  # oldest first, ends yesterday

    mailboxes = ctx.cfg["mailboxes"]
    with ThreadPoolExecutor(max_workers=len(mailboxes) or 1) as pool:
        futures = {m: pool.submit(_daily_counts, ctx, m, day_starts, today_start) for m in mailboxes}
    data, out = {}, []
    for m, fut in futures.items():
        try:
            data[m] = fut.result()
        except Exception as e:
            out.append(error("activity", m, *explain(e, GMAIL_READONLY)))

    active = [m for m, (c, today) in data.items() if sum(c) + today > 0]
    for m, (counts, today) in data.items():
        total = sum(counts)
        series = " ".join(str(c) for c in counts)
        detail = f"Last {n} days (oldest first): {series}; today so far: {today}"
        out.append(Result("activity.volume", m, INFO, f"Sent {total} in {n} days (avg {total / n:.1f}/day)", detail=detail))

        spikes = find_spikes(counts, t["activity_spike_multiplier"], t["activity_spike_min_count"])
        if spikes:
            desc = ", ".join(f"{day_starts[i].date()}: {counts[i]} vs avg {avg:.1f}" for i, avg in spikes)
            out.append(Result("activity.spike", m, WARN, f"Sending spike: {desc}",
                              detail=detail,
                              why="A sudden jump in volume is what trips Gmail/Outlook rate and spam filters, and is also "
                                  "the first sign of a hijacked mailbox sending spam.",
                              fix="Confirm you sent these (Gmail > Sent for those dates). If not: reset the password, sign "
                                  "out all sessions, and check filters/forwarding and Admin console > Reporting > Email log search.",
                              # latest spike date: a new spike shows as drift, an old one aging out doesn't
                              observed=str(day_starts[spikes[-1][0]].date())))
        else:
            out.append(Result("activity.spike", m, PASS, f"No day above {t['activity_spike_multiplier']}x trailing average",
                              observed="(none)"))

        if total + today == 0 and active:
            out.append(Result("activity.dormant", m, WARN, f"No mail sent in {n}+ days while other mailboxes are active",
                              why="A dormant mailbox loses sender reputation and suddenly restarting volume from it looks "
                                  "suspicious to receivers; it may also be an account nobody is watching.",
                              fix="If it's still in use, warm it back up gradually (a few real sends per day). If not, "
                                  "consider suspending it in Admin console.",
                              observed="dormant"))
        else:
            out.append(Result("activity.dormant", m, PASS, "Mailbox is sending", observed="active"))
    return out


# --------------------------------------------------------------- hard bounces

def check_hard_bounces(ctx):
    """Last-7-day HARD bounces per mailbox from HardBounceCheck's bounces.db.

    That table keeps one row per bounced address, so this counts addresses
    whose latest HARD bounce was in the last 7 days, credited to each mailbox
    in its sending_mailboxes list. Skipped silently if the DB isn't there.
    """
    path = ctx.cfg.path("bounce_db") if ctx.cfg.get("bounce_db") else ""
    if not path or not os.path.exists(path):
        return []
    cutoff = (ctx.now - timedelta(days=7)).astimezone(timezone.utc).isoformat()
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT sending_mailboxes FROM bounces WHERE bounce_type = 'HARD' AND last_seen >= ?", (cutoff,)
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []  # different schema / unreadable: skip silently as requested
    counts = {m: 0 for m in ctx.cfg["mailboxes"]}
    for (mailboxes,) in rows:
        for m in (mailboxes or "").split(","):
            m = m.strip().lower()
            if m in counts:
                counts[m] += 1
    warn_at = ctx.cfg.thresholds["hard_bounces_7d_warn"]
    out = []
    for m, n in counts.items():
        if n >= warn_at:
            out.append(Result("bounces.hard_7d", m, WARN, f"{n} hard-bounced addresses in the last 7 days",
                              detail=f"From {path}",
                              why="Hard bounce rates above ~2% get you throttled or spam-foldered by Gmail and Outlook.",
                              fix="Run HardBounceCheck with --contacts and remove everything in removal_list.csv from your "
                                  "send lists; verify new lists (mailerdemon) before sending."))
        else:
            out.append(Result("bounces.hard_7d", m, INFO, f"{n} hard-bounced addresses in the last 7 days"))
    return out
