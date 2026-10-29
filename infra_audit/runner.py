"""Run the registered checks concurrently and collect results."""

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .checks import CHECKS
from .google_api import Google
from .result import error


@dataclass
class Context:
    cfg: object
    dns: object
    history: object
    google: object
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _label(fn, arg):
    name = fn.__name__.removeprefix("check_")
    if isinstance(arg, dict):
        return name, arg["domain"]
    return name, arg or ""


def _invoke(ctx, section, fn, arg):
    try:
        results = fn(ctx, arg) if arg is not None else fn(ctx)
    except Exception as e:  # a crashing check is an ERROR, never a pass
        name, target = _label(fn, arg)
        results = [error(name, target or ctx.cfg.root, f"Check '{name}' crashed", f"{type(e).__name__}: {e}")]
    for r in results:
        r.section = section
    return results


CANARIES = [("google.com", "A"), ("gmail.com", "MX")]


def dns_preflight(ctx):
    """None if the resolver answers known-good names, else an error string.

    Without this, a broken or filtering resolver that answers NXDOMAIN for
    everything would turn into "No SPF record" FAILs and "not listed" PASSes.
    """
    for name, rdtype in CANARIES:
        ans = ctx.dns.query(name, rdtype)
        if not ans.ok:
            return f"{name} {rdtype} lookup returned {ans.status} {ans.error}".strip()
    return None


def run(ctx, sections, checks=None, preflight=True):
    """Returns (results, elapsed_seconds)."""
    checks = CHECKS if checks is None else checks
    started = time.monotonic()
    jobs = []
    results = []
    google_ready = True

    dns_sections = {"dns", "reputation"} & set(sections)
    if preflight and dns_sections:
        problem = dns_preflight(ctx)
        if problem:
            for section in sorted(dns_sections):
                r = error("dns.resolver", ctx.cfg.root,
                          f"DNS resolver isn't working; {section} checks skipped (results would be meaningless)",
                          problem + ". Check your network/VPN, or set network.dns_nameservers in config.json "
                                    "(e.g. your router's IP).")
                r.section = section
                results.append(r)
            sections = [s for s in sections if s not in dns_sections]
    if "mailboxes" in sections and isinstance(ctx.google, Google) and ctx.google.key_missing():
        google_ready = False
        results.append(error("google.auth", ctx.cfg.root,
                             "Mailbox checks skipped: service account key not found",
                             f"Expected at {ctx.google.key_path} (google.service_account_file in config.json). Use the "
                             "same service_account.json as HardBounceCheck / Engagement-Tracker."))
        results[-1].section = "mailboxes"

    for section, scope, fn in checks:
        if section not in sections or (section == "mailboxes" and not google_ready):
            continue
        if scope == "domain":
            jobs += [(section, fn, d) for d in ctx.cfg.active_domains]
        elif scope == "mailbox":
            jobs += [(section, fn, m) for m in ctx.cfg["mailboxes"]]
        else:
            jobs.append((section, fn, None))

    with ThreadPoolExecutor(max_workers=int(ctx.cfg.net["workers"])) as pool:
        futures = [pool.submit(_invoke, ctx, section, fn, arg) for section, fn, arg in jobs]
        for f in futures:
            results.extend(f.result())
    return results, time.monotonic() - started
