"""infra_audit: read-only health check of your email sending infrastructure."""

import argparse
import os
import sys
from datetime import datetime

from . import drift as drift_mod
from . import report
from .checks import SECTIONS
from .config import load_config
from .dnsutil import Dns
from .google_api import Google
from .history import History
from .result import ERROR, FAIL, WARN
from .runner import Context, run


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="infra_audit", description=__doc__)
    p.add_argument("--config", default="config.json", help="path to config.json (default: ./config.json)")
    p.add_argument("--only", choices=SECTIONS, action="append",
                   help="run only this section (repeatable): dns, reputation, mailboxes")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON instead of the console report")
    p.add_argument("--verbose", "-v", action="store_true", help="also list PASS and INFO items")
    p.add_argument("--no-save", action="store_true", help="don't record this run in history or write a report file")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not os.path.exists(args.config):
        sys.exit(f"Config not found: {args.config} (pass --config path/to/config.json)")
    cfg = load_config(args.config)
    sections = [s for s in SECTIONS if s in (args.only or SECTIONS)]

    net = cfg.net
    history = History(cfg.path("history_db"))
    ctx = Context(
        cfg=cfg,
        dns=Dns(net["dns_timeout"], net["dns_lifetime"], net["dns_retries"], net["dns_nameservers"]),
        history=history,
        google=Google(cfg.path(cfg["google"].get("service_account_file", "service_account.json"))),
    )
    previous, previous_time = history.previous(sections)
    results, elapsed = run(ctx, sections)
    # A section that couldn't run at all (broken resolver, missing key) is
    # neither compared nor saved as a baseline: it would look like everything vanished.
    skipped = {r.section for r in results if r.check in ("dns.resolver", "google.auth")}
    previous = {k: v for k, v in previous.items() if v["section"] not in skipped}
    changes = drift_mod.compute(previous, results)

    local = ctx.now.astimezone()
    data = {
        "domain": cfg.root,
        "sections": sections,
        "started_at": ctx.now.isoformat(),
        "local_time": local.strftime("%Y-%m-%d %H:%M %Z"),
        "file_stamp": local.strftime("%Y-%m-%d_%H%M%S"),
        "elapsed": elapsed,
        "results": results,
        "drift": changes,
        "counts": report.counts(results),
        "first_run": not previous,
        "previous_time": (datetime.fromisoformat(previous_time).astimezone().strftime("%Y-%m-%d %H:%M %Z")
                          if previous_time else None),
    }
    if not args.no_save:
        saved_sections = [s for s in sections if s not in skipped]
        history.save(ctx.now.isoformat(), saved_sections, [r for r in results if r.section in saved_sections],
                     data["counts"])
        data["report_path"] = report.write_markdown(data, cfg.path("reports_dir"))

    if args.json:
        print(report.to_json(data))
    else:
        print(report.render_console(data, verbose=args.verbose, color=False if args.no_color else None))

    c = data["counts"]
    regressions = any(ch.kind == drift_mod.REGRESSION for ch in changes)
    if c[FAIL] or regressions:
        return 2
    if c[WARN] or c[ERROR]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
