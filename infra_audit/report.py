"""Console, Markdown and JSON output."""

import json
import os
import sys
import time
from collections import Counter

from .drift import CHECK_FAILED, CHANGED, IMPROVED, REGRESSION
from .result import ERROR, FAIL, INFO, PASS, REPORT_ORDER, WARN

COLORS = {FAIL: "31", WARN: "33", ERROR: "35", PASS: "32", INFO: "36",
          REGRESSION: "31", CHANGED: "33", CHECK_FAILED: "35", IMPROVED: "32"}


def counts(results):
    c = Counter(r.status for r in results)
    return {s: c.get(s, 0) for s in (FAIL, WARN, ERROR, PASS, INFO)}


def count_line(c):
    return " · ".join(f"{c[s]} {s}" for s in (FAIL, WARN, ERROR, PASS, INFO))


def _sorted(results, statuses):
    return sorted((r for r in results if r.status in statuses),
                  key=lambda r: (REPORT_ORDER[r.status], r.section, r.check, r.target))


def _short(value, n=110):
    value = "(none)" if value is None else str(value)
    return value if len(value) <= n else value[: n - 1] + "…"


class Painter:
    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, key):
        return f"\033[{COLORS.get(key, '0')}m{text}\033[0m" if self.enabled else text

    def bold(self, text):
        return f"\033[1m{text}\033[0m" if self.enabled else text


def render_console(run, verbose=False, color=None):
    paint = Painter(sys.stdout.isatty() if color is None else color)
    results, drift, c = run["results"], run["drift"], run["counts"]
    lines = []
    header = f"infra_audit · {run['domain']} · {run['local_time']} · {run['elapsed']:.1f}s · sections: {', '.join(run['sections'])}"

    if not drift and c[FAIL] == 0 and c[WARN] == 0 and c[ERROR] == 0:
        note = ("first run, baseline saved" if run.get("report_path") else "first run") if run["first_run"] \
            else "no changes since last run"
        lines.append(paint(f"OK All healthy: {count_line(c)} · {run['local_time']} ({note})", PASS))
        if run.get("report_path"):
            lines.append(f"  Report: {run['report_path']}")
        return "\n".join(lines)

    lines.append(paint.bold(header))
    lines.append("")
    if run["first_run"]:
        saved = "baseline saved" if run.get("report_path") else "nothing saved (--no-save)"
        lines.append(paint.bold(f"DRIFT: first run, {saved}. The next saved run will show what changed."))
    elif drift:
        lines.append(paint.bold(f"DRIFT since last run ({run['previous_time']}): {len(drift)} change(s)"))
        for ch in drift:
            arrow = f"{ch.before_status} -> {ch.after_status}" if ch.after_status else f"was {ch.before_status}"
            lines.append(f"  {paint(f'{ch.kind:<12}', ch.kind)} {ch.target}: {ch.title}  [{arrow}]")
            if ch.before is not None or ch.after is not None:
                if ch.kind in (REGRESSION, CHANGED) or ch.after is None:
                    lines.append(f"      before: {_short(ch.before)}")
                    lines.append(f"      after:  {_short(ch.after)}")
    else:
        lines.append(paint.bold(f"DRIFT since last run ({run['previous_time']}): no changes"))
    lines.append("")

    for status in (FAIL, WARN, ERROR):
        items = _sorted(results, {status})
        if not items:
            continue
        label = {FAIL: "FAIL", WARN: "WARN", ERROR: "ERROR: check could not run (NOT a pass; re-run)"}[status]
        lines.append(paint.bold(f"{label} ({len(items)})"))
        for r in items:
            lines.append(f"  {paint(f'[{r.status}]', r.status)} {r.target}: {r.title}")
            if r.detail:
                lines.append(f"      Found: {r.detail}")
            if status != ERROR and r.why:
                lines.append(f"      Why:   {r.why}")
            if status != ERROR and r.fix:
                lines.append(f"      Fix:   {r.fix}")
        lines.append("")

    if verbose:
        for status in (INFO, PASS):
            items = _sorted(results, {status})
            if items:
                lines.append(paint.bold(f"{status} ({len(items)})"))
                lines += [f"  {paint(f'[{status}]', status)} {r.target}: {r.title}" for r in items]
                lines.append("")

    lines.append(paint.bold("Summary: ") + count_line(c) + ("" if verbose else "   (use --verbose to list PASS/INFO)"))
    if run.get("report_path"):
        lines.append(f"Report: {run['report_path']}")
    return "\n".join(lines)


def render_markdown(run):
    results, drift, c = run["results"], run["drift"], run["counts"]
    md = [f"# infra_audit report: {run['domain']}", "",
          f"- Run: {run['local_time']} ({run['elapsed']:.1f}s)",
          f"- Sections: {', '.join(run['sections'])}",
          f"- Totals: {count_line(c)}", ""]
    md.append("## Drift since last run")
    if run["first_run"]:
        md.append("First run: baseline saved.")
    elif not drift:
        md.append(f"No changes since {run['previous_time']}.")
    else:
        md.append(f"Compared with {run['previous_time']}.\n")
        md.append("| Change | Target | Check | Status | Before | After |")
        md.append("|---|---|---|---|---|---|")
        for ch in drift:
            md.append(f"| {ch.kind} | {ch.target} | {ch.title} | {ch.before_status} → {ch.after_status or '-'} "
                      f"| {_md(ch.before)} | {_md(ch.after)} |")
    md.append("")
    for status in (FAIL, WARN, ERROR):
        items = _sorted(results, {status})
        if not items:
            continue
        md.append(f"## {status} ({len(items)})")
        for r in items:
            md.append(f"### {r.target}: {r.title}")
            md.append(f"- Check: `{r.check}` ({r.section})")
            if r.detail:
                md.append(f"- Found: {r.detail}")
            if r.why:
                md.append(f"- Why it matters: {r.why}")
            if r.fix:
                md.append(f"- Fix: {r.fix}")
            md.append("")
    for status in (INFO, PASS):
        items = _sorted(results, {status})
        if items:
            md.append(f"## {status} ({len(items)})")
            md += [f"- **{r.target}**: {r.title}" + (f" ({r.detail})" if r.detail else "") for r in items]
            md.append("")
    return "\n".join(md)


def _md(value):
    return "" if value is None else _short(value, 80).replace("|", "\\|")


def prune_reports(reports_dir, keep_days):
    """Delete this tool's own dated reports older than keep_days (history stays in SQLite)."""
    if not keep_days:
        return
    cutoff = time.time() - keep_days * 86400
    for name in os.listdir(reports_dir):
        path = os.path.join(reports_dir, name)
        if name.startswith("infra_audit_") and name.endswith(".md") and os.path.getmtime(path) < cutoff:
            os.remove(path)


def to_json(run):
    return json.dumps({
        "domain": run["domain"],
        "started_at": run["started_at"],
        "elapsed_seconds": round(run["elapsed"], 2),
        "sections": run["sections"],
        "counts": run["counts"],
        "first_run": run["first_run"],
        "previous_run": run["previous_time"],
        "drift": [ch.to_dict() for ch in run["drift"]],
        "results": [r.to_dict() for r in _sorted(run["results"], {FAIL, WARN, ERROR, INFO, PASS})],
        "report_path": run.get("report_path"),
    }, indent=2)


def write_markdown(run, reports_dir, keep_days=90):
    os.makedirs(reports_dir, exist_ok=True)
    prune_reports(reports_dir, keep_days)
    path = os.path.join(reports_dir, f"infra_audit_{run['file_stamp']}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(run))
    return path
