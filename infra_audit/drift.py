"""Compare this run against the previous one."""

from dataclasses import asdict, dataclass

from .result import ERROR, FAIL, RANK, WARN

REGRESSION, CHANGED, CHECK_FAILED, IMPROVED, REMOVED = (
    "REGRESSION", "CHANGED", "CHECK FAILED", "IMPROVED", "NO LONGER CHECKED")
ORDER = {REGRESSION: 0, CHANGED: 1, CHECK_FAILED: 2, IMPROVED: 3, REMOVED: 4}


@dataclass
class Change:
    kind: str
    check: str
    target: str
    title: str
    before_status: str = ""
    after_status: str = ""
    before: str = None
    after: str = None

    def to_dict(self):
        return asdict(self)


def compute(previous, results):
    """List of Changes, regressions first. Empty on a first run (previous == {})."""
    if not previous:
        return []
    changes = []
    current_keys = set()
    for r in results:
        current_keys.add(r.key)
        p = previous.get(r.key)
        if p is None:
            # A key we've never seen before only matters if it's a problem
            # (e.g. a newly stale SPF include, a new unknown send-as alias).
            if r.status in (WARN, FAIL):
                changes.append(Change(REGRESSION, r.check, r.target, r.title, "(new)", r.status, None, r.observed))
            continue
        before, after = p["status"], r.status
        value_changed = (p["observed"] is not None and r.observed is not None and p["observed"] != r.observed)
        if after == ERROR and before != ERROR:
            changes.append(Change(CHECK_FAILED, r.check, r.target, r.title, before, after))
        elif before != ERROR and after != ERROR and RANK[after] > RANK[before]:
            changes.append(Change(REGRESSION, r.check, r.target, r.title, before, after, p["observed"], r.observed))
        elif value_changed:
            changes.append(Change(CHANGED, r.check, r.target, r.title, before, after, p["observed"], r.observed))
        elif before != ERROR and after != ERROR and RANK[after] < RANK[before]:
            changes.append(Change(IMPROVED, r.check, r.target, r.title, before, after))

    # Keys that vanished. `previous` only holds sections that ran this time.
    # Skip families that ERRORed this run: their sub-results simply weren't
    # produced, which says nothing about the real state.
    errored = {(r.check.split(".")[0], r.target) for r in results if r.status == ERROR}
    for key, p in previous.items():
        if key in current_keys or (p["check"].split(".")[0], p["target"]) in errored:
            continue
        if p["status"] in (WARN, FAIL):
            changes.append(Change(IMPROVED, p["check"], p["target"], p["title"] + " (no longer reported)",
                                  p["status"], ""))
        elif p["observed"] is not None:
            changes.append(Change(REMOVED, p["check"], p["target"], p["title"], p["status"], "", p["observed"], None))

    changes.sort(key=lambda c: (ORDER[c.kind], c.check, c.target))
    return _collapse_changed(changes)


def _collapse_changed(changes):
    """One DNS edit changes several derived values (SPF record, include list,
    lookup count...). Keep one CHANGED line per check family and target,
    preferring the raw '<family>.record' value. Regressions are all kept."""
    best = {}
    for c in changes:
        if c.kind != CHANGED:
            continue
        fam = (c.check.split(".")[0], c.target)
        if fam not in best or c.check.endswith(".record"):
            best[fam] = c
    keep = set(map(id, best.values()))
    return [c for c in changes if c.kind != CHANGED or id(c) in keep]
