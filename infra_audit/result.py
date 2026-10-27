"""The one result type every check returns."""

from dataclasses import asdict, dataclass

PASS, WARN, FAIL, INFO, ERROR = "PASS", "WARN", "FAIL", "INFO", "ERROR"

# Report order: worst first. ERROR sits after WARN: the check didn't run, so
# it is never a pass, but it also isn't a confirmed problem.
REPORT_ORDER = {FAIL: 0, WARN: 1, ERROR: 2, INFO: 3, PASS: 4}

# Used by drift to decide whether a change is a regression. ERROR is
# deliberately absent: a failed check says nothing about the real state.
RANK = {PASS: 0, INFO: 0, WARN: 1, FAIL: 2}


@dataclass
class Result:
    check: str            # stable id, e.g. "spf.lookups" (drift keys on check+target)
    target: str           # domain, hostname, or mailbox
    status: str
    title: str            # one line: what was found
    detail: str = ""      # supporting facts
    why: str = ""         # why it matters (WARN/FAIL)
    fix: str = ""         # exact manual fix (WARN/FAIL)
    observed: str = None  # stable value for drift; None = don't diff values
    section: str = ""     # dns | reputation | mailboxes (set by the runner)

    @property
    def key(self):
        return f"{self.check}|{self.target}"

    def to_dict(self):
        return asdict(self)


def error(check, target, title, detail=""):
    return Result(
        check, target, ERROR, title, detail,
        why="The check itself failed, so this item is unverified (not a pass).",
        fix="Re-run infra_audit. If it keeps failing, look at the detail line.",
    )
