"""Offline tests: a fake DNS zone drives the real check functions."""

import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from infra_audit import drift
from infra_audit.checks import accounts, dangling, dkim, dmarc, mx, reputation, spf
from infra_audit.config import load_config
from infra_audit.dnsutil import ERROR, NOANSWER, NXDOMAIN, OK, Answer
from infra_audit.history import History
from infra_audit.result import ERROR as S_ERROR, FAIL, INFO, PASS, WARN, Result
from infra_audit.runner import Context, run

ROOT = "blossomstreetventures.com"
CONFIG = os.path.join(os.path.dirname(__file__), "..", "config.json")


def dkim_txt(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


KEY_2048 = dkim_txt(2048)
KEY_1024 = dkim_txt(1024)


class FakeDns:
    """zone: {(name, rdtype): [records] | 'nx' | 'timeout'}; anything unlisted is NXDOMAIN."""

    def __init__(self, zone):
        self.zone = {(k[0].lower(), k[1]): v for k, v in zone.items()}

    def query(self, name, rdtype):
        name = name.lower().rstrip(".")
        v = self.zone.get((name, rdtype))
        if v == "timeout":
            return Answer(name, rdtype, ERROR, error="Timeout")
        if v is None or v == "nx":
            # name exists with other types -> NOANSWER, else NXDOMAIN
            exists = any(k[0] == name for k in self.zone)
            return Answer(name, rdtype, NOANSWER if exists else NXDOMAIN)
        return Answer(name, rdtype, OK, tuple(v))

    def resolves(self, name):
        a = self.query(name, "A")
        return True if a.ok else (None if a.failed else False)


def healthy_zone():
    return {
        ("google.com", "A"): ["142.250.0.1"],
        ("gmail.com", "MX"): [(5, "gmail-smtp-in.l.google.com")],
        (ROOT, "TXT"): ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"],
        ("_spf.google.com", "TXT"): ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"],
        ("_netblocks.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 ~all"],
        ("_netblocks2.google.com", "TXT"): ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
        ("_netblocks3.google.com", "TXT"): ["v=spf1 ip4:172.217.0.0/19 ~all"],
        ("send." + ROOT, "TXT"): ["v=spf1 include:amazonses.com ~all"],
        ("amazonses.com", "TXT"): ["v=spf1 ip4:199.255.192.0/22 ~all"],
        ("google._domainkey." + ROOT, "TXT"): [KEY_2048],
        ("_dmarc." + ROOT, "TXT"): [f"v=DMARC1; p=reject; rua=mailto:dmarc@{ROOT}"],
        (ROOT, "MX"): [(1, "smtp.google.com")],
        ("smtp.google.com", "A"): ["142.250.1.27"],
        ("send." + ROOT, "MX"): [(10, "feedback-smtp.us-east-1.amazonses.com")],
        ("feedback-smtp.us-east-1.amazonses.com", "A"): ["54.240.0.1"],
        ("k2._domainkey." + ROOT, "CNAME"): ["dkim2.mcsv.net"],
        ("dkim2.mcsv.net", "TXT"): ["v=DKIM1; p=abc"],
        ("k3._domainkey." + ROOT, "CNAME"): ["dkim3.mcsv.net"],
        ("dbltest.com.dbl.spamhaus.org", "A"): ["127.0.1.2"],
        ("test.surbl.org.multi.surbl.org", "A"): ["127.0.0.254"],
        ("test.uribl.com.black.uribl.com", "A"): ["127.0.0.2"],
    }


@pytest.fixture
def cfg():
    return load_config(CONFIG)


def make_ctx(cfg, zone, tmp_path, now=None):
    return Context(cfg=cfg, dns=FakeDns(zone), history=History(str(tmp_path / "h.db")), google=None,
                   now=now or datetime(2026, 10, 27, tzinfo=timezone.utc))


def by_check(results):
    return {r.check: r for r in results}


def root_target(cfg):
    return cfg["sending_domains"][0]


def ses_target(cfg):
    return cfg["sending_domains"][1]


# ------------------------------------------------------------------ SPF

def test_spf_healthy(cfg, tmp_path):
    ctx = make_ctx(cfg, healthy_zone(), tmp_path)
    r = by_check(spf.check_spf(ctx, root_target(cfg)))
    assert r["spf.record"].status == PASS
    assert r["spf.all"].status == PASS
    assert r["spf.includes"].status == PASS
    assert r["spf.lookups"].status == PASS and "4 of 10" in r["spf.lookups"].title
    assert r["spf.legacy"].status == PASS


def test_spf_domain_connect_managed_include(cfg, tmp_path):
    """SES via GoDaddy Domain Connect: include:dc-xxx._spfm.send.<domain> wraps amazonses.com."""
    zone = healthy_zone()
    managed = "dc-fd741b8612._spfm.send." + ROOT
    zone[("send." + ROOT, "TXT")] = [f"v=spf1 include:{managed} ~all"]
    zone[(managed, "TXT")] = ["v=spf1 include:amazonses.com ~all"]
    r = by_check(spf.check_spf(make_ctx(cfg, zone, tmp_path), ses_target(cfg)))
    assert r["spf.includes"].status == PASS
    assert r["spf.unknown"].status == PASS
    zone[(managed, "TXT")] = ["v=spf1 include:sketchy.example ~all"]
    zone[("sketchy.example", "TXT")] = ["v=spf1 ip4:1.2.3.4 -all"]
    r = by_check(spf.check_spf(make_ctx(cfg, zone, tmp_path), ses_target(cfg)))
    assert r["spf.includes"].status == FAIL
    assert r["spf.unknown"].status == WARN and "sketchy.example" in r["spf.unknown"].title


def test_spf_multiple_records_fail(cfg, tmp_path):
    zone = healthy_zone()
    zone[(ROOT, "TXT")] = ["v=spf1 include:_spf.google.com ~all", "v=spf1 include:servers.mcsv.net -all"]
    r = spf.check_spf(make_ctx(cfg, zone, tmp_path), root_target(cfg))
    assert r[0].status == FAIL and "2 SPF records" in r[0].title


def test_spf_plus_all_and_legacy_and_unknown(cfg, tmp_path):
    zone = healthy_zone()
    zone[(ROOT, "TXT")] = ["v=spf1 include:_spf.google.com include:servers.mcsv.net include:mystery.example ?all"]
    zone[("servers.mcsv.net", "TXT")] = ["v=spf1 ip4:205.201.128.0/20 -all"]
    zone[("mystery.example", "TXT")] = ["v=spf1 ip4:1.2.3.4 -all"]
    r = by_check(spf.check_spf(make_ctx(cfg, zone, tmp_path), root_target(cfg)))
    assert r["spf.all"].status == FAIL
    assert r["spf.legacy"].status == WARN and "servers.mcsv.net" in r["spf.legacy"].title
    assert "include:servers.mcsv.net" not in r["spf.legacy"].fix.split("to: ", 1)[1]
    assert r["spf.unknown"].status == WARN and "mystery.example" in r["spf.unknown"].title


def test_spf_lookup_limits(cfg, tmp_path):
    zone = healthy_zone()
    incs = [f"i{n}.example" for n in range(7)]
    zone[(ROOT, "TXT")] = ["v=spf1 include:_spf.google.com " + " ".join(f"include:{i}" for i in incs) + " ~all"]
    for i in incs:
        zone[(i, "TXT")] = ["v=spf1 a mx -all"]
    cfg_t = root_target(cfg)
    cfg_t = {**cfg_t, "spf_known_includes": incs}
    r = by_check(spf.check_spf(make_ctx(cfg, zone, tmp_path), cfg_t))
    assert r["spf.lookups"].status == FAIL  # 4 (google) + 7*3 = 25


def test_spf_stale_include_and_dns_error(cfg, tmp_path):
    zone = healthy_zone()
    zone[(ROOT, "TXT")] = ["v=spf1 include:_spf.google.com include:gone.example include:slow.example ~all"]
    zone[("slow.example", "TXT")] = "timeout"
    r = by_check(spf.check_spf(make_ctx(cfg, zone, tmp_path), root_target(cfg)))
    assert r["spf.stale"].status == FAIL and "gone.example" in r["spf.stale"].title
    assert r["spf.lookups"].status == S_ERROR  # incomplete count is never a PASS


def test_spf_dns_timeout_is_error(cfg, tmp_path):
    zone = healthy_zone()
    zone[(ROOT, "TXT")] = "timeout"
    r = spf.check_spf(make_ctx(cfg, zone, tmp_path), root_target(cfg))
    assert [x.status for x in r] == [S_ERROR]


# ----------------------------------------------------------------- DKIM

def test_dkim_valid_and_ses_unconfigured(cfg, tmp_path):
    r = by_check(dkim.check_dkim(make_ctx(cfg, healthy_zone(), tmp_path), root_target(cfg)))
    assert r["dkim.google"].status == PASS and "2048-bit" in r["dkim.google"].title
    assert r["dkim.amazon_ses"].status == WARN
    assert r["dkim.google.age"].status == INFO


def test_dkim_weak_missing_revoked(cfg, tmp_path):
    zone = healthy_zone()
    zone[("google._domainkey." + ROOT, "TXT")] = [KEY_1024]
    t = {**root_target(cfg), "dkim_selectors": {"google": "Google Workspace", "tok1": "Amazon SES", "old": "X"},
         "dkim_expected_providers": []}
    zone[("old._domainkey." + ROOT, "TXT")] = ["v=DKIM1; p="]
    r = by_check(dkim.check_dkim(make_ctx(cfg, zone, tmp_path), t))
    assert r["dkim.google"].status == WARN and "1024" in r["dkim.google"].title
    assert r["dkim.tok1"].status == FAIL and "missing" in r["dkim.tok1"].title
    assert r["dkim.old"].status == FAIL and "revoked" in r["dkim.old"].title


# ---------------------------------------------------------------- DMARC

def test_dmarc_regression_from_reject(cfg, tmp_path):
    zone = healthy_zone()
    zone[("_dmarc." + ROOT, "TXT")] = ["v=DMARC1; p=quarantine; sp=none; pct=50; rua=mailto:x@vendor.example"]
    r = by_check(dmarc.check_dmarc(make_ctx(cfg, zone, tmp_path), root_target(cfg)))
    assert r["dmarc.policy"].status == FAIL and "p=reject" in r["dmarc.policy"].fix
    assert r["dmarc.sp"].status == WARN
    assert r["dmarc.pct"].status == WARN
    assert r["dmarc.rua.external"].status == WARN  # vendor.example lacks the _report._dmarc record


def test_dmarc_external_rua_authorized(cfg, tmp_path):
    zone = healthy_zone()
    zone[("_dmarc." + ROOT, "TXT")] = ["v=DMARC1; p=reject; rua=mailto:x@vendor.example"]
    zone[(f"{ROOT}._report._dmarc.vendor.example", "TXT")] = ["v=DMARC1"]
    r = by_check(dmarc.check_dmarc(make_ctx(cfg, zone, tmp_path), root_target(cfg)))
    assert r["dmarc.rua.external"].status == PASS


def test_dmarc_subdomain_inherits_quarantine_is_warn(cfg, tmp_path):
    zone = healthy_zone()
    zone[("_dmarc." + ROOT, "TXT")] = [f"v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@{ROOT}"]
    r = dmarc.check_dmarc(make_ctx(cfg, zone, tmp_path), ses_target(cfg))
    assert r[0].status == WARN and "quarantine" in r[0].title


def test_dmarc_external_rua_deduped(cfg, tmp_path):
    zone = healthy_zone()
    zone[("_dmarc." + ROOT, "TXT")] = ["v=DMARC1; p=reject; rua=mailto:a@ar.vendor.example, mailto:b@ar.vendor.example"]
    zone[(f"{ROOT}._report._dmarc.ar.vendor.example", "TXT")] = ["v=DMARC1"]
    r = [x for x in dmarc.check_dmarc(make_ctx(cfg, zone, tmp_path), root_target(cfg)) if x.check == "dmarc.rua.external"]
    assert len(r) == 1


def test_dmarc_subdomain_inherits(cfg, tmp_path):
    r = dmarc.check_dmarc(make_ctx(cfg, healthy_zone(), tmp_path), ses_target(cfg))
    assert r[0].status == PASS and "inherits" in r[0].title


# ------------------------------------------------------------------- MX

def test_mx_healthy_and_unexpected(cfg, tmp_path):
    r = by_check(mx.check_mx(make_ctx(cfg, healthy_zone(), tmp_path), root_target(cfg)))
    assert r["mx.records"].status == PASS and r["mx.priority"].status == PASS
    zone = healthy_zone()
    zone[(ROOT, "MX")] = [(1, "smtp.google.com"), (5, "mx.evil.example")]
    zone[("mx.evil.example", "A")] = ["6.6.6.6"]
    r = by_check(mx.check_mx(make_ctx(cfg, zone, tmp_path), root_target(cfg)))
    assert r["mx.records"].status == FAIL and "mx.evil.example" in r["mx.records"].title


def test_ses_mx_missing(cfg, tmp_path):
    zone = healthy_zone()
    del zone[("send." + ROOT, "MX")]
    r = mx.check_mx(make_ctx(cfg, zone, tmp_path), ses_target(cfg))
    assert r[0].status == FAIL and "amazonses" in r[0].fix


# ------------------------------------------------------------ dangling

def test_dangling_cname(cfg, tmp_path):
    r = {x.target: x for x in dangling.check_dangling_cnames(make_ctx(cfg, healthy_zone(), tmp_path))}
    assert r["k2._domainkey." + ROOT].status == INFO   # legacy but still resolves
    assert r["k3._domainkey." + ROOT].status == FAIL   # dkim3.mcsv.net doesn't exist in the fake zone


# ---------------------------------------------------------- reputation

def test_reputation_clean_listed_blocked_and_timeout(cfg, tmp_path):
    zone = healthy_zone()
    zone[(f"{ROOT}.black.uribl.com", "A")] = ["127.0.0.2"]
    zone[(f"{ROOT}.multi.surbl.org", "A")] = ["127.0.0.1"]          # SURBL "query refused" code
    zone[(f"{ROOT}.uribl.spameatingmonkey.net", "A")] = "timeout"
    r = {x.check: x for x in reputation.check_blocklists(make_ctx(cfg, zone, tmp_path), root_target(cfg))}
    assert r["reputation.dbl.spamhaus.org"].status == PASS
    assert r["reputation.black.uribl.com"].status == FAIL
    assert r["reputation.multi.surbl.org"].status == S_ERROR
    assert r["reputation.uribl.spameatingmonkey.net"].status == S_ERROR


def test_reputation_dead_list_is_not_clean(cfg, tmp_path):
    zone = healthy_zone()
    del zone[("dbltest.com.dbl.spamhaus.org", "A")]   # test entry not answered -> can't trust "clean"
    r = {x.check: x for x in reputation.check_blocklists(make_ctx(cfg, zone, tmp_path), root_target(cfg))}
    assert r["reputation.dbl.spamhaus.org"].status == S_ERROR


# -------------------------------------------------------------- runner

def test_broken_resolver_skips_dns_sections(cfg, tmp_path):
    ctx = make_ctx(cfg, {}, tmp_path)  # everything NXDOMAIN, like a broken resolver
    results, _ = run(ctx, ["dns", "reputation"])
    assert results and all(r.status == S_ERROR and r.check == "dns.resolver" for r in results)


def test_crashing_check_is_error(cfg, tmp_path):
    def boom(ctx, target):
        raise RuntimeError("bad")
    results, _ = run(make_ctx(cfg, healthy_zone(), tmp_path), ["dns"], checks=[("dns", "domain", boom)])
    assert {r.status for r in results} == {S_ERROR}


# ---------------------------------------------------------------- drift

def test_drift_regression_and_change(tmp_path):
    h = History(str(tmp_path / "h.db"))
    run1 = [Result("dmarc.policy", ROOT, PASS, "p=reject", observed="reject", section="dns"),
            Result("spf.record", ROOT, PASS, "One SPF", observed="v=spf1 a ~all", section="dns"),
            Result("gmail.filters", "s@x", WARN, "1 filter", observed="f1", section="mailboxes")]
    h.save("2026-10-20T00:00:00+00:00", ["dns", "mailboxes"], run1, {})
    prev, when = h.previous(["dns", "mailboxes"])
    run2 = [Result("dmarc.policy", ROOT, FAIL, "p=none", observed="none", section="dns"),
            Result("spf.record", ROOT, PASS, "One SPF", observed="v=spf1 mx ~all", section="dns"),
            Result("gmail.autoforward", "s@x", FAIL, "fwd on", observed="on", section="mailboxes")]
    changes = drift.compute(prev, run2)
    kinds = {(c.check, c.kind) for c in changes}
    assert ("dmarc.policy", drift.REGRESSION) in kinds
    assert ("spf.record", drift.CHANGED) in kinds
    assert ("gmail.autoforward", drift.REGRESSION) in kinds        # new problem
    assert ("gmail.filters", drift.IMPROVED) in kinds              # warning went away
    assert changes[0].kind == drift.REGRESSION
    assert when.startswith("2026-10-20")


def test_drift_error_is_not_regression(tmp_path):
    prev = {"spf.record|d": {"check": "spf.record", "target": "d", "status": PASS, "title": "", "observed": "x", "section": "dns"}}
    changes = drift.compute(prev, [Result("spf.record", "d", S_ERROR, "dns failed")])
    assert [c.kind for c in changes] == [drift.CHECK_FAILED]


def test_only_section_compares_with_latest_run_of_that_section(tmp_path):
    h = History(str(tmp_path / "h.db"))
    h.save("2026-10-01T00:00:00+00:00", ["dns", "reputation"], [Result("a.b", "d", PASS, "", observed="1", section="dns")], {})
    h.save("2026-10-02T00:00:00+00:00", ["mailboxes"], [Result("m.x", "s", PASS, "", observed="1", section="mailboxes")], {})
    prev, _ = h.previous(["dns"])
    assert list(prev) == ["a.b|d"]


# ------------------------------------------------------- mailbox helpers

def test_find_spikes():
    counts = [5, 6, 4, 5, 30, 5]
    assert [i for i, _ in accounts.find_spikes(counts, 2.0, 10)] == [4]
    assert accounts.find_spikes([0, 0, 0, 3], 2.0, 10) == []  # below minimum count


def test_hard_bounces_from_hardbouncecheck_db(cfg, tmp_path):
    import sqlite3

    db = tmp_path / "bounces.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE bounces (email TEXT PRIMARY KEY, bounce_type TEXT, first_seen TEXT, last_seen TEXT, "
                 "bounce_count INTEGER, sending_mailboxes TEXT, active_contact INTEGER)")
    now = datetime(2026, 10, 27, tzinfo=timezone.utc)
    recent = (now - timedelta(days=2)).isoformat()
    old = (now - timedelta(days=30)).isoformat()
    rows = [(f"a{i}@x.com", "HARD", recent, recent, 1, f"sammy@{ROOT},s@{ROOT}", 0) for i in range(6)]
    rows += [("old@x.com", "HARD", old, old, 1, f"s@{ROOT}", 0), ("soft@x.com", "SOFT", recent, recent, 1, f"s@{ROOT}", 0)]
    conn.executemany("INSERT INTO bounces VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    cfg["bounce_db"] = str(db)
    (tmp_path / "state.json").write_text(json.dumps({"mailboxes": {
        f"sammy@{ROOT}": {"last_checked": (now - timedelta(days=1)).isoformat()},
        f"s@{ROOT}": {"last_checked": (now - timedelta(days=90)).isoformat()}}}))
    sent = {f"sammy@{ROOT}": 400, f"s@{ROOT}": 900, f"partner@{ROOT}": 800}  # founder/cofounder: Gmail unreadable
    accounts_sent = accounts._sent_last_7_days
    accounts._sent_last_7_days = lambda ctx: sent
    try:
        results = accounts.check_hard_bounces(make_ctx(cfg, {}, tmp_path, now))
    finally:
        accounts._sent_last_7_days = accounts_sent
    r = {x.target: x for x in results if x.check == "bounces.hard_7d"}
    fresh = {x.target: x for x in results if x.check == "bounces.fresh"}
    assert r[f"sammy@{ROOT}"].status == WARN and "1.5%" in r[f"sammy@{ROOT}"].title   # 6 / 400
    assert r[f"s@{ROOT}"].status == PASS and "0.7%" in r[f"s@{ROOT}"].title            # 6 / 900
    assert r[f"partner@{ROOT}"].status == PASS and "0.0%" in r[f"partner@{ROOT}"].title
    assert r[f"founder@{ROOT}"].status == INFO and "unavailable" in r[f"founder@{ROOT}"].detail
    assert fresh[f"sammy@{ROOT}"].status == PASS
    assert fresh[f"s@{ROOT}"].status == WARN and "90 days" in fresh[f"s@{ROOT}"].title
    assert fresh[f"partner@{ROOT}"].status == WARN and "never" in fresh[f"partner@{ROOT}"].title


def test_hard_bounces_missing_db_is_silent(cfg, tmp_path):
    cfg["bounce_db"] = str(tmp_path / "nope.db")
    assert accounts.check_hard_bounces(make_ctx(cfg, {}, tmp_path)) == []


def test_directory_skipped_without_approval(cfg, tmp_path):
    r = accounts.check_directory(make_ctx(cfg, {}, tmp_path))
    assert len(r) == 1 and r[0].status == INFO and "skipped" in r[0].title


def test_config_is_valid_json():
    with open(CONFIG) as f:
        json.load(f)


# ------------------------------------------------------- gmail settings

class FakeGoogle:
    """Stands in for google_api.Google: svc.users().settings().<x>() chains return canned data."""

    def __init__(self, data):
        self.data = data

    def gmail(self, mailbox):
        from unittest.mock import MagicMock

        svc = MagicMock()
        s = svc.users.return_value.settings.return_value
        s.getAutoForwarding.return_value.execute.return_value = self.data.get("autoforward", {"enabled": False})
        s.filters.return_value.list.return_value.execute.return_value = self.data.get("filters", {})
        s.sendAs.return_value.list.return_value.execute.return_value = self.data.get("sendas", {})
        s.getVacation.return_value.execute.return_value = self.data.get("vacation", {})
        return svc


def gctx(cfg, tmp_path, data):
    ctx = make_ctx(cfg, {}, tmp_path)
    ctx.google = FakeGoogle(data)
    return ctx


def test_gmail_forwarding_filters_aliases_vacation(cfg, tmp_path):
    from infra_audit.checks import gmail_settings as g

    box = f"s@{ROOT}"
    ctx = gctx(cfg, tmp_path, {
        "autoforward": {"enabled": True, "emailAddress": "x@evil.example", "disposition": "archive"},
        "filters": {"filter": [
            {"criteria": {"from": "bank.com"}, "action": {"addLabelIds": ["TRASH"]}},
            {"criteria": {"query": "invoice"}, "action": {"forward": "x@evil.example"}},
            {"criteria": {"from": "news.com"}, "action": {"addLabelIds": ["Label_1"]}},
        ]},
        "sendas": {"sendAs": [{"sendAsEmail": box, "isPrimary": True}, {"sendAsEmail": "me@gmail.com"}]},
        "vacation": {"enableAutoReply": True, "responseSubject": "Away"},
    })
    assert g.check_auto_forwarding(ctx, box)[0].status == FAIL
    f = g.check_filters(ctx, box)[0]
    assert f.status == FAIL and "auto-deletes" in f.detail and "forwards to x@evil.example" in f.detail
    assert "news.com" not in f.detail
    assert g.check_send_as(ctx, box)[0].status == WARN
    assert g.check_vacation(ctx, box)[0].status == WARN


def test_gmail_api_error_is_error(cfg, tmp_path):
    from infra_audit.checks import gmail_settings as g

    class Boom:
        def gmail(self, mailbox):
            raise RuntimeError("unauthorized_client: Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested.")

    ctx = make_ctx(cfg, {}, tmp_path)
    ctx.google = Boom()
    r = g.check_delegates(ctx, f"s@{ROOT}")[0]
    assert r.status == S_ERROR and "gmail.readonly" in r.title
