"""Nice-to-have records: MTA-STS, TLS-RPT, BIMI, CAA, DNSSEC. Mostly INFO."""

import fnmatch

import requests

from ..dnsutil import txt_starting
from ..result import FAIL, INFO, PASS, WARN, Result, error

MTA_STS_NOTE = ("MTA-STS tells other mail servers to require encrypted (TLS) delivery to your MX, blocking "
                "downgrade/interception attacks on inbound mail.")
TLS_RPT_NOTE = "TLS-RPT asks other mail servers to email you daily reports of TLS failures delivering to you."


def parse_policy(text):
    policy = {"mx": []}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "mx":
                policy["mx"].append(v.lower())
            else:
                policy[k] = v
    return policy


def check_mta_sts(ctx):
    domain = ctx.cfg.root
    ans = ctx.dns.query(f"_mta-sts.{domain}", "TXT")
    if ans.failed:
        return [error("mta_sts", domain, "Could not look up MTA-STS (DNS failure)", ans.error)]
    records = txt_starting(ans, "v=STSv1")
    if not records:
        return [Result("mta_sts", domain, INFO, "MTA-STS not set up (optional)",
                       detail=MTA_STS_NOTE + " Setup: host a policy file at https://mta-sts." + domain +
                       "/.well-known/mta-sts.txt and add TXT _mta-sts." + domain + " = v=STSv1; id=<date>.",
                       observed="(none)")]
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = requests.get(url, timeout=ctx.cfg.net["http_timeout"], allow_redirects=False)
    except requests.RequestException as e:
        return [Result("mta_sts", domain, FAIL, "MTA-STS TXT record exists but the policy file can't be fetched",
                       detail=f"{url}: {type(e).__name__}",
                       why="Senders that honour MTA-STS may fail or delay delivery to you when the policy is unreachable.",
                       fix=f"Fix hosting/HTTPS for mta-sts.{domain}, or delete the TXT record at _mta-sts.{domain}.",
                       observed="unreachable")]
    if resp.status_code != 200:
        return [Result("mta_sts", domain, FAIL, f"MTA-STS policy file returns HTTP {resp.status_code}",
                       why="Senders treat this as a broken policy.",
                       fix=f"Publish the policy at {url}, or delete the TXT record at _mta-sts.{domain}.",
                       observed=f"http {resp.status_code}")]
    policy = parse_policy(resp.text)
    mode = policy.get("mode", "?").lower()
    mx = ctx.dns.query(domain, "MX")
    uncovered = [h for _, h in mx.records if not any(fnmatch.fnmatch(h, p) for p in policy["mx"])] if mx.ok else []
    observed = f"mode={mode}; mx={','.join(policy['mx'])}"
    if uncovered and mode == "enforce":
        return [Result("mta_sts", domain, FAIL, "MTA-STS (enforce) doesn't cover MX host(s): " + ", ".join(uncovered),
                       why="Senders that honour MTA-STS will refuse to deliver to those hosts.",
                       fix=f"Edit {url} so its mx: lines cover your MX hosts (e.g. 'mx: *.google.com' or 'mx: smtp.google.com'), "
                           f"then change the id= in TXT _mta-sts.{domain}.",
                       observed=observed)]
    if mode == "enforce":
        return [Result("mta_sts", domain, PASS, "MTA-STS enforced", detail=observed, observed=observed)]
    return [Result("mta_sts", domain, INFO, f"MTA-STS in {mode} mode", detail=observed, observed=observed)]


def check_tls_rpt(ctx):
    domain = ctx.cfg.root
    ans = ctx.dns.query(f"_smtp._tls.{domain}", "TXT")
    if ans.failed:
        return [error("tls_rpt", domain, "Could not look up TLS-RPT (DNS failure)", ans.error)]
    records = txt_starting(ans, "v=TLSRPTv1")
    if not records:
        return [Result("tls_rpt", domain, INFO, "TLS-RPT not set up (optional)",
                       detail=TLS_RPT_NOTE + f" Setup: TXT _smtp._tls.{domain} = v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
                       observed="(none)")]
    return [Result("tls_rpt", domain, PASS, "TLS-RPT configured", detail=records[0], observed=records[0])]


def check_bimi(ctx):
    domain = ctx.cfg.root
    ans = ctx.dns.query(f"default._bimi.{domain}", "TXT")
    if ans.failed:
        return [error("bimi", domain, "Could not look up BIMI (DNS failure)", ans.error)]
    records = txt_starting(ans, "v=BIMI1")
    if not records:
        return [Result("bimi", domain, INFO, "BIMI not set up (optional)",
                       detail="BIMI shows your logo next to mail in some inboxes. Gmail requires DMARC enforcement "
                              "plus a paid VMC/CMC certificate.",
                       observed="(none)")]
    return [Result("bimi", domain, INFO, "BIMI record present", detail=records[0], observed=records[0])]


def check_caa(ctx):
    domain = ctx.cfg.root
    ans = ctx.dns.query(domain, "CAA")
    if ans.failed:
        return [error("caa", domain, "Could not look up CAA (DNS failure)", ans.error)]
    if not ans.ok:
        return [Result("caa", domain, INFO, "No CAA records (any certificate authority may issue for you)",
                       detail="Optional hardening: CAA limits which CAs can issue TLS certs for your domain.",
                       observed="(none)")]
    observed = "; ".join(sorted(ans.records))
    return [Result("caa", domain, INFO, "CAA records present", detail=observed, observed=observed)]


def check_dnssec(ctx):
    domain = ctx.cfg.root
    ds = ctx.dns.query(domain, "DS")
    if ds.failed:
        return [error("dnssec", domain, "Could not look up DNSSEC DS record (DNS failure)", ds.error)]
    if not ds.ok:
        return [Result("dnssec", domain, INFO, "DNSSEC not enabled",
                       detail="Optional: DNSSEC signs your DNS so records can't be forged in transit. "
                              "Enable it at your DNS host, then add the DS record at your registrar.",
                       observed="unsigned")]
    key = ctx.dns.query(domain, "DNSKEY")
    if key.failed:
        return [error("dnssec", domain, "Could not look up DNSKEY (DNS failure)", key.error)]
    if not key.ok:
        return [Result("dnssec", domain, FAIL, "DS record at registrar but zone has no DNSKEY (broken DNSSEC)",
                       why="Validating resolvers will treat your whole domain as unresolvable: mail and web break.",
                       fix="At your registrar, remove the DS record, or re-enable DNSSEC signing at your DNS host.",
                       observed="broken")]
    return [Result("dnssec", domain, INFO, "DNSSEC enabled (DS + DNSKEY present)", observed="signed")]
