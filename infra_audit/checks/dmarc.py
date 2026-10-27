"""DMARC: policy, subdomain policy, pct, alignment, and reporting addresses."""

import re

from ..dnsutil import is_within, txt_starting
from ..result import FAIL, INFO, PASS, WARN, Result, error

POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}
EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")


def parse(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _record_with(tags, **changes):
    merged = {**tags, **changes}
    order = ["v", "p", "sp", "pct", "adkim", "aspf", "rua", "ruf", "fo"]
    keys = [k for k in order if k in merged] + [k for k in merged if k not in order]
    return "; ".join(f"{k}={merged[k]}" for k in keys)


def check_dmarc(ctx, target):
    domain = target["domain"]
    root = ctx.cfg.root
    expected = ctx.cfg["dmarc"].get("expected_policy", "reject").lower()
    host = f"_dmarc.{domain}"
    ans = ctx.dns.query(host, "TXT")
    if ans.failed:
        return [error("dmarc.record", domain, "Could not look up DMARC (DNS failure)", ans.error)]
    records = txt_starting(ans, "v=DMARC1")

    if not records and domain != root:
        root_ans = ctx.dns.query(f"_dmarc.{root}", "TXT")
        if root_ans.failed:
            return [error("dmarc.record", domain, "Could not look up the root DMARC record (DNS failure)", root_ans.error)]
        root_records = txt_starting(root_ans, "v=DMARC1")
        if len(root_records) == 1:
            rt = parse(root_records[0])
            inherited = rt.get("sp", rt.get("p", "none")).lower()
            if POLICY_RANK.get(inherited, -1) >= POLICY_RANK[expected]:
                return [Result("dmarc.record", domain, PASS, f"No own DMARC record; inherits sp/p={inherited} from {root}",
                               observed=f"inherit:{inherited}")]
            return [Result("dmarc.record", domain, FAIL, f"Inherits a weak DMARC policy ({inherited}) from {root}",
                           why="Spoofed mail from this subdomain won't be rejected.",
                           fix=f"In your DNS provider, edit the TXT record at _dmarc.{root} and set sp={expected} "
                               f"(or remove sp= so it inherits p={expected}).",
                           observed=f"inherit:{inherited}")]
        # Root has no usable record; the root's own check reports that.
        return [Result("dmarc.record", domain, FAIL, "No DMARC record here or on the root domain",
                       why="Without DMARC, anyone can spoof this domain and receivers have no policy to apply.",
                       fix=f"In your DNS provider, add a TXT record at _dmarc.{root}: v=DMARC1; p={expected}; rua=mailto:dmarc@{root}",
                       observed="(none)")]

    if not records:
        return [Result("dmarc.record", domain, FAIL, "No DMARC record",
                       why="Without DMARC, anyone can spoof your domain and Gmail/Yahoo bulk-sender rules are not met.",
                       fix=f"In your DNS provider, add a TXT record at {host}: v=DMARC1; p={expected}; rua=mailto:dmarc@{root}",
                       observed="(none)")]
    if len(records) > 1:
        return [Result("dmarc.record", domain, FAIL, f"{len(records)} DMARC records (must be exactly one)",
                       detail=" | ".join(records),
                       why="Multiple DMARC records means receivers ignore DMARC entirely.",
                       fix=f"In your DNS provider, delete all but one TXT record at {host}.",
                       observed=" | ".join(sorted(records)))]

    record = records[0]
    tags = parse(record)
    out = [Result("dmarc.record", domain, PASS, "One DMARC record", detail=record, observed=record)]

    p = tags.get("p", "").lower()
    if p not in POLICY_RANK:
        out.append(Result("dmarc.policy", domain, FAIL, f"DMARC policy is invalid or missing (p={p or '?'})",
                          why="An invalid p= makes receivers ignore the record.",
                          fix=f"In your DNS provider, edit the TXT record at {host} to: {_record_with(tags, p=expected)}",
                          observed=p or "(missing)"))
    elif POLICY_RANK[p] < POLICY_RANK[expected]:
        out.append(Result("dmarc.policy", domain, FAIL, f"DMARC policy is p={p}, expected p={expected}",
                          why="A weaker policy lets spoofed mail through and is a regression from your intended setup.",
                          fix=f"In your DNS provider, edit the TXT record at {host} to: {_record_with(tags, p=expected)}",
                          observed=p))
    else:
        out.append(Result("dmarc.policy", domain, PASS, f"DMARC policy p={p}", observed=p))

    if "sp" in tags:
        sp = tags["sp"].lower()
        if POLICY_RANK.get(sp, -1) < POLICY_RANK[expected]:
            out.append(Result("dmarc.sp", domain, WARN, f"Subdomain policy sp={sp} is weaker than p={p}",
                              why="Attackers can spoof any subdomain (e.g. billing.yourdomain) and it won't be rejected.",
                              fix=f"In your DNS provider, edit the TXT record at {host} to: {_record_with(tags, sp=expected)}",
                              observed=sp))
        else:
            out.append(Result("dmarc.sp", domain, PASS, f"Subdomain policy sp={sp}", observed=sp))
    else:
        out.append(Result("dmarc.sp", domain, INFO, f"No sp= tag: subdomains inherit p={p}", observed=f"inherit:{p}"))

    pct = tags.get("pct", "100")
    if pct != "100":
        out.append(Result("dmarc.pct", domain, WARN, f"DMARC pct={pct}: policy applies to only {pct}% of failing mail",
                          why="The rest of spoofed mail is treated as if you had a weaker policy.",
                          fix=f"In your DNS provider, edit the TXT record at {host} and remove pct= (defaults to 100).",
                          observed=pct))
    else:
        out.append(Result("dmarc.pct", domain, PASS, "DMARC applies to 100% of mail", observed="100"))

    adkim, aspf = tags.get("adkim", "r").lower(), tags.get("aspf", "r").lower()
    ses_active = any("amazonses.com" in (d.get("mx_expected_suffixes") or []) for d in ctx.cfg.active_domains)
    if aspf == "s" and ses_active:
        out.append(Result("dmarc.alignment", domain, WARN, "aspf=s (strict SPF alignment) with an SES MAIL FROM subdomain",
                          why="SES mail uses send.<domain> as MAIL FROM, which only aligns under relaxed SPF alignment; "
                              "DMARC then rests on DKIM alone.",
                          fix=f"In your DNS provider, edit the TXT record at {host} and set aspf=r (or remove aspf=).",
                          observed=f"adkim={adkim},aspf={aspf}"))
    else:
        out.append(Result("dmarc.alignment", domain, INFO,
                          f"Alignment: DKIM {'strict' if adkim == 's' else 'relaxed'}, SPF {'strict' if aspf == 's' else 'relaxed'}",
                          observed=f"adkim={adkim},aspf={aspf}"))

    out.extend(_check_report_uris(ctx, domain, host, tags, "rua", required=(domain == root)))
    out.extend(_check_report_uris(ctx, domain, host, tags, "ruf", required=False))
    return out


def _check_report_uris(ctx, domain, host, tags, tag, required):
    check = f"dmarc.{tag}"
    label = "aggregate (rua)" if tag == "rua" else "forensic (ruf)"
    value = tags.get(tag, "")
    if not value:
        if required:
            return [Result(check, domain, WARN, f"No DMARC {label} reporting address",
                           why="Without rua reports you can't see who is sending as your domain or spot auth failures.",
                           fix=f"In your DNS provider, edit the TXT record at {host} and add: rua=mailto:dmarc@{ctx.cfg.root}",
                           observed="(none)")]
        return [Result(check, domain, INFO, f"No DMARC {label} address (optional)", observed="(none)")]

    out, addresses = [], []
    for uri in [u.strip() for u in value.split(",") if u.strip()]:
        addr = uri.split("!", 1)[0]
        if not addr.lower().startswith("mailto:") or not EMAIL_RE.match(addr[7:]):
            out.append(Result(f"{check}.syntax", domain, WARN, f"Invalid DMARC {tag} URI: {uri}",
                              why="Receivers skip malformed report addresses, so you get no reports.",
                              fix=f"In your DNS provider, edit the TXT record at {host} so {tag}= is like mailto:dmarc@{ctx.cfg.root}",
                              observed=uri))
            continue
        addresses.append(addr[7:].lower())
    if addresses:
        out.append(Result(check, domain, PASS, f"DMARC {label} reports go to " + ", ".join(addresses),
                          observed=",".join(sorted(addresses))))

    for addr in addresses:
        rdomain = EMAIL_RE.match(addr).group(1).lower()
        if is_within(rdomain, ctx.cfg.root):
            continue
        auth_host = f"{domain}._report._dmarc.{rdomain}"
        ans = ctx.dns.query(auth_host, "TXT")
        cid = f"{check}.external"
        if ans.failed:
            out.append(error(cid, f"{domain}->{rdomain}", f"Could not verify {rdomain} accepts your DMARC reports", ans.error))
        elif txt_starting(ans, "v=DMARC1"):
            out.append(Result(cid, f"{domain}->{rdomain}", PASS, f"{rdomain} authorizes receiving your {tag} reports",
                              observed="authorized"))
        else:
            out.append(Result(cid, f"{domain}->{rdomain}", WARN,
                              f"External {tag} domain {rdomain} hasn't authorized your reports",
                              why="Receivers must drop reports to an external domain that lacks this record, so you get none.",
                              fix=f"Ask the {rdomain} report service to publish TXT {auth_host} = \"v=DMARC1\" "
                                  "(most DMARC vendors do this automatically when you add the domain in their dashboard).",
                              observed="missing"))
    return out
