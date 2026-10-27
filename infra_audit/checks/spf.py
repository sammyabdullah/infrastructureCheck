"""SPF: one record, required includes present, sane `all`, <= 10 DNS lookups."""

from ..dnsutil import txt_starting
from ..result import ERROR, FAIL, INFO, PASS, WARN, Result, error

LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
WHY_SPF = "Receivers use SPF to decide whether a server may send as your domain; a broken SPF hurts inbox placement."


def split_terms(record):
    """['include:_spf.google.com', '~all', ...] without the v=spf1 prefix."""
    return [t for t in record.split()[1:] if t]


def _mech(term):
    """(qualifier, name, value) for an SPF term; modifiers come back with qualifier ''."""
    if "=" in term and ":" not in term.split("=", 1)[0]:
        name, value = term.split("=", 1)
        return "", name.lower(), value
    q = term[0] if term[0] in "+-~?" else "+"
    body = term[1:] if term[0] in "+-~?" else term
    name, _, value = body.partition(":")
    name = name.split("/", 1)[0]
    return q, name.lower(), value


def count_lookups(dns, record, seen=None, depth=0):
    """Recursively count SPF DNS lookups.

    Returns (count, stale, errors, per_include) where `stale` lists include/
    redirect targets with no SPF record (a permerror), `errors` lists targets
    whose lookup failed (so the count is incomplete), and `per_include` maps
    each top-level include to the lookups it costs (itself + nested).
    """
    seen = set() if seen is None else seen
    count, stale, errors, per_include = 0, [], [], {}
    for term in split_terms(record):
        q, name, value = _mech(term)
        if name in ("include", "redirect"):
            target = value.lower().rstrip(".")
            cost = 1
            if target and target not in seen and depth < 10:
                seen.add(target)
                ans = dns.query(target, "TXT")
                if ans.failed:
                    errors.append(target)
                else:
                    records = txt_starting(ans, "v=spf1")
                    if not records:
                        stale.append(target)
                    else:
                        sub_count, sub_stale, sub_err, _ = count_lookups(dns, records[0], seen, depth + 1)
                        cost += sub_count
                        stale += sub_stale
                        errors += sub_err
            count += cost
            per_include[f"{name}:{target}"] = cost
        elif name in LOOKUP_MECHANISMS:
            count += 1
    return count, stale, errors, per_include


def check_spf(ctx, target):
    domain = target["domain"]
    t = ctx.cfg.thresholds
    out = []
    ans = ctx.dns.query(domain, "TXT")
    if ans.failed:
        return [error("spf.record", domain, "Could not look up SPF (DNS failure)", ans.error)]

    required = [i.lower() for i in target["spf_required_includes"]]
    suggested = "v=spf1 " + " ".join(f"include:{i}" for i in required + target["spf_known_includes"]) + " ~all"
    records = txt_starting(ans, "v=spf1")
    if not records:
        return [Result("spf.record", domain, FAIL, "No SPF record",
                       why=WHY_SPF + " With none, many receivers treat your mail as unauthenticated.",
                       fix=f"In your DNS provider, add a TXT record at {domain} with value: {suggested}",
                       observed="(none)")]
    if len(records) > 1:
        return [Result("spf.record", domain, FAIL, f"{len(records)} SPF records (must be exactly one)",
                       detail=" | ".join(records),
                       why="Multiple SPF records is a permanent error: receivers treat SPF as failed for ALL your mail.",
                       fix=f"In your DNS provider, merge the TXT records at {domain} that start with v=spf1 "
                           f"into a single record (keep every include once, one ~all at the end) and delete the rest.",
                       observed=" | ".join(sorted(records)))]
    record = records[0]
    out.append(Result("spf.record", domain, PASS, "One SPF record", detail=record, observed=record))

    terms = [_mech(term) for term in split_terms(record)]

    # The `all` mechanism.
    all_terms = [(q, n) for q, n, _ in terms if n == "all"]
    has_redirect = any(n == "redirect" for _, n, _ in terms)
    if all_terms and all_terms[-1][0] in "+?":
        q = all_terms[-1][0]
        shown = "+all" if q == "+" else "?all"
        out.append(Result("spf.all", domain, FAIL, f"SPF ends in {shown}",
                          why=("+all lets ANY server on the internet pass SPF as you." if q == "+"
                               else "?all is 'neutral': it gives receivers no protection against spoofing."),
                          fix=f"In your DNS provider, edit the TXT record at {domain}: replace '{shown}' with '~all'.",
                          observed=shown))
    elif all_terms:
        shown = all_terms[-1][0] + "all"
        out.append(Result("spf.all", domain, PASS, f"SPF ends in {shown}", observed=shown))
    elif has_redirect:
        out.append(Result("spf.all", domain, INFO, "SPF uses redirect= (policy comes from the redirect target)",
                          observed="redirect"))
    else:
        out.append(Result("spf.all", domain, WARN, "SPF has no ~all or -all",
                          why="Without an all mechanism, unlisted senders get a 'neutral' result instead of a soft/hard fail.",
                          fix=f"In your DNS provider, edit the TXT record at {domain} and add ' ~all' at the end.",
                          observed="(none)"))

    # Required / legacy / unrecognized includes.
    includes = [v.lower().rstrip(".") for _, n, v in terms if n == "include"]
    missing = [i for i in required if i not in includes]
    if missing:
        out.append(Result("spf.includes", domain, FAIL, "SPF is missing: " + ", ".join(missing),
                          why="Mail from that service will fail SPF and lean entirely on DKIM.",
                          fix=f"In your DNS provider, edit the TXT record at {domain} and add "
                              + " ".join(f"include:{m}" for m in missing) + " before the ~all.",
                          observed=",".join(sorted(includes))))
    else:
        out.append(Result("spf.includes", domain, PASS, "SPF includes every required sender",
                          detail=", ".join(includes) or "(no includes)", observed=",".join(sorted(includes))))

    count, stale, errors, per_include = count_lookups(ctx.dns, record, seen={domain})

    legacy = [i for i in includes if i in [x.lower() for x in target["spf_legacy_includes"]]]
    if legacy:
        freed = sum(per_include.get(f"include:{i}", 1) for i in legacy)
        kept = " ".join(t for t in record.split() if t.lower().lstrip("+") not in {f"include:{i}" for i in legacy})
        out.append(Result("spf.legacy", domain, WARN, "Legacy include still in SPF: " + ", ".join(legacy),
                          detail=f"You are not actively sending through it. Removing it frees {freed} of your 10 DNS lookups.",
                          why="Unused includes waste the 10-lookup budget and authorize servers you don't use to send as you.",
                          fix=f"In your DNS provider, edit the TXT record at {domain} to: {kept}",
                          observed=",".join(legacy)))
    elif target["spf_legacy_includes"]:
        out.append(Result("spf.legacy", domain, PASS, "No legacy includes in SPF", observed="(none)"))

    known = set(required) | {i.lower() for i in target["spf_known_includes"]} | {i.lower() for i in target["spf_legacy_includes"]}
    unknown = [i for i in includes if i not in known]
    if unknown:
        out.append(Result("spf.unknown", domain, WARN, "Unrecognized SPF include(s): " + ", ".join(unknown),
                          why="Each include authorizes a third party to send as your domain. Stale ones are a spoofing path.",
                          fix="If you still send through it, add it to spf_known_includes in config.json. If not, "
                              f"in your DNS provider remove 'include:{unknown[0]}' from the TXT record at {domain}.",
                          observed=",".join(sorted(unknown))))
    else:
        out.append(Result("spf.unknown", domain, PASS, "No unrecognized SPF includes", observed="(none)"))
    if any(n == "ptr" for _, n, _ in terms):
        out.append(Result("spf.ptr", domain, WARN, "SPF uses the deprecated ptr mechanism",
                          why="ptr is slow, unreliable and ignored by some receivers (RFC 7208 says do not use it).",
                          fix=f"In your DNS provider, remove 'ptr' from the TXT record at {domain}.",
                          observed="ptr"))

    if stale:
        out.append(Result("spf.stale", domain, FAIL, "SPF include points at a domain with no SPF: " + ", ".join(stale),
                          why="An include with no SPF record is a permanent error: receivers can fail SPF for all your mail.",
                          fix=f"In your DNS provider, remove 'include:{stale[0]}' from the TXT record at {domain}"
                              " (or fix the include name if it is a typo).",
                          observed=",".join(sorted(stale))))
    else:
        out.append(Result("spf.stale", domain, PASS, "Every SPF include resolves to an SPF record", observed="(none)"))

    breakdown = ", ".join(f"{k} = {v}" for k, v in per_include.items())
    if errors:
        out.append(Result("spf.lookups", domain, ERROR, f"SPF lookup count incomplete (at least {count})",
                          detail="DNS failed for: " + ", ".join(errors),
                          why="The check itself failed, so this item is unverified (not a pass).",
                          fix="Re-run infra_audit."))
    elif count > t["spf_lookups_fail"]:
        out.append(Result("spf.lookups", domain, FAIL, f"SPF needs {count} DNS lookups (hard limit is 10)",
                          detail=breakdown,
                          why="Over 10 lookups is a permanent error: receivers treat SPF as failed for all your mail.",
                          fix=f"In your DNS provider, edit the TXT record at {domain} and remove includes you no longer "
                              "use (start with any legacy/unrecognized ones above).",
                          observed=str(count)))
    elif count >= t["spf_lookups_warn"]:
        out.append(Result("spf.lookups", domain, WARN, f"SPF needs {count} of 10 allowed DNS lookups",
                          detail=breakdown,
                          why="One more provider (or a provider adding a nested include) will push you over 10 and break SPF.",
                          fix=f"In your DNS provider, trim unused includes from the TXT record at {domain}.",
                          observed=str(count)))
    else:
        out.append(Result("spf.lookups", domain, PASS, f"SPF needs {count} of 10 DNS lookups",
                          detail=breakdown, observed=str(count)))
    return out
