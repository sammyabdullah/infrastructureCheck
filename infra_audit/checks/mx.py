"""MX: records exist, point at the expected provider, and the hosts resolve."""

from ..dnsutil import is_within
from ..result import FAIL, PASS, WARN, Result, error

GOOGLE_PRIMARY = {"aspmx.l.google.com", "smtp.google.com"}


def check_mx(ctx, target):
    domain = target["domain"]
    suffixes = target.get("mx_expected_suffixes")
    if suffixes is None:
        return []
    ans = ctx.dns.query(domain, "MX")
    if ans.failed:
        return [error("mx.records", domain, "Could not look up MX (DNS failure)", ans.error)]
    is_ses = any(s.endswith("amazonses.com") for s in suffixes)
    if not ans.ok:
        if is_ses:
            fix = (f"In your DNS provider, add an MX record at {domain} with priority 10 pointing to "
                   "the feedback-smtp...amazonses.com host your sending service lists (Resend: Dashboard > Domains > " + domain + ").")
            why = ("Resend/Amazon SES require this MX for the bounce subdomain; without it mail falls back to amazonses.com and "
                   "SPF no longer aligns with your domain.")
        else:
            fix = ("In your DNS provider, add an MX record at " + domain + " pointing to smtp.google.com with priority 1 "
                   "(Google's current single-record setup).")
            why = "With no MX, nobody can reply to you and many receivers reject mail from domains that can't receive."
        return [Result("mx.records", domain, FAIL, "No MX records", why=why, fix=fix, observed="(none)")]

    records = sorted(ans.records)
    observed = ", ".join(f"{p} {h}" for p, h in records)
    out = []
    if any(h in ("", ".") for _, h in records):
        return [Result("mx.records", domain, FAIL, "Null MX (domain says it accepts no mail)",
                       why="Receivers reject mail from domains with a null MX.",
                       fix=f"In your DNS provider, replace the '.' MX record at {domain} with your provider's MX hosts.",
                       observed=observed)]
    unexpected = [h for _, h in records if not any(is_within(h, s) for s in suffixes)]
    if unexpected:
        out.append(Result("mx.records", domain, FAIL, "Unexpected MX host(s): " + ", ".join(unexpected),
                          detail=observed,
                          why="Mail for your domain is being routed to a server you didn't list: lost mail or interception.",
                          fix=f"In your DNS provider, delete the MX record(s) at {domain} pointing to "
                              + ", ".join(unexpected) + " unless you added them on purpose (then add the suffix to "
                              "mx_expected_suffixes in config.json).",
                          observed=observed))
    else:
        out.append(Result("mx.records", domain, PASS, f"{len(records)} MX record(s), all at expected provider",
                          detail=observed, observed=observed))

    if any("google.com" in s for s in suffixes):
        lowest = min(p for p, _ in records)
        primaries = {h for p, h in records if p == lowest}
        if not primaries & GOOGLE_PRIMARY:
            out.append(Result("mx.priority", domain, WARN, "Highest-priority MX isn't Google's primary host",
                              detail=observed,
                              why="Senders try the lowest-numbered MX first; a backup host as primary slows or misroutes mail.",
                              fix=f"In your DNS provider, give smtp.google.com (or ASPMX.L.GOOGLE.COM) the lowest priority number at {domain}.",
                              observed=",".join(sorted(primaries))))
        else:
            out.append(Result("mx.priority", domain, PASS, "MX priorities are sane", observed=",".join(sorted(primaries))))

    dead = []
    for _, host in records:
        resolved = ctx.dns.resolves(host)
        if resolved is None:
            out.append(error("mx.resolves", host, f"Could not resolve MX host {host}"))
        elif not resolved:
            dead.append(host)
    if dead:
        out.append(Result("mx.resolves", domain, FAIL, "MX host(s) don't resolve: " + ", ".join(dead),
                          why="Senders can't deliver to a host with no address.",
                          fix=f"In your DNS provider, fix or delete the MX record(s) at {domain} pointing to " + ", ".join(dead) + ".",
                          observed=",".join(dead)))
    else:
        out.append(Result("mx.resolves", domain, PASS, "Every MX host resolves", observed="ok"))
    return out
