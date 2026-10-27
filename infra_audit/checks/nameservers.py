"""Nameserver sanity: every authoritative server answers and agrees, and the
parent (.com) delegation matches what the servers themselves publish."""

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from ..result import FAIL, PASS, WARN, Result, error


def _ask(ip, name, rdtype, timeout, tries=2):
    """Non-recursive query straight to one server. Returns the response or raises."""
    last = None
    for _ in range(tries):
        try:
            q = dns.message.make_query(name, rdtype)
            q.flags &= ~dns.flags.RD
            resp = dns.query.udp(q, ip, timeout=timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(q, ip, timeout=timeout)
            return resp
        except (dns.exception.Timeout, OSError) as e:
            last = e
    raise last


def _ip(ctx, host):
    a = ctx.dns.query(host, "A")
    return a.records[0] if a.ok else None


def _ns_names(resp, section):
    names = set()
    for rrset in getattr(resp, section):
        if rrset.rdtype == dns.rdatatype.NS:
            names |= {r.target.to_text().rstrip(".").lower() for r in rrset}
    return names


def check_nameservers(ctx):
    domain = ctx.cfg.root
    timeout = ctx.cfg.net["dns_timeout"]
    ans = ctx.dns.query(domain, "NS")
    if ans.failed:
        return [error("ns.records", domain, "Could not look up NS records (DNS failure)", ans.error)]
    if not ans.ok:
        return [Result("ns.records", domain, FAIL, "No NS records found",
                       why="Without nameservers nothing about your domain resolves.",
                       fix="At your registrar, set the nameservers for your domain to your DNS host's servers.",
                       observed="(none)")]
    child = set(ans.records)
    out = []
    if len(child) < 2:
        out.append(Result("ns.count", domain, WARN, f"Only {len(child)} nameserver",
                          why="One nameserver is a single point of failure for mail and web.",
                          fix="At your DNS host/registrar, add at least one more nameserver.", observed=str(len(child))))

    # Ask every authoritative server directly.
    lame, views, serials, failed = [], {}, {}, []
    for host in sorted(child):
        ip = _ip(ctx, host)
        if not ip:
            lame.append(f"{host} (no address)")
            continue
        try:
            ns_resp = _ask(ip, domain, "NS", timeout)
            soa_resp = _ask(ip, domain, "SOA", timeout)
        except Exception as e:
            failed.append(f"{host}: {type(e).__name__}")
            continue
        if ns_resp.rcode() != dns.rcode.NOERROR or not ns_resp.flags & dns.flags.AA:
            lame.append(f"{host} (not authoritative: {dns.rcode.to_text(ns_resp.rcode())})")
            continue
        views[host] = _ns_names(ns_resp, "answer")
        for rrset in soa_resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                serials[host] = rrset[0].serial

    if lame:
        out.append(Result("ns.lame", domain, FAIL if len(lame) == len(child) else WARN,
                          "Lame delegation: " + "; ".join(lame),
                          why="Resolvers that hit a lame server time out or fail, causing intermittent lookup failures "
                              "(and SPF/DKIM temperrors).",
                          fix="At your registrar, remove the listed nameserver(s) from your domain, or fix them at the DNS host.",
                          observed=",".join(sorted(lame))))
    elif failed and not views:
        out.append(error("ns.lame", domain, "No authoritative server answered direct queries", "; ".join(failed)))
    else:
        out.append(Result("ns.lame", domain, PASS, f"All {len(views)} nameservers answer authoritatively", observed="ok"))
    if failed and views:
        out.append(error("ns.direct", domain, "Some nameservers didn't answer direct queries", "; ".join(failed)))

    distinct = {frozenset(v) for v in views.values()}
    if len(distinct) > 1 or (views and next(iter(distinct)) != child):
        detail = "; ".join(f"{h}: {','.join(sorted(v))}" for h, v in views.items())
        out.append(Result("ns.consistency", domain, WARN, "Nameservers disagree about the NS set",
                          detail=detail,
                          why="Inconsistent NS sets mean some resolvers may use stale or wrong servers.",
                          fix="At your DNS host, make the NS records at the zone apex list exactly the same servers "
                              "your registrar delegates to.",
                          observed=detail))
    elif views:
        out.append(Result("ns.consistency", domain, PASS, "All nameservers agree on the NS set",
                          observed=",".join(sorted(child))))

    if len(set(serials.values())) > 1:
        detail = ", ".join(f"{h}={s}" for h, s in sorted(serials.items()))
        out.append(Result("ns.soa", domain, WARN, "Nameservers serve different zone versions (SOA serials differ)",
                          detail=detail,
                          why="Some servers have stale records; usually clears within minutes after an edit. Persistent = broken sync.",
                          fix="If this persists past an hour, contact your DNS host: zone transfer to the secondary servers is failing."))

    # Parent delegation: what .com says vs what the zone says.
    tld = domain.split(".", 1)[1]
    tld_ns = ctx.dns.query(tld, "NS")
    parent = None
    if tld_ns.ok:
        for host in sorted(tld_ns.records)[:3]:
            ip = _ip(ctx, host)
            if not ip:
                continue
            try:
                resp = _ask(ip, domain, "NS", timeout)
                parent = _ns_names(resp, "authority") or _ns_names(resp, "answer")
                break
            except Exception:
                continue
    if parent is None:
        out.append(error("ns.delegation", domain, f"Could not query the .{tld} servers for your delegation"))
    elif parent != child:
        out.append(Result("ns.delegation", domain, WARN, "Registrar delegation doesn't match the zone's NS records",
                          detail=f"registrar (.{tld}): {','.join(sorted(parent))}; zone: {','.join(sorted(child))}",
                          why="Mismatches cause some resolvers to query servers that aren't (or are no longer) authoritative.",
                          fix="Make the nameserver list at your registrar and the NS records at your DNS host identical.",
                          observed=",".join(sorted(parent))))
    else:
        out.append(Result("ns.delegation", domain, PASS, "Registrar delegation matches the zone",
                          detail=", ".join(sorted(parent)), observed=",".join(sorted(parent))))
    return out
