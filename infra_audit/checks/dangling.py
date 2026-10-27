"""Dangling CNAMEs: a CNAME whose target no longer exists can be claimed by
someone else (subdomain takeover), and is DNS clutter either way."""

from ..dnsutil import NXDOMAIN
from ..result import FAIL, INFO, PASS, Result, error


def _candidates(ctx):
    """Configured hostnames plus every configured DKIM selector host."""
    hosts = dict(ctx.cfg["cname_hosts"])
    for d in ctx.cfg["sending_domains"]:
        for selector, provider in d["dkim_selectors"].items():
            hosts.setdefault(f"{selector}._domainkey.{d['domain']}", f"{provider} DKIM")
    return hosts


def check_dangling_cnames(ctx):
    out = []
    for host, note in sorted(_candidates(ctx).items()):
        host = host.lower().rstrip(".")
        cname = ctx.dns.query(host, "CNAME")
        if cname.failed:
            out.append(error("dangling", host, f"Could not look up CNAME for {host}", cname.error))
            continue
        if not cname.ok:
            out.append(Result("dangling", host, INFO, "No CNAME here (nothing to dangle)", detail=note, observed="(none)"))
            continue
        target = cname.records[0]
        # Dangling = the target name doesn't exist at all (NXDOMAIN). A DKIM
        # CNAME target is a TXT-only name, so query the type it should have.
        probe = ctx.dns.query(target, "TXT" if "._domainkey." in host else "A")
        alive = None if probe.failed else probe.status != NXDOMAIN
        observed = f"-> {target}"
        if alive is None:
            out.append(error("dangling", host, f"Could not resolve CNAME target {target}"))
        elif not alive:
            out.append(Result("dangling", host, FAIL, f"Dangling CNAME: {host} -> {target} (target doesn't resolve)",
                              detail=note,
                              why="If someone registers or claims that target, they control a hostname on your domain "
                                  "(phishing, cookie theft, reputation damage).",
                              fix=f"In your DNS provider, delete the CNAME record at {host}.",
                              observed=observed))
        elif "legacy" in note.lower() or "not used" in note.lower():
            out.append(Result("dangling", host, INFO, f"{host} -> {target} still resolves ({note})",
                              detail="Not dangling. Safe to delete when you're sure you no longer use it.",
                              observed=observed))
        else:
            out.append(Result("dangling", host, PASS, f"{host} -> {target} resolves", detail=note, observed=observed))
    return out
