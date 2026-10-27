"""Domain blocklists (DNS-based). NXDOMAIN = not listed. Timeouts and the
lists' own "query refused" codes are ERROR, never "clean"."""

from ..result import FAIL, PASS, Result, error


def check_blocklists(ctx, target):
    domain = target["domain"]
    out = []
    for bl in ctx.cfg["reputation_lists"]:
        check = "reputation." + bl["zone"]
        # Lists publish a permanently-listed test entry. If it doesn't come
        # back listed, the list isn't really answering us and "clean" is meaningless.
        if bl.get("test_domain"):
            test = ctx.dns.query(f"{bl['test_domain']}.{bl['zone']}", "A")
            refused = test.ok and all(c in bl.get("blocked_codes", []) for c in test.records)
            if not test.ok or refused:
                out.append(error(check, domain, f"{bl['name']} isn't answering properly (not confirmed clean)",
                                 f"its test entry {bl['test_domain']} came back {test.status}"
                                 f"{' (query refused)' if refused else ''}. Usually your resolver is blocked "
                                 "by the list; run from another network or set network.dns_nameservers."))
                continue
        ans = ctx.dns.query(f"{domain}.{bl['zone']}", "A")
        if ans.failed:
            out.append(error(check, domain, f"{bl['name']} lookup failed (not confirmed clean)", ans.error))
            continue
        if ans.absent:
            out.append(Result(check, domain, PASS, f"Not listed on {bl['name']}", observed="clean"))
            continue
        codes = sorted(ans.records)
        blocked = [c for c in codes if c in bl.get("blocked_codes", [])]
        if blocked:
            out.append(error(check, domain, f"{bl['name']} refused the query (not confirmed clean)",
                             f"return code {', '.join(blocked)}: the list blocks your DNS resolver (common with "
                             "8.8.8.8/1.1.1.1 or high volume). Run from a different network or use your ISP's resolver."))
            continue
        out.append(Result(check, domain, FAIL, f"LISTED on {bl['name']}",
                          detail=f"return code {', '.join(codes)}",
                          why="Receivers that use this list will spam-folder or reject mail containing or sent from this domain.",
                          fix=f"Find and stop the cause first (compromised mailbox, volume spike, a bad link), then request "
                              f"removal at {bl['delist_url']}.",
                          observed="listed:" + ",".join(codes)))
    return out
