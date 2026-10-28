"""DKIM: each configured selector publishes a valid public key of >= 2048 bits."""

import base64
import hashlib
from datetime import datetime, timezone

from ..result import FAIL, INFO, PASS, WARN, Result, error

WHY_DKIM = "DKIM is what lets Gmail, Outlook and others confirm your mail is really from you; DMARC p=reject depends on it."


def parse_tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = "".join(v.split())
    return tags


def key_bits(p_value, key_type="rsa"):
    """Public key size in bits. Raises ValueError for an unparseable key."""
    der = base64.b64decode(p_value, validate=True)
    if key_type == "ed25519":
        if len(der) != 32:
            raise ValueError("ed25519 key is not 32 bytes")
        return 256
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    return load_der_public_key(der).key_size


def regenerate_fix(provider, selector, domain):
    if provider == "Google Workspace":
        return ("In Google Admin console > Apps > Google Workspace > Gmail > Authenticate email, pick "
                f"{domain}, click 'Generate new record' with 2048-bit key length, publish the TXT value it shows at "
                f"{selector}._domainkey.{domain} in your DNS provider, wait for it to resolve, then click 'Start authentication'.")
    if provider == "Resend":
        return ("Resend generates this key. In the Resend dashboard > Domains > " + domain + ", look for an option to "
                "regenerate/rotate the DKIM key at 2048 bits; if there isn't one, ask Resend support for a 2048-bit key. "
                "Then publish the new TXT value it gives you in your DNS provider.")
    if provider == "Amazon SES":
        return ("In the AWS SES console > Verified identities > " + domain + " > Authentication (DKIM), confirm Easy DKIM "
                "uses RSA_2048_BIT and re-publish the three CNAME records it lists in your DNS provider.")
    return (f"In {provider}'s settings, regenerate the DKIM key (2048-bit) and publish it at "
            f"{selector}._domainkey.{domain} in your DNS provider.")


def check_dkim(ctx, target):
    domain = target["domain"]
    selectors = target["dkim_selectors"]
    out = []

    for provider in target["dkim_expected_providers"]:
        if provider not in selectors.values():
            out.append(Result(f"dkim.{provider.lower().replace(' ', '_')}", domain, WARN,
                              f"No DKIM selector configured for {provider}",
                              why="Unlisted selectors aren't checked, so a broken or missing key there would go unnoticed.",
                              fix=f"Add {provider}'s selector(s) to dkim_selectors for {domain} in config.json "
                                  "(the TXT/CNAME records named <selector>._domainkey in your DNS provider).",
                              observed="(unconfigured)"))

    for selector, provider in selectors.items():
        out.extend(_check_selector(ctx, domain, selector, provider))
    return out


def _check_selector(ctx, domain, selector, provider):
    check = f"dkim.{selector}"
    host = f"{selector}._domainkey.{domain}"
    ans = ctx.dns.query(host, "TXT")
    if ans.failed:
        return [error(check, domain, f"Could not look up DKIM selector '{selector}' (DNS failure)", ans.error)]
    records = [r for r in ans.records if "p=" in r.replace(" ", "")]
    if not records:
        return [Result(check, domain, FAIL, f"DKIM key missing at {host} ({provider})",
                       why=WHY_DKIM + " Mail signed with this selector will fail DKIM.",
                       fix=regenerate_fix(provider, selector, domain), observed="(missing)")]
    if len(records) > 1:
        return [Result(check, domain, FAIL, f"{len(records)} DKIM records at {host} (must be one)",
                       why="Receivers may pick the wrong one and fail DKIM.",
                       fix=f"In your DNS provider, delete all but the current TXT record at {host}.",
                       observed="(multiple)")]
    tags = parse_tags(records[0])
    p = tags.get("p", "")
    if not p:
        return [Result(check, domain, FAIL, f"DKIM key at {host} is revoked (empty p=)",
                       why=WHY_DKIM, fix=regenerate_fix(provider, selector, domain), observed="(revoked)")]
    try:
        bits = key_bits(p, tags.get("k", "rsa").lower())
    except Exception as e:
        return [Result(check, domain, FAIL, f"DKIM key at {host} doesn't parse",
                       detail=f"{type(e).__name__}: {e}. Often a TXT value split or pasted with stray characters.",
                       why=WHY_DKIM, fix=regenerate_fix(provider, selector, domain), observed="(malformed)")]

    fingerprint = hashlib.sha256(p.encode()).hexdigest()[:16]
    out = []
    min_bits = ctx.cfg.thresholds["dkim_min_bits"]
    if tags.get("k", "rsa").lower() == "rsa" and bits < min_bits:
        out.append(Result(check, domain, WARN, f"DKIM key '{selector}' is only {bits}-bit ({provider})",
                          why=f"Keys under {min_bits} bits are considered weak; some receivers already discount them.",
                          fix=regenerate_fix(provider, selector, domain), observed=f"{bits}:{fingerprint}"))
    else:
        out.append(Result(check, domain, PASS, f"DKIM key '{selector}' valid, {bits}-bit ({provider})",
                          observed=f"{bits}:{fingerprint}"))

    # Key age: DNS can't tell us when a key was created, so we use the first
    # time this tool saw this exact key.
    first = ctx.history.first_seen(check, domain, f"{bits}:{fingerprint}")
    if first:
        days = (ctx.now - datetime.fromisoformat(first).astimezone(timezone.utc)).days
        warn_days = ctx.cfg.thresholds["dkim_key_age_warn_days"]
        if days >= warn_days:
            out.append(Result(f"{check}.age", domain, WARN, f"DKIM key '{selector}' unchanged for {days}+ days",
                              detail=f"First seen by infra_audit on {first[:10]}.",
                              why="Long-lived keys have more time to leak; rotating yearly-ish is common practice.",
                              fix=regenerate_fix(provider, selector, domain)))
        else:
            out.append(Result(f"{check}.age", domain, INFO, f"DKIM key '{selector}' unchanged since {first[:10]}"))
    else:
        out.append(Result(f"{check}.age", domain, INFO, f"DKIM key '{selector}' first seen today",
                          detail="Key age can't be read from DNS; infra_audit tracks it from now on."))
    return out
