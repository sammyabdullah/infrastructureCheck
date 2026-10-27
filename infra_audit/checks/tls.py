"""TLS certificates: website (HTTPS) and MX servers (SMTP STARTTLS). Best-effort:
connection problems are ERROR, never PASS."""

import smtplib
import socket
import ssl
from datetime import datetime, timezone

from ..result import FAIL, PASS, WARN, Result, error


def _context():
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _expiry(cert):
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)


def _issuer(cert):
    parts = dict(x[0] for x in cert.get("issuer", ()))
    return parts.get("organizationName") or parts.get("commonName") or "?"


def _grade(ctx, check, host, cert, why, fix):
    exp = _expiry(cert)
    days = (exp - ctx.now).days
    t = ctx.cfg.thresholds
    title = f"TLS cert valid until {exp.date()} ({days} days, {_issuer(cert)})"
    # Observed = issuer only: certs renew often and expiry drift is just noise.
    if days <= t["tls_expiry_fail_days"]:
        return Result(check, host, FAIL, title, why=why, fix=fix, observed=_issuer(cert))
    if days <= t["tls_expiry_warn_days"]:
        return Result(check, host, WARN, title, why=why, fix=fix, observed=_issuer(cert))
    return Result(check, host, PASS, title, observed=_issuer(cert))


def check_website_tls(ctx):
    out = []
    timeout = ctx.cfg.net["http_timeout"]
    for host in ctx.cfg["website_hosts"]:
        try:
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with _context().wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
        except ssl.SSLCertVerificationError as e:
            out.append(Result("tls.web", host, FAIL, f"Website certificate is invalid: {e.verify_message}",
                              why="Links to your site from your emails show security warnings; some filters penalize that.",
                              fix=f"In your website host's dashboard, re-issue/renew the TLS certificate for {host}.",
                              observed="invalid"))
            continue
        except (OSError, ssl.SSLError) as e:
            out.append(error("tls.web", host, f"Could not connect to https://{host}", f"{type(e).__name__}: {e}"))
            continue
        out.append(_grade(ctx, "tls.web", host, cert,
                          why="An expired website cert shows browser warnings on every link in your mail.",
                          fix=f"In your website host's dashboard, renew the TLS certificate for {host} (or enable auto-renew)."))
    return out


def check_mx_starttls(ctx):
    if not ctx.cfg["check_mx_starttls"]:
        return []
    mx = ctx.dns.query(ctx.cfg.root, "MX")
    if not mx.ok:
        return []  # the MX check reports this
    out = []
    timeout = ctx.cfg.net["smtp_timeout"]
    hosts = [h for _, h in sorted(mx.records)][:2]  # primary + one backup is enough
    for host in hosts:
        try:
            with smtplib.SMTP(host, 25, timeout=timeout) as smtp:
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    out.append(Result("tls.mx", host, FAIL, f"MX {host} doesn't offer STARTTLS",
                                      why="Mail to you would travel unencrypted.",
                                      fix="Contact your mail provider; Google's MX always offers STARTTLS, so check the MX records.",
                                      observed="no-starttls"))
                    continue
                smtp.starttls(context=_context())
                cert = smtp.sock.getpeercert()
        except ssl.SSLCertVerificationError as e:
            out.append(Result("tls.mx", host, FAIL, f"MX {host} certificate is invalid: {e.verify_message}",
                              why="Senders enforcing TLS (MTA-STS, many banks) will refuse to deliver to you.",
                              fix="Check that your MX records point at your provider's real hostnames.",
                              observed="invalid"))
            continue
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            out.append(error("tls.mx", host, f"Could not reach {host}:25 for STARTTLS",
                             f"{type(e).__name__}: {e}. Home ISPs often block port 25; set check_mx_starttls to false "
                             "in config.json if this always fails from your network."))
            continue
        out.append(_grade(ctx, "tls.mx", host, cert,
                          why="Senders enforcing TLS will refuse to deliver once it expires.",
                          fix="Contact your mail provider (for Google, open a Workspace support case)."))
    return out
