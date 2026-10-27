"""Thread-safe, cached DNS lookups with timeouts and retries.

A lookup ends in exactly one of four states. Only `error` is retried, and
callers must never read `error` as "record absent": a timeout or SERVFAIL
means "unknown", which the checks report as ERROR.
"""

import threading
import time
from dataclasses import dataclass

import dns.exception
import dns.resolver

OK, NXDOMAIN, NOANSWER, ERROR = "ok", "nxdomain", "noanswer", "error"


@dataclass(frozen=True)
class Answer:
    name: str
    rdtype: str
    status: str
    records: tuple = ()
    error: str = ""

    @property
    def ok(self):
        return self.status == OK

    @property
    def failed(self):
        return self.status == ERROR

    @property
    def absent(self):
        return self.status in (NXDOMAIN, NOANSWER)


def _format(rdata, rdtype):
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rdtype == "MX":
        return (int(rdata.preference), rdata.exchange.to_text().rstrip(".").lower())
    if rdtype in ("NS", "CNAME", "PTR"):
        return rdata.target.to_text().rstrip(".").lower()
    if rdtype == "CAA":
        return f'{rdata.flags} {rdata.tag.decode()} "{rdata.value.decode()}"'
    return rdata.to_text()


class Dns:
    def __init__(self, timeout=4.0, lifetime=8.0, retries=2, nameservers=None):
        self.timeout = float(timeout)
        self.lifetime = float(lifetime)
        self.retries = int(retries)
        self.nameservers = list(nameservers or [])
        self._cache = {}
        self._lock = threading.Lock()
        self._local = threading.local()

    def _resolver(self):
        r = getattr(self._local, "resolver", None)
        if r is None:
            r = dns.resolver.Resolver()
            r.timeout = self.timeout
            r.lifetime = self.lifetime
            if self.nameservers:
                r.nameservers = self.nameservers
            self._local.resolver = r
        return r

    def query(self, name, rdtype):
        name = name.lower().rstrip(".")
        key = (name, rdtype)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        answer = self._query(name, rdtype)
        if not answer.failed:
            with self._lock:
                self._cache[key] = answer
        return answer

    def _query(self, name, rdtype):
        last_error = ""
        for attempt in range(self.retries + 1):
            try:
                rrset = self._resolver().resolve(name, rdtype)
                return Answer(name, rdtype, OK, tuple(_format(r, rdtype) for r in rrset))
            except dns.resolver.NXDOMAIN:
                return Answer(name, rdtype, NXDOMAIN)
            except dns.resolver.NoAnswer:
                return Answer(name, rdtype, NOANSWER)
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
                last_error = f"{type(e).__name__}: {e}"
            except Exception as e:  # unexpected dnspython error: report, don't crash the run
                last_error = f"{type(e).__name__}: {e}"
            if attempt < self.retries:
                time.sleep(0.5 * (attempt + 1))
        return Answer(name, rdtype, ERROR, error=last_error or "lookup failed")

    def resolves(self, name):
        """True/False if the name has an A or AAAA record, None if lookups failed."""
        a = self.query(name, "A")
        if a.ok:
            return True
        aaaa = self.query(name, "AAAA")
        if aaaa.ok:
            return True
        if a.failed or aaaa.failed:
            return None
        return False


def txt_starting(answer, prefix):
    """TXT records whose first token is `prefix` (e.g. v=spf1), case-insensitive."""
    p = prefix.lower()
    out = []
    for rec in answer.records:
        head = rec.strip().lower()
        if head == p or head.startswith(p + " ") or head.startswith(p + ";"):
            out.append(rec.strip())
    return out


def is_within(host, domain):
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)
