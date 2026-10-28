"""Load config.json. Everything site-specific lives there, not in code."""

import copy
import json
import os

DEFAULT_THRESHOLDS = {
    "spf_lookups_warn": 8,
    "spf_lookups_fail": 10,
    "dkim_min_bits": 2048,
    "dkim_key_age_warn_days": 730,
    "domain_expiry_warn_days": 60,
    "domain_expiry_fail_days": 14,
    "tls_expiry_warn_days": 21,
    "tls_expiry_fail_days": 7,
    "activity_days": 14,
    "activity_spike_multiplier": 2.0,
    "activity_spike_min_count": 10,
    "last_login_warn_days": 30,
    "hard_bounce_rate_warn_pct": 1.0,
    "hard_bounce_rate_fail_pct": 2.0,
}

DEFAULT_NETWORK = {
    "dns_timeout": 4,
    "dns_lifetime": 8,
    "dns_retries": 2,
    "dns_nameservers": [],
    "http_timeout": 10,
    "smtp_timeout": 10,
    "workers": 32,
}


class Config(dict):
    """A dict with a few convenience accessors. `base_dir` is the config file's folder."""

    base_dir = "."

    def path(self, key_or_value):
        """Resolve a configured path relative to the config file's folder."""
        value = self.get(key_or_value, key_or_value) if isinstance(key_or_value, str) else key_or_value
        value = os.path.expanduser(value)
        return value if os.path.isabs(value) else os.path.normpath(os.path.join(self.base_dir, value))

    @property
    def root(self):
        return self["root_domain"].lower().rstrip(".")

    @property
    def active_domains(self):
        return [d for d in self["sending_domains"] if d.get("active", True)]

    @property
    def thresholds(self):
        return self["thresholds"]

    @property
    def net(self):
        return self["network"]


def _strip_notes(obj):
    if isinstance(obj, dict):
        return {k: _strip_notes(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_notes(v) for v in obj]
    return obj


def load_config(path):
    with open(path) as f:
        raw = _strip_notes(json.load(f))
    cfg = Config(copy.deepcopy(raw))
    cfg.base_dir = os.path.dirname(os.path.abspath(path))
    cfg["thresholds"] = {**DEFAULT_THRESHOLDS, **raw.get("thresholds", {})}
    cfg["network"] = {**DEFAULT_NETWORK, **raw.get("network", {})}
    cfg.setdefault("sending_domains", [{"domain": raw["root_domain"]}])
    cfg.setdefault("cname_hosts", {})
    cfg.setdefault("dmarc", {"expected_policy": "reject"})
    cfg.setdefault("website_hosts", [raw["root_domain"]])
    cfg.setdefault("check_mx_starttls", True)
    cfg.setdefault("reputation_lists", [])
    cfg.setdefault("mailboxes", [])
    cfg.setdefault("allowed_send_as", list(cfg["mailboxes"]))
    cfg.setdefault("allowed_forwarding", [])
    cfg.setdefault("allowed_delegates", [])
    cfg.setdefault("allowed_filter_terms", [])
    cfg.setdefault("google", {})
    cfg.setdefault("bounce_db", "")
    cfg.setdefault("history_db", "data/infra_audit.db")
    cfg.setdefault("reports_dir", "reports")
    for d in cfg["sending_domains"]:
        d["domain"] = d["domain"].lower().rstrip(".")
        d.setdefault("label", d["domain"])
        d.setdefault("spf_required_includes", [])
        d.setdefault("spf_known_includes", [])
        d.setdefault("spf_legacy_includes", [])
        d.setdefault("dkim_selectors", {})
        d.setdefault("dkim_expected_providers", [])
        d.setdefault("mx_expected_suffixes", None)
    for key in ("mailboxes", "allowed_send_as", "allowed_forwarding", "allowed_delegates"):
        cfg[key] = [a.lower() for a in cfg[key]]
    return cfg
