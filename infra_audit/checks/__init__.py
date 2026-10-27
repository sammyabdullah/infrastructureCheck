"""The check registry. Add or remove a check by adding or deleting one line.

Each entry is (section, scope, function):
  section  dns | reputation | mailboxes   (what --only selects)
  scope    domain   fn(ctx, target)  once per active sending domain in config.json
           root     fn(ctx)          once, for the root domain
           mailbox  fn(ctx, mailbox) once per mailbox
           fleet    fn(ctx)          once, across all mailboxes
Every function returns a list of Result.
"""

from . import accounts, dangling, dkim, dmarc, gmail_settings, mx, nameservers, policy_records, registration, reputation, spf, tls

CHECKS = [
    # Part 1: DNS and authentication
    ("dns", "domain", spf.check_spf),
    ("dns", "domain", dkim.check_dkim),
    ("dns", "domain", dmarc.check_dmarc),
    ("dns", "domain", mx.check_mx),
    ("dns", "root", policy_records.check_mta_sts),
    ("dns", "root", policy_records.check_tls_rpt),
    ("dns", "root", policy_records.check_bimi),
    ("dns", "root", policy_records.check_caa),
    ("dns", "root", policy_records.check_dnssec),
    ("dns", "root", nameservers.check_nameservers),
    ("dns", "root", dangling.check_dangling_cnames),
    ("dns", "root", registration.check_registration),
    ("dns", "root", tls.check_website_tls),
    ("dns", "root", tls.check_mx_starttls),
    # Part 2: reputation
    ("reputation", "domain", reputation.check_blocklists),
    # Part 3: mailboxes
    ("mailboxes", "mailbox", gmail_settings.check_auto_forwarding),
    ("mailboxes", "mailbox", gmail_settings.check_forwarding_addresses),
    ("mailboxes", "mailbox", gmail_settings.check_filters),
    ("mailboxes", "mailbox", gmail_settings.check_delegates),
    ("mailboxes", "mailbox", gmail_settings.check_send_as),
    ("mailboxes", "mailbox", gmail_settings.check_vacation),
    ("mailboxes", "fleet", accounts.check_directory),
    ("mailboxes", "fleet", accounts.check_sending_activity),
    ("mailboxes", "fleet", accounts.check_hard_bounces),
]

SECTIONS = ["dns", "reputation", "mailboxes"]
