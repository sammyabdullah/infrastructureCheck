# infra_audit

A read-only health check of the email sending setup for `blossomstreetventures.com`. Each run checks:

- DNS authentication: SPF, DKIM, DMARC, MX, plus MTA-STS, TLS-RPT, BIMI, CAA and DNSSEC.
- Nameservers, dangling CNAMEs, domain registration, and TLS certificates.
- Domain blocklists.
- Each of the 5 mailboxes: Gmail settings, account security, sending volume and hard bounces.

It prints a prioritized report with **what changed since the last run at the top**, saves the run to SQLite, and writes a dated Markdown report.

It works the same way as mailerdemon, HardBounceCheck, Engagement-Tracker and BlackListChecker: pure Python with DNS, public lookups and Google APIs. It never calls an LLM or AI API at runtime.

**It is strictly read-only.** It only makes DNS queries, HTTPS GETs, an SMTP `EHLO`/`STARTTLS` handshake (no mail is sent), and Google API `get`/`list` calls. It never changes DNS, Gmail, Workspace or any account. Every fix is manual, and the report tells you exactly what to change and where.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

1. **Service account key.** Copy (or symlink) the same `service_account.json` that HardBounceCheck and Engagement-Tracker use into this folder, or point `google.service_account_file` in `config.json` at it. It is gitignored.
2. **Bounce database (optional).** `bounce_db` in `config.json` is set to `../../Old claude/Claude Hard Bounce Check/bounces.db` (relative to this folder). Change it if that file moves. If the file isn't there, the bounce check is skipped silently.
3. **SES DKIM selectors.** SES Easy DKIM uses three random-token selectors. Get them from AWS console > SES > Verified identities > blossomstreetventures.com > Authentication (DKIM). Each record looks like `<token>._domainkey...`. Add them under the root domain's `dkim_selectors`:
   ```json
   "dkim_selectors": {
     "google": "Google Workspace",
     "abc123token": "Amazon SES",
     "def456token": "Amazon SES",
     "ghi789token": "Amazon SES"
   }
   ```
   Until you do, you'll see one WARN: "No DKIM selector configured for Amazon SES".

## Usage

```bash
python -m infra_audit                    # everything
python -m infra_audit --only dns         # just DNS/auth (repeatable: --only dns --only reputation)
python -m infra_audit --only reputation
python -m infra_audit --only mailboxes
python -m infra_audit --json             # machine-readable output
python -m infra_audit --verbose          # also list every PASS/INFO
python -m infra_audit --no-save          # don't record history or write a report
```

Exit codes: `0` healthy, `1` WARN or ERROR present, `2` a FAIL or a regression. This is useful with cron:

```cron
30 8 * * 1-5 cd /path/to/infrastructureCheck && .venv/bin/python -m infra_audit >> data/cron.log 2>&1
```

## Reading the report

Every check returns one of these statuses:

| Status | Meaning |
|---|---|
| **FAIL** | Broken, or a security/deliverability problem. Fix it now. |
| **WARN** | Works, but risky or degraded. Fix it soon. |
| **ERROR** | The check itself couldn't run (DNS timeout, a blocklist refused your resolver, API not permitted). This is **never a pass**. Re-run it; if it keeps failing, read its detail line. |
| **INFO** | Facts and nice-to-haves (MTA-STS absent, BIMI, CAA, DNSSEC, send volumes). |
| **PASS** | Checked and fine. |

The console report is ordered like this:

1. **DRIFT.** Changes since the last run of the same section(s), most important first:
   - `REGRESSION`: something got worse (PASS→WARN/FAIL), or a new problem appeared.
   - `CHANGED`: a record's value changed but it still passes. For example, someone edited SPF or rotated a DKIM key. Before and after values are shown.
   - `CHECK FAILED`: was fine last time, couldn't be checked this time.
   - `IMPROVED` / `NO LONGER CHECKED`.
2. **FAIL**, then **WARN**, each with *Found*, *Why* it matters, and the exact *Fix*.
3. **ERROR** items.
4. A one-line count of everything.

If everything passes and nothing changed, you get one line with the counts and the time.

Each run is stored in `data/infra_audit.db` and also written to `reports/infra_audit_YYYY-MM-DD_HHMMSS.md`, which lists every item, including PASS and INFO.

Using `--only` compares each section against the most recent run that included that section. A section that couldn't run at all (broken DNS, missing key) is neither compared nor saved as a baseline.

## Scopes (Google)

All Google access uses the **same service account and domain-wide delegation as HardBounceCheck and Engagement-Tracker**: one JSON key, impersonating each mailbox with `with_subject`.

### Already authorized: `https://www.googleapis.com/auth/gmail.readonly`

Your existing domain-wide delegation entry already grants this scope. infra_audit uses it, impersonating each mailbox as itself, for:

- `settings.getAutoForwarding`, `settings.forwardingAddresses.list`, `settings.filters.list`, `settings.delegates.list`, `settings.sendAs.list`, `settings.getVacation`
- `messages.list` with `in:sent after:… before:…`, which fetches **message IDs only, used purely to count sends per day**. No headers or bodies are fetched.

**No new Gmail scope is needed.** There are two narrower-looking alternatives, and neither works:

- `gmail.metadata` rejects the search (`q`) parameter that sent-mail counting needs (the same finding as Engagement-Tracker).
- `gmail.settings.basic` can *modify* settings, so it's a broader grant, not a narrower one.

If Google refuses any settings call under `gmail.readonly`, that check reports **ERROR** and names the scope it was refused under. infra_audit never widens scope on its own.

### Not authorized yet (skipped until you approve): `https://www.googleapis.com/auth/admin.directory.user.readonly`

This scope is needed only for the account-security checks: 2-Step Verification enrolled/enforced, last login, suspended/archived, and admin status. It impersonates `google.admin_email` (`sammy@`), which must be a super admin.

Until you approve it, those checks show a single INFO line: "Account security checks skipped". To enable them:

1. In Google Cloud Console, open the same project as the service account and enable the **Admin SDK API** (APIs & Services > Library).
2. Go to Google Admin console > Security > Access and data control > API controls > Domain-wide delegation, and **edit** the existing entry for the service account's client ID. Set the scopes to **both** of these, comma-separated:
   ```
   https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly
   ```
   ⚠️ Keep `gmail.readonly` in the list. Replacing it would break HardBounceCheck and Engagement-Tracker.
3. In `config.json`, set `"directory_scope_approved": true`.

## What's checked

| Section | Check | Notes |
|---|---|---|
| dns | SPF | Exactly one record; required includes (`_spf.google.com` on root, `amazonses.com` on `send.`); `+all`/`?all` FAIL, no `~all`/`-all` WARN; recursive DNS-lookup count (WARN at 8, FAIL over 10); includes with no SPF record (FAIL: permerror); legacy includes (`servers.mcsv.net`, Mailchimp) flagged as removable with the lookups that removing them frees; unrecognized includes WARN. |
| dns | DKIM | Each configured selector resolves to a parseable key; WARN under 2048 bits. DNS can't reveal a key's age, so infra_audit records when it first saw each key and WARNs after `dkim_key_age_warn_days`. |
| dns | DMARC | One record; `p=` must be at least `reject` (anything less is a FAIL); `sp=`, `pct`, alignment; `rua`/`ruf` syntax; external report domains must publish `<yourdomain>._report._dmarc.<theirdomain>`. Subdomains without their own record inherit the root's `sp=`/`p=`. Warns on `aspf=s` because SES's `send.` MAIL FROM needs relaxed SPF alignment. |
| dns | MX | Present, all hosts at the expected provider (Google for root, `amazonses.com` feedback MX for `send.`), primary priority sane, hosts resolve. Unexpected changes appear in drift. |
| dns | MTA-STS / TLS-RPT / BIMI / CAA / DNSSEC | INFO when absent, each with a one-line note on what it does. An MTA-STS policy that's unreachable, or that doesn't cover your MX in enforce mode, is a FAIL. A DS record with no DNSKEY is a FAIL. |
| dns | Nameservers | Queries every authoritative server directly: lame servers, disagreeing NS sets, SOA serial mismatch, and whether the registrar's `.com` delegation matches the zone. |
| dns | Dangling CNAMEs | Hosts in `cname_hosts` plus every DKIM selector. A CNAME whose target is NXDOMAIN is a FAIL (takeover risk). The legacy Mailchimp `k2`/`k3` CNAMEs are checked only for this, and are reported as INFO "safe to delete" if they still resolve. |
| dns | Registration (RDAP) | Expiry (WARN at 60 days, FAIL at 14) and registrar transfer lock. |
| dns | TLS | Website certificate (`website_hosts`) and MX STARTTLS certificate: validity and expiry. Home ISPs often block port 25. If the MX check always ERRORs from your network, set `check_mx_starttls` to `false`. |
| reputation | Domain blocklists | Spamhaus DBL, Spamhaus ZRD, SURBL, URIBL black, and SEM URIBL, for the root domain and `send.`. IP lists are skipped, because Google's outbound IPs are shared. NXDOMAIN means clean. Timeouts, and the lists' "query refused" return codes, are ERROR, never clean. Lists with a published test entry are also probed with it, so a list that silently stopped answering can't look clean. |
| mailboxes | Gmail settings | Auto-forwarding (FAIL unless allowlisted); registered forwarding addresses; filters that forward, delete, archive or spam mail; delegates; unrecognized send-as aliases; vacation responder. |
| mailboxes | Account security | Admin SDK, needs approval (see Scopes). |
| mailboxes | Sending activity | Sent messages per day for the last 14 full days, plus today. WARN on a day above 2× the trailing average (minimum 10 sends), and on a mailbox with no sends in 14+ days while the others are active. |
| mailboxes | Hard bounces | Count of addresses whose latest HARD bounce in HardBounceCheck's `bounces.db` was in the last 7 days, per mailbox. That database keeps one row per address, so this counts addresses, not bounce events. WARNs if HardBounceCheck hasn't scanned a mailbox in over 7 days (from its `state.json`), so stale zeros don't read as clean. |

A **DNS sanity check** runs first: if `google.com` or `gmail.com` don't resolve, the DNS and reputation sections are reported as ERROR instead of producing fake "no SPF record" FAILs and fake "not listed" passes.

## Configuration

Everything site-specific is in `config.json`: domain, sending subdomains and which are active, SPF required/known/legacy includes, DKIM selectors, CNAME hosts to watch, expected DMARC policy, blocklists, mailboxes, allowlists (send-as, forwarding, delegates), the admin to impersonate, the bounce DB path, thresholds, and DNS/HTTP timeouts. Keys that start with `_` are notes.

Notes:

- Keep `network.dns_nameservers` empty, so your Mac's resolver is used. Spamhaus and URIBL refuse queries that come through big public resolvers like 8.8.8.8 and 1.1.1.1.
- To stop checking a subdomain, set `"active": false` on it.

## Adding or removing a check

Checks are registered in `infra_audit/checks/__init__.py`, one line each:

```python
("dns", "domain", spf.check_spf),
```

Delete or comment out the line to drop a check. To add one, write a function that returns a list of `Result` and add one line. The scope controls how often the function runs:

- `domain` runs once per active sending domain.
- `root` runs once.
- `mailbox` runs once per mailbox.
- `fleet` runs once across all mailboxes.

## Tests

```bash
pip install pytest
python -m pytest -q
```

The tests run offline against a fake DNS zone and mocked Gmail responses.
