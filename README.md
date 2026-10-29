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

Windows Command Prompt, from the `infrastructureCheck` folder:

```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

1. **Service account key.** Copy the same `service_account.json` that HardBounceCheck and Engagement-Tracker use into this folder, or point `google.service_account_file` in `config.json` at it. It is gitignored.
2. **Bounce database (optional).** `bounce_db` in `config.json` is set to `../../Old claude/Claude Hard Bounce Check/bounces.db` (relative to this folder). Change it if that file moves. If the file isn't there, the bounce check is skipped silently.
3. **DKIM selectors.** `dkim_selectors` lists every DKIM key to check: `google2026` (Google Workspace, rotated to 2048-bit on 2026-10-27), `resend` (Resend) and `brevo1`/`brevo2` (Brevo). If you add a sending service, add its selector there; its DNS record is named `<selector>._domainkey`.

## Usage

```
cd /d "C:\Users\sammy\Dropbox\The Dan\DAN Fund\Claude Infrastructure Check\infrastructureCheck"
.venv\Scripts\activate
python -m infra_audit                    # everything
python -m infra_audit --only dns         # just DNS/auth (repeatable: --only dns --only reputation)
python -m infra_audit --only reputation
python -m infra_audit --only mailboxes
python -m infra_audit --json             # machine-readable output
python -m infra_audit --verbose          # also list every PASS/INFO
python -m infra_audit --no-save          # don't record history or write a report
```

Exit codes: `0` healthy, `1` WARN or ERROR present, `2` a FAIL or a regression.

### Scheduled daily run (Windows)

`scripts\run_scheduled.bat` runs two things in order:

1. HardBounceCheck (`..\..\Old claude\Claude Hard Bounce Check`), so the bounce data is fresh.
2. A full infra_audit run.

Everything it prints is appended to `data\scheduled_run.log`. If infra_audit finds a FAIL or a regression, the new report opens in Notepad. WARNs alone don't pop anything up.

Register it once, from the `infrastructureCheck` folder:

```
powershell -ExecutionPolicy Bypass -File scripts\setup_schedule.ps1
```

This creates the task "infra_audit daily". It runs at 7:43 AM, or as soon as the PC is on if it was off at that time.

- Run a check yourself and see the results on screen: double-click `scripts\run_now.bat`.
- Test it now: `powershell -Command "Start-ScheduledTask -TaskName 'infra_audit daily'"`
- Remove it: `powershell -Command "Unregister-ScheduledTask -TaskName 'infra_audit daily' -Confirm:$false"`

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

Each run is stored in `data/infra_audit.db` and also written to `reports/infra_audit_YYYY-MM-DD_HHMMSS.md`, which lists every item, including PASS and INFO. Report files older than `reports_keep_days` (90) are deleted automatically; the full history stays in the database.

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
| dns | SPF | Exactly one record; valid syntax (e.g. a stray space in `include: x` is a FAIL); required includes (`_spf.google.com` on root, `amazonses.com` on `send.`); `+all`/`?all` FAIL, no `~all`/`-all` WARN; recursive DNS-lookup count (WARN at 8, FAIL over 10); includes with no SPF record (FAIL: permerror); legacy includes (`spf_legacy_includes`, e.g. Mailchimp's `servers.mcsv.net`) flagged as removable with the lookups that removing them frees; includes on your own domain (Resend's `dc-…._spfm.send` record) are judged by what they contain; unrecognized includes WARN. |
| dns | DKIM | Each configured selector resolves to a parseable key; WARN under 2048 bits. DNS can't reveal a key's age, so infra_audit records when it first saw each key and WARNs after `dkim_key_age_warn_days`. |
| dns | DMARC | One record; `p=` must be at least `reject` (anything less is a FAIL); `sp=`, `pct`, alignment; `rua`/`ruf` syntax; external report domains must publish `<yourdomain>._report._dmarc.<theirdomain>`. Subdomains without their own record inherit the root's `sp=`/`p=`. Warns on `aspf=s` because Resend's `send.` bounce subdomain needs relaxed SPF alignment. |
| dns | MX | Present, all hosts at the expected provider (Google for root, `amazonses.com` feedback MX for `send.`), primary priority sane, hosts resolve. Unexpected changes appear in drift. |
| dns | MTA-STS / TLS-RPT / BIMI / CAA / DNSSEC | INFO when absent, each with a one-line note on what it does. An MTA-STS policy that's unreachable, or that doesn't cover your MX in enforce mode, is a FAIL. A DS record with no DNSKEY is a FAIL. |
| dns | Nameservers | Queries every authoritative server directly: lame servers, disagreeing NS sets, SOA serial mismatch, and whether the registrar's `.com` delegation matches the zone. |
| dns | Dangling CNAMEs | Hosts in `cname_hosts` plus every DKIM selector. A CNAME whose target is NXDOMAIN is a FAIL (takeover risk). Old records marked "not used" in `cname_hosts` (Mailchimp, GoDaddy email) are reported as INFO "safe to delete" if they ever reappear. |
| dns | Registration (RDAP) | Expiry (WARN at 60 days, FAIL at 14) and registrar transfer lock. |
| dns | TLS | Website certificate (`website_hosts`) and MX STARTTLS certificate: validity and expiry. The MX STARTTLS check is off by default here (`check_mx_starttls`), because your ISP blocks outbound port 25. |
| reputation | Domain blocklists | Spamhaus DBL, SURBL, URIBL black, and SEM URIBL, for the root domain and `send.`. IP lists are skipped, because Google's outbound IPs are shared. NXDOMAIN means clean. Timeouts, and the lists' "query refused" return codes, are ERROR, never clean. Lists with a published test entry are also probed with it, so a list that silently stopped answering can't look clean. |
| mailboxes | Gmail settings | Auto-forwarding (FAIL unless allowlisted); registered forwarding addresses; filters that forward, delete, archive or spam mail; delegates; unrecognized send-as aliases; vacation responder. |
| mailboxes | Account security | Admin SDK, needs approval (see Scopes). |
| mailboxes | Sending activity | Sent messages per day for the last 14 full days, plus today. WARN on a day above 2× the trailing average (minimum 10 sends), and on a mailbox with no sends in 14+ days while the others are active. |
| mailboxes | Hard bounces | Hard bounce rate for the last 7 days per mailbox: addresses whose latest HARD bounce in HardBounceCheck's `bounces.db` falls in the last 7 days, divided by messages sent in those 7 days (from Gmail). WARN at 1%, FAIL at 2%. That database keeps one row per address, so this counts addresses, not bounce events. Also WARNs if HardBounceCheck hasn't scanned a mailbox in over 7 days (read from its `state.json`), so stale zeros don't read as clean. |

A **DNS sanity check** runs first: if `google.com` or `gmail.com` don't resolve, the DNS and reputation sections are reported as ERROR instead of producing fake "no SPF record" FAILs and fake "not listed" passes.

## Configuration

Everything site-specific is in `config.json`: domain, sending subdomains and which are active, SPF required/known/legacy includes, DKIM selectors, CNAME hosts to watch, expected DMARC policy, blocklists, mailboxes, allowlists (send-as, forwarding, delegates, and `allowed_filter_terms` for archive filters you created on purpose), the admin to impersonate, the bounce DB path, thresholds, and DNS/HTTP timeouts. Keys that start with `_` are notes.

Notes:

- Keep `network.dns_nameservers` empty, so your PC's normal resolver is used. Spamhaus and URIBL refuse queries that come through big public resolvers like 8.8.8.8 and 1.1.1.1.
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
