"""Read-only Google API access via the same service account + domain-wide
delegation your HardBounceCheck and Engagement-Tracker tools already use.

Only read methods (get/list) are ever called. Scopes are never widened: if
a call is refused under the authorized scope, the check reports ERROR and
names the scope it would need.
"""

import os
import random
import threading
import time

GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
DIRECTORY_USER_READONLY = "https://www.googleapis.com/auth/admin.directory.user.readonly"

RETRYABLE = (429, 500, 502, 503, 504)


class Google:
    def __init__(self, key_path):
        self.key_path = key_path
        self._creds = {}
        self._lock = threading.Lock()

    def key_missing(self):
        return not os.path.exists(self.key_path)

    def _credentials(self, subject, scope):
        from google.oauth2 import service_account

        with self._lock:
            key = (subject, scope)
            if key not in self._creds:
                base = service_account.Credentials.from_service_account_file(self.key_path, scopes=[scope])
                self._creds[key] = base.with_subject(subject)
            return self._creds[key]

    # googleapiclient service objects aren't thread-safe, so every caller
    # gets its own (cheap: discovery docs are bundled, nothing is fetched).
    def gmail(self, mailbox):
        from googleapiclient.discovery import build

        return build("gmail", "v1", credentials=self._credentials(mailbox, GMAIL_READONLY), cache_discovery=False)

    def directory(self, admin_email):
        from googleapiclient.discovery import build

        return build("admin", "directory_v1",
                     credentials=self._credentials(admin_email, DIRECTORY_USER_READONLY), cache_discovery=False)


def execute(request, retries=4):
    """request.execute() with backoff on rate limits / transient server errors."""
    from googleapiclient.errors import HttpError

    for attempt in range(retries + 1):
        try:
            return request.execute(num_retries=0)
        except HttpError as e:
            status = getattr(e.resp, "status", None)
            rate_limited = status == 403 and "rateLimitExceeded" in str(e)
            if (status in RETRYABLE or rate_limited) and attempt < retries:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue
            raise


def explain(exc, scope):
    """Turn an auth/API exception into (title, detail) for an ERROR result."""
    text = f"{type(exc).__name__}: {exc}"
    lowered = text.lower()
    short_scope = scope.rsplit("/", 1)[-1]
    if "unauthorized_client" in lowered or "insufficient" in lowered or "scope" in lowered:
        return (
            f"Not permitted under the authorized scope ({short_scope})",
            f"{text[:300]} -- the service account's domain-wide delegation does not cover this call. "
            f"Not widening scope automatically; see README 'Scopes'.",
        )
    if "invalid_grant" in lowered:
        return ("Delegation refused for this account",
                f"{text[:300]} -- check the address exists and is not suspended.")
    if "accessnotconfigured" in lowered or "has not been used in project" in lowered:
        return ("API not enabled on the Cloud project", text[:300])
    return ("Google API call failed", text[:300])
