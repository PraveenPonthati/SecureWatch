"""
detector.py — Stateful anomaly detection engine.

Three detection rules, each modelling a real-world cloud attack pattern:

1. Brute Force      — credential stuffing / password spray
2. Off-Hours Access — attackers operate in different time zones; legitimate
                      users rarely work at 2 AM
3. IAM Changes      — privilege escalation or backdoor account creation
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timezone

# ── Brute-force config ───────────────────────────────────────────────────────
# Security reasoning: 5 failed logins within 60 seconds from one IP almost
# certainly means automated credential stuffing, not a user mis-typing their
# password.
BRUTE_FORCE_THRESHOLD = 5       # number of failures
BRUTE_FORCE_WINDOW_SEC = 60     # rolling window in seconds

# ── Off-hours config (IST = UTC+5:30) ───────────────────────────────────────
# Security reasoning: most company employees work 9-18 IST. API calls
# outside that window warrant attention, especially from external IPs.
IST_OFFSET_HOURS = 5.5          # UTC+5:30
WORK_START_HOUR = 9             # 9:00 AM IST
WORK_END_HOUR = 18              # 6:00 PM IST

# ── IAM high-privilege actions ───────────────────────────────────────────────
# Security reasoning: these actions can grant admin access, create backdoor
# users, or attach powerful managed policies. Any one of them is worth logging.
WATCHED_IAM_ACTIONS = {
    "iam:PutUserPolicy",
    "iam:AttachUserPolicy",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AddUserToGroup",
}


class AnomalyDetector:
    """
    Holds minimal in-memory state to detect the three rule types.
    Designed to be called once per log event in a tight loop.
    """

    def __init__(self):
        # Per-IP deque of timestamps for recent failed logins
        # Using a deque so old timestamps are cheap to discard
        self._failed_logins: dict[str, deque] = defaultdict(deque)

    # ── Rule 1: Brute Force ──────────────────────────────────────────────────
    def is_brute_force(self, event: dict) -> bool:
        """
        Sliding-window counter: if an IP accumulates BRUTE_FORCE_THRESHOLD
        failed ConsoleLogin events within BRUTE_FORCE_WINDOW_SEC, flag it.
        """
        if event.get("eventName") != "ConsoleLogin":
            return False
        if event.get("errorCode") != "FailedAuthentication":
            return False

        ip = event.get("sourceIPAddress", "unknown")
        now = time.monotonic()
        window = self._failed_logins[ip]

        # Add the current timestamp
        window.append(now)

        # Drop entries older than the window
        while window and (now - window[0]) > BRUTE_FORCE_WINDOW_SEC:
            window.popleft()

        # If we've accumulated enough failures, it's a brute-force attempt
        return len(window) >= BRUTE_FORCE_THRESHOLD

    # ── Rule 2: Off-Hours Activity ───────────────────────────────────────────
    def is_off_hours(self, event: dict) -> bool:
        """
        Check if the event happened outside business hours (9-18 IST).
        For simulated events we also respect the _simulated_off_hours flag
        so demos show data regardless of what time the container starts.
        """
        # Honour the simulation flag injected by mock_logs.py
        if event.get("_simulated_off_hours"):
            return True

        # Parse the real event timestamp
        try:
            event_time_utc = datetime.fromisoformat(
                event["eventTime"].replace("Z", "+00:00")
            )
        except (KeyError, ValueError):
            return False

        # Convert UTC → IST by adding 5h 30m
        ist_hour = (event_time_utc.hour + IST_OFFSET_HOURS) % 24
        # Outside [9, 18) is considered off-hours
        return ist_hour < WORK_START_HOUR or ist_hour >= WORK_END_HOUR

    # ── Rule 3: IAM Changes ──────────────────────────────────────────────────
    def is_iam_change(self, event: dict) -> bool:
        """
        Any write-level IAM action is notable. Real environments should alert
        on these even during business hours because they're rarely part of
        normal automated workflows.
        """
        action = event.get("eventName", "")
        return action in WATCHED_IAM_ACTIONS

    # ── Single entry point ───────────────────────────────────────────────────
    def analyze(self, event: dict) -> dict[str, bool]:
        """
        Run all three rules against one event.
        Returns a dict of {rule_name: triggered_bool}.
        """
        return {
            "brute_force": self.is_brute_force(event),
            "off_hours": self.is_off_hours(event),
            "iam_change": self.is_iam_change(event),
        }
