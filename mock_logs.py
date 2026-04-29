"""
mock_logs.py — Generates realistic simulated AWS CloudTrail log events.
No real AWS account needed. Produces a continuous stream of log dicts.

Security reasoning: CloudTrail records every API call in AWS. By simulating
this data we can build and test detection logic without touching real infra.
"""

import random
import time
from datetime import datetime, timezone

# A pool of "attacker" IPs that will trigger brute force and off-hours rules
ATTACKER_IPS = ["185.220.101.1", "45.33.32.156", "104.21.7.99"]
# A pool of "normal" IPs representing legitimate employees
NORMAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 4) for j in range(10, 20)]

# AWS API actions that represent normal S3/EC2 read-only work
NORMAL_ACTIONS = [
    "s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups", "cloudwatch:GetMetricData",
]

# IAM write actions — any of these in production is worth an alert
# because they can escalate privileges or create backdoor accounts
IAM_WRITE_ACTIONS = [
    "iam:PutUserPolicy", "iam:AttachUserPolicy", "iam:CreateUser",
    "iam:CreateAccessKey", "iam:AddUserToGroup",
]

# Common IAM usernames for simulation
USERS = ["alice", "bob", "charlie", "deploy-bot", "dev-pipeline"]


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_failed_login(source_ip: str) -> dict:
    """
    Simulates a ConsoleLogin event with errorCode=FailedAuthentication.
    Multiple of these from the same IP in a short window = brute force.
    """
    return {
        "eventTime": _now_utc(),
        "eventName": "ConsoleLogin",
        "errorCode": "FailedAuthentication",
        "errorMessage": "Failed authentication",
        "sourceIPAddress": source_ip,
        "userAgent": "Mozilla/5.0",
        "userIdentity": {
            "type": "IAMUser",
            "userName": random.choice(USERS),
        },
    }


def make_iam_change(source_ip: str) -> dict:
    """
    Simulates an IAM write event (e.g. adding a policy to a user).
    These are high-signal events — legitimate changes should be rare
    and tracked in change-management, so any unexpected one is suspicious.
    """
    action = random.choice(IAM_WRITE_ACTIONS)
    return {
        "eventTime": _now_utc(),
        "eventName": action,
        "errorCode": None,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.x",
        "userIdentity": {
            "type": "IAMUser",
            "userName": random.choice(USERS),
        },
        "requestParameters": {
            "userName": f"new-user-{random.randint(100, 999)}",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    }


def make_normal_event(source_ip: str) -> dict:
    """Normal day-to-day API call — S3 reads, EC2 describes, etc."""
    return {
        "eventTime": _now_utc(),
        "eventName": random.choice(NORMAL_ACTIONS),
        "errorCode": None,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-sdk-python/1.x",
        "userIdentity": {
            "type": "IAMUser",
            "userName": random.choice(USERS),
        },
    }


def generate_events():
    """
    Infinite generator that yields CloudTrail-shaped log dicts.

    Burst pattern — every ~5 seconds we fire:
      - A burst of failed logins from an attacker IP  (triggers brute force)
      - 1-2 IAM change events                         (triggers IAM alert)
      - Several normal events for realistic background traffic
      - Occasionally an off-hours API call (marked by a flag so detector
        can check time-of-day without relying on the test machine's clock)

    We inject events frequently so the Grafana panels show data right away.
    """
    cycle = 0
    while True:
        attacker_ip = random.choice(ATTACKER_IPS)
        normal_ip = random.choice(NORMAL_IPS)

        # --- Brute-force burst: 6 failed logins in quick succession ---
        # Threshold is 5, so this reliably fires the brute-force counter
        for _ in range(random.randint(5, 8)):
            yield make_failed_login(attacker_ip)
            time.sleep(0.05)  # fast enough to stay within the 60-second window

        # --- IAM change (high severity) ---
        yield make_iam_change(attacker_ip)
        if random.random() < 0.5:
            yield make_iam_change(normal_ip)  # simulate an insider threat too

        # --- Off-hours marker: explicit flag so detector can count it ---
        # We don't fake the system clock; instead we tag the event so the
        # detector can recognise it regardless of what time the demo runs.
        off_hours_event = make_normal_event(attacker_ip)
        off_hours_event["_simulated_off_hours"] = True  # synthetic flag
        yield off_hours_event

        # --- Normal background traffic ---
        for _ in range(random.randint(4, 8)):
            yield make_normal_event(normal_ip)
            time.sleep(0.1)

        cycle += 1
        # Sleep between bursts so we don't flood the logs
        time.sleep(random.uniform(2, 4))


if __name__ == "__main__":
    # Quick smoke test — print 10 sample events
    gen = generate_events()
    for i, event in enumerate(gen):
        print(event)
        if i >= 9:
            break
