"""
ingester.py — Reads the simulated log stream and feeds events to the detector.

This is the glue layer between mock_logs.py (event source) and detector.py
(analysis engine). When a rule fires it increments the right Prometheus counter
in metrics.py.

In a real system this module would read from an S3 bucket, an SQS queue, or a
Kinesis stream instead of the local generator.
"""

import time
from mock_logs import generate_events
from detector import AnomalyDetector


def run_ingestion_loop():
    """
    Continuously pulls events from the mock log generator, runs them through
    the detector, and updates Prometheus counters.

    We import the counters from metrics.py here (not at top-level) so that
    this module can also be imported in tests without starting FastAPI.
    """
    # Lazy import to avoid a circular import: metrics.py imports this module
    # via on_startup, so we defer the counter import until we're actually running.
    from metrics import brute_force_counter, offhours_counter, iam_counter

    detector = AnomalyDetector()
    processed = 0

    print("[ingester] Starting log ingestion loop…")

    for event in generate_events():
        try:
            results = detector.analyze(event)
            source_ip = event.get("sourceIPAddress", "unknown")
            action = event.get("eventName", "unknown")

            if results["brute_force"]:
                # Increment with the attacker's IP as a label
                brute_force_counter.labels(source_ip=source_ip).inc()
                print(f"[ALERT] Brute force from {source_ip}")

            if results["off_hours"]:
                offhours_counter.labels(source_ip=source_ip).inc()
                print(f"[ALERT] Off-hours API call: {action} from {source_ip}")

            if results["iam_change"]:
                iam_counter.labels(action=action).inc()
                print(f"[ALERT] IAM change: {action} by {event.get('userIdentity', {}).get('userName')}")

            processed += 1
            if processed % 50 == 0:
                print(f"[ingester] Processed {processed} events so far")

        except Exception as exc:
            # Log and continue — a single bad event should never crash the loop
            print(f"[ingester] Error processing event: {exc}")


if __name__ == "__main__":
    # Standalone test: run the ingestion loop directly (no FastAPI)
    run_ingestion_loop()
