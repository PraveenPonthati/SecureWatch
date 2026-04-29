"""
metrics.py — FastAPI application that exposes Prometheus metrics.

The /metrics endpoint is scraped by Prometheus every 15 seconds (configured
in prometheus.yml). Grafana then queries Prometheus to render the dashboards.

Architecture:
  mock_logs.py  →  ingester.py  →  detector.py  →  metrics.py (/metrics)
                                                         ↑
                                               Prometheus scrapes here
                                                         ↑
                                                 Grafana queries Prometheus
"""

import threading
import time

from fastapi import FastAPI
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

# ── Prometheus counters ──────────────────────────────────────────────────────
# Counters only go up (they never reset), which is the right model for
# security events — you never want to "uncount" a brute-force attempt.

brute_force_counter = Counter(
    "brute_force_attempts_total",
    "Number of brute-force login attempt clusters detected",
    ["source_ip"],  # label lets Grafana break down by attacker IP
)

offhours_counter = Counter(
    "offhours_api_calls_total",
    "Number of API calls made outside business hours (9-18 IST)",
    ["source_ip"],
)

iam_counter = Counter(
    "iam_changes_total",
    "Number of high-privilege IAM write actions detected",
    ["action"],  # label shows which IAM action was used
)

# ── FastAPI app ──────────────────────────────────────────────────────────────
app = FastAPI(title="SecureWatch Metrics")


@app.get("/metrics")
def metrics():
    """
    Standard Prometheus text exposition format.
    Prometheus scrapes this endpoint; clients should not call it directly.
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/healthz")
def health():
    """Simple liveness probe so docker-compose can confirm the service is up."""
    return {"status": "ok"}


# ── Background ingestion thread ──────────────────────────────────────────────
# We run the log ingestion loop in a daemon thread so the FastAPI server
# stays responsive on the main thread. The thread calls increment() on the
# Prometheus counters; prometheus_client handles thread-safety internally.

def _start_ingestion():
    """Start the log ingestion loop in a background thread."""
    # Import here to avoid circular imports at module level
    from ingester import run_ingestion_loop
    t = threading.Thread(target=run_ingestion_loop, daemon=True, name="ingester")
    t.start()


@app.on_event("startup")
def on_startup():
    """Kick off background ingestion when uvicorn starts."""
    _start_ingestion()
