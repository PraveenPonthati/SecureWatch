# Use a slim Python 3.12 base to keep the image small
FROM python:3.12-slim

# Set working directory inside the container
WORKDIR /app

# Copy dependency list first — Docker caches this layer separately.
# If only source files change, pip install is skipped on rebuild.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application source files
COPY mock_logs.py ingester.py detector.py metrics.py ./

# Expose the port uvicorn will listen on
EXPOSE 8000

# Start the FastAPI server.
# --host 0.0.0.0 is required so Prometheus can reach the container.
CMD ["uvicorn", "metrics:app", "--host", "0.0.0.0", "--port", "8000"]
