# SENTINEL Ultimate - Production Docker Image
# Multi-stage build for minimal attack surface

# Build stage
FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage
FROM python:3.13-slim AS runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r sentinel --gid 1000 \
    && useradd -r -g sentinel --uid 1000 --home-dir /app --shell /bin/false sentinel

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=sentinel:sentinel sentinel/ ./sentinel/
COPY --chown=sentinel:sentinel config/ ./config/
COPY --chown=sentinel:sentinel crypto/ ./crypto/
COPY --chown=sentinel:sentinel layer2/ ./layer2/
COPY --chown=sentinel:sentinel layer3/ ./layer3/

# Environment
ENV PATH="${PATH}"
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Security hardening
RUN mkdir -p /app/data /app/logs /app/tmp \
    && chown -R sentinel:sentinel /app/data /app/logs /app/tmp \
    && chmod 700 /app/data /app/logs /app/tmp

# Non-root user
USER sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1

# Expose port
EXPOSE 8080

# Run
CMD ["python", "-m", "sentinel"]