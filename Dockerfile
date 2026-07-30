FROM python:3.11-slim

WORKDIR /app

# Install system build deps (needed for psycopg2 / cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy NER model (optional — comment out if not using spaCy)
RUN python -m spacy download en_core_web_sm || echo "spaCy model download skipped"

# Copy application source
COPY . .

# Expose API port
EXPOSE 8000

# Docker health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run with multiple Uvicorn workers for concurrent request handling
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--log-level", "info"]
