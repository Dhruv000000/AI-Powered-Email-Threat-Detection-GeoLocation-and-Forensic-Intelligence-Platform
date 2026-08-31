FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/backend

# Set Python Path
ENV PYTHONPATH=/app

# Create non-root user for security
RUN useradd -m -u 1000 dfiruser && \
    mkdir -p /app/backend/storage /app/backend/ml/models && \
    chown -R dfiruser:dfiruser /app

USER dfiruser

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
