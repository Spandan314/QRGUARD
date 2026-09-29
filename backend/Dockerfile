# QRGUARD backend image. Works on Render, Railway, Fly.io or any Docker host.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Tesseract OCR is a system program, not a pip package (used from Phase 3 onwards).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first so Docker can cache this layer between code changes.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Never run the web server as root.
RUN useradd --create-home --uid 10001 appuser
USER appuser

ENV APP_ENV=production
EXPOSE 5000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
