# nmap_service Dockerfile
FROM python:3.11-slim

# Cài nmap và các tool cần thiết
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY .

# Railway sẽ inject PORT
CMD ["sh", "-c", "uvicorn nmap_flowise:app --host 0.0.0.0 --port ${PORT} --reload"]
