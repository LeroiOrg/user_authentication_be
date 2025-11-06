FROM python:3.11-slim

RUN apt-get update && apt-get install -y netcat-openbsd curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --default-timeout=120 --no-cache-dir -r requirements.txt

COPY . .

COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["bash", "-c", "/wait-for-it.sh db:5432 -- python app/db/migrations/create_tables.py && uvicorn app.main:app --host 0.0.0.0 --port 8080"]
