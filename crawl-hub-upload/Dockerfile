FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
RUN mkdir -p /tmp/crawlhub-data && chmod -R 777 /tmp/crawlhub-data

ENV DB_PATH=/tmp/crawlhub-data/crawlhub.db
ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-7860} --proxy-headers"]
