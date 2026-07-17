FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*

# sadece agent scripti / dependency yok
COPY agent.py .

CMD ["python", "-u", "agent.py"]



