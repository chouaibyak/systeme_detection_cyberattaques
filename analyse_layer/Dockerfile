FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
ARG MITRE_ATTACK_VERSION=19.1
RUN mkdir -p /app/data && python -c "from urllib.request import urlretrieve; urlretrieve('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v${MITRE_ATTACK_VERSION}/enterprise-attack/enterprise-attack.json', '/app/data/enterprise-attack.json')"
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
