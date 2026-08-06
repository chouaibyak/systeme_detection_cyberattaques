import time
import requests
import json
import os

# Configuration
LOG_FILE = "/var/log/cowrie/cowrie.json"
API_URL = "http://fastapi:8000/ingest"

print("Shipper Python démarré...")

# Attendre que le fichier existe
while not os.path.exists(LOG_FILE):
    time.sleep(2)

with open(LOG_FILE, "r") as f:
    f.seek(0, 2) # Se placer à la fin du fichier
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        try:
            log_data = json.loads(line)
            requests.post(API_URL, json=log_data)
        except Exception as e:
            print(f"Erreur d'envoi : {e}")