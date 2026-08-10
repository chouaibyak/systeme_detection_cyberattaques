import time
import requests
import json
import os
import threading

# ================= CONFIGURATION =================
API_URL = "http://fastapi:8000/ingest"

HONEYPOTS_CONFIG = {
    "cowrie": "/var/log/cowrie/cowrie.json",
    "dionaea": "/opt/dionaea/var/lib/dionaea/dionaea.json",
    "honeytrap": "/var/log/honeytrap/honeytrap.json"
}
# =================================================

def monitor_log(source_name, log_path):
    print(f"[*] Démarrage de la surveillance pour {source_name} : {log_path}")

    while not os.path.exists(log_path):
        print(f"[!] {source_name} : Fichier non trouvé. Attente...")
        time.sleep(5)

    try:
        with open(log_path, "r") as f:
            # IMPORTANT: Laisse f.seek(0, 2) commenté pour lire l'historique
            f.seek(0, 2) 
            
            print(f"[+] {source_name} : Lecture du fichier commencée...")

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                try:
                    log_data = json.loads(line)
                    log_data["honeypot_source"] = source_name
                    
                    # ENVOI VERS FASTAPI
                    response = requests.post(API_URL, json=log_data, timeout=5)
                    
                    if response.status_code == 200:
                        # ON AJOUTE CE PRINT POUR VOIR QUE CA MARCHE !
                        print(f"[OK] {source_name} -> Log envoyé avec succès !")
                    else:
                        print(f"[!] {source_name} : Erreur API {response.status_code}")

                except json.JSONDecodeError:
                    print(f"[!] {source_name} : Ligne JSON invalide ignorée.")
                except requests.exceptions.RequestException as e:
                    print(f"[!] {source_name} : Erreur de connexion à FastAPI : {e}")
                    time.sleep(2)
                except Exception as e:
                    print(f"[!] {source_name} : Erreur imprévue : {e}")

    except Exception as e:
        print(f"[CRITICAL] Erreur fatale sur le thread {source_name} : {e}")

if __name__ == "__main__":
    print("--- Multi-Honeypot Shipper (MODE VERBEUX) démarré ---")
    threads = []
    for name, path in HONEYPOTS_CONFIG.items():
        t = threading.Thread(target=monitor_log, args=(name, path))
        t.daemon = True
        threads.append(t)
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du Shipper...")