import time
import requests
import json
import os
import threading

# ================= CONFIGURATION =================
API_URL = "http://fastapi:8000/ingest"

# Liste des honeypots à surveiller
# Format: "nom_du_honeypot": "chemin_du_fichier_log"
HONEYPOTS_CONFIG = {
    "cowrie": "/var/log/cowrie/cowrie.json",
    "dionaea": "/opt/dionaea/var/lib/dionaea/dionaea.json",
    "honeytrap": "/var/log/honeytrap/honeytrap.json"
}
# =================================================

def monitor_log(source_name, log_path):
    """
    Fonction exécutée par chaque thread pour surveiller un fichier spécifique.
    """
    print(f"[*] Démarrage de la surveillance pour {source_name} : {log_path}")

    # 1. Attendre que le fichier existe (au cas où Docker met du temps à monter les volumes)
    while not os.path.exists(log_path):
        print(f"[!] {source_name} : Fichier non trouvé. Attente...")
        time.sleep(5)

    try:
        with open(log_path, "r") as f:
            # Se placer à la fin du fichier pour ne pas renvoyer les vieux logs
            f.seek(0, 2) 
            print(f"[+] {source_name} : Lecture en cours...")

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1) # Pause courte pour ne pas saturer le CPU
                    continue
                
                try:
                    # Parsing du log JSON
                    log_data = json.loads(line)
                    
                    # AJOUT DE LA SOURCE : Indique à FastAPI quel honeypot a généré ce log
                    log_data["honeypot_source"] = source_name
                    
                    # Envoi vers FastAPI
                    response = requests.post(API_URL, json=log_data, timeout=5)
                    
                    if response.status_code == 200:
                        # Succès
                        pass 
                    else:
                        print(f"[!] {source_name} : Erreur API {response.status_code}")

                except json.JSONDecodeError:
                    print(f"[!] {source_name} : Ligne JSON invalide ignorée.")
                except requests.exceptions.RequestException as e:
                    print(f"[!] {source_name} : Erreur de connexion à FastAPI : {e}")
                    time.sleep(2) # Pause pour éviter de spammer en cas de crash API

    except Exception as e:
        print(f"[CRITICAL] Erreur fatale sur le thread {source_name} : {e}")

if __name__ == "__main__":
    print("--- Multi-Honeypot Shipper démarré ---")
    
    threads = []

    # Création d'un thread pour chaque honeypot configuré
    for name, path in HONEYPOTS_CONFIG.items():
        t = threading.Thread(target=monitor_log, args=(name, path))
        t.daemon = True  # Le thread s'arrête si le programme principal s'arrête
        threads.append(t)
        t.start()

    # Maintenir le programme principal en vie
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du Shipper...")