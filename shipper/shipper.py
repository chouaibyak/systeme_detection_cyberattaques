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

def send_log(source_name, log_data):
    """Envoie un événement sans le perdre si l'API redémarre."""
    log_data["honeypot_source"] = source_name
    while True:
        try:
            response = requests.post(API_URL, json=log_data, timeout=5)
            response.raise_for_status()
            print(f"[OK] {source_name} -> Log envoyé avec succès !")
            return
        except requests.exceptions.RequestException as error:
            print(f"[!] {source_name} : API indisponible ({error}), nouvel essai dans 2 s.")
            time.sleep(2)


def is_security_event(source_name, log_data):
    """Ignore les événements de service qui ne décrivent pas une connexion."""
    if source_name == "honeytrap":
        # Honeytrap emits a heartbeat every 30 seconds.  Indexing these events
        # floods Elasticsearch and makes the ML baseline meaningless.
        return log_data.get("category") != "heartbeat" and bool(
            log_data.get("source-ip") or log_data.get("source.ip") or log_data.get("src_ip")
        )
    return True


def monitor_log(source_name, log_path):
    print(f"[*] Démarrage de la surveillance pour {source_name} : {log_path}")

    while not os.path.exists(log_path):
        print(f"[!] {source_name} : Fichier non trouvé. Attente...")
        time.sleep(5)

    try:
        with open(log_path, "r") as f:
            # Le service ne rejoue pas l'historique à chaque redémarrage.
            f.seek(0, 2)
            
            print(f"[+] {source_name} : Lecture du fichier commencée...")

            while True:
                line = f.readline()
                if not line:
                    # Cowrie effectue une rotation quotidienne : reprendre le
                    # nouveau cowrie.json plutôt que rester attaché à l'ancien.
                    try:
                        if os.stat(log_path).st_ino != os.fstat(f.fileno()).st_ino:
                            print(f"[*] {source_name} : rotation détectée, réouverture du journal.")
                            return monitor_log(source_name, log_path)
                    except FileNotFoundError:
                        pass
                    time.sleep(0.1)
                    continue
                
                try:
                    log_data = json.loads(line)
                    if is_security_event(source_name, log_data):
                        send_log(source_name, log_data)
                    else:
                        print(f"[-] {source_name} : événement technique ignoré.")

                except json.JSONDecodeError:
                    print(f"[!] {source_name} : Ligne JSON invalide ignorée.")
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
