import json
from datetime import datetime
from collections import defaultdict

class LogNormalizer:
    def __init__(self):
        self.mappings = {
            "cowrie": {"source_ip": "src_ip", "dst_port": "dst_port", "protocol": "protocol", "event_type": "eventid"},
            "dionaea": {"source_ip": "src_ip", "dst_port": "dst_port", "protocol": "connection.protocol", "event_type": "connection.type"},
            "honeytrap": {"source_ip": "source-ip", "dst_port": "destination-port", "protocol": "category", "event_type": "type"}
        }
        self.whitelists = {
            "cowrie": ["username", "password", "input", "session", "hassh"],
            "dionaea": ["credentials", "transport", "file_hash", "src_port"],
            "honeytrap": ["http.url", "http.method", "http.header.user-agent", "token"]
        }

    def _get_nested_value(self, data, key_path):
        keys = key_path.split('.')
        for k in keys:
            if isinstance(data, dict): data = data.get(k)
            else: return None
        return data

    def normalize(self, raw_log):
        source = raw_log.get("honeypot_source", "unknown")
        if source not in self.mappings: return None
        mapping = self.mappings[source]
        whitelist = self.whitelists.get(source, [])
        normalized = {
            "timestamp": raw_log.get("timestamp") or raw_log.get("date") or datetime.now().isoformat(),
            "source_ip": None, "dst_port": None, "protocol": None, "event_type": None,
            "honeypot": source, "extra_info": {}
        }
        for std_key, raw_key in mapping.items():
            val = self._get_nested_value(raw_log, raw_key) if '.' in raw_key else raw_log.get(raw_key)
            normalized[std_key] = val
        for field in whitelist:
            val = self._get_nested_value(raw_log, field) if '.' in field else raw_log.get(field)
            if val is not None: normalized["extra_info"][field] = val
        return normalized

# ==============================================================================
# CLASSE : FeatureExtractor
# ==============================================================================
class FeatureExtractor:
    def extract_features(self, normalized_logs):
        """
        Transforme une liste de logs normalisés en un dictionnaire de features par IP.
        """
        # 1. Groupement des logs par IP source
        sessions = defaultdict(list)
        for log in normalized_logs:
            if log and log["source_ip"]:
                sessions[log["source_ip"]].append(log)

        features_by_ip = {}

        for ip, logs in sessions.items():
            # --- CALCUL DES FEATURES NUMÉRIQUES ---
            
            # Feature 1 : Nombre total d'événements (Volume)
            total_events = len(logs)

            # Feature 2 : Nombre de ports distincts ciblés (Scanning)
            unique_ports = len(set([l["dst_port"] for l in logs if l["dst_port"]]))

            # Feature 3 : Nombre de tentatives de login (Brute Force)
            # On compte les événements de type login ou la présence de passwords
            login_attempts = sum(1 for l in logs if "login" in str(l["event_type"]).lower() or "password" in l["extra_info"])

            # Feature 4 : Nombre de commandes exécutées (Post-Exploitation)
            commands_count = sum(1 for l in logs if "input" in l["extra_info"])

            # Feature 5 : Diversité des protocoles utilisés
            unique_protocols = len(set([l["protocol"] for l in logs if l["protocol"]]))

            # On assemble le vecteur final pour l'IP
            features_by_ip[ip] = {
                "total_events": total_events,
                "unique_ports": unique_ports,
                "login_attempts": login_attempts,
                "commands_count": commands_count,
                "unique_protocols": unique_protocols
            }

        return features_by_ip

# ==============================================================================
# TEST COMPLET (Normalisation -> Extraction)
# ==============================================================================
if __name__ == "__main__":
    # 1. Simulation d'un dataset de logs bruts (mélange de sources)
    raw_dataset = [
        # Attaquant 1 : Brute Force SSH (Beaucoup de tentatives, 1 port)
        {"src_ip": "1.1.1.1", "dst_port": 2222, "protocol": "ssh", "eventid": "login.failed", "password": "123", "honeypot_source": "cowrie"},
        {"src_ip": "1.1.1.1", "dst_port": 2222, "protocol": "ssh", "eventid": "login.failed", "password": "456", "honeypot_source": "cowrie"},
        {"src_ip": "1.1.1.1", "dst_port": 2222, "protocol": "ssh", "eventid": "login.failed", "password": "789", "honeypot_source": "cowrie"},
        
        # Attaquant 2 : Scanner de ports (Peu d'événements, beaucoup de ports)
        {"source-ip": "2.2.2.2", "destination-port": 80, "category": "http", "type": "connect", "honeypot_source": "honeytrap"},
        {"source-ip": "2.2.2.2", "destination-port": 443, "category": "https", "type": "connect", "honeypot_source": "honeytrap"},
        {"source-ip": "2.2.2.2", "destination-port": 5900, "category": "vnc", "type": "connect", "honeypot_source": "honeytrap"},
        
        # Attaquant 3 : Interaction riche (Dionaea + commandes)
        {"src_ip": "3.3.3.3", "dst_port": 445, "connection": {"protocol": "smbd", "type": "accept"}, "honeypot_source": "dionaea"},
        {"src_ip": "3.3.3.3", "dst_port": 2222, "protocol": "ssh", "eventid": "command", "input": "whoami", "honeypot_source": "cowrie"},
        {"src_ip": "3.3.3.3", "dst_port": 2222, "protocol": "ssh", "eventid": "command", "input": "ls -la", "honeypot_source": "cowrie"},
    ]

    # --- ÉTAPE 1 : Normalisation ---
    normalizer = LogNormalizer()
    normalized_logs = [normalizer.normalize(log) for log in raw_dataset]

    # --- ÉTAPE 2 : Extraction de Features ---
    extractor = FeatureExtractor()
    final_features = extractor.extract_features(normalized_logs)

    print("--- RÉSULTAT FINAL : VECTEURS POUR L'IA ---")
    for ip, feats in final_features.items():
        print(f"\nIP: {ip} -> Features: {feats}")
