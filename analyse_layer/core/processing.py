import json
from datetime import datetime
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest

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
            "source_ip": None,
            "dst_port": None,
            "protocol": None,
            "event_type": None,
            "honeypot": source,
            "extra_info": {}
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
# CLASSE : ML(Isolated Forest)
# ==============================================================================

class SentinelML:
    MIN_SAMPLES_FOR_ML = 8

    def __init__(self, contamination=0.1):
        """
        Initialisation du moteur IA.
        contamination : % d'anomalies attendues (ex: 0.1 = 10%)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.is_trained = False

    def predict_anomalies(self, features_by_ip):
        """
        Prend les features extraites par FeatureExtractor et rend un verdict.
        """
        if not features_by_ip:
            return {}

        # 1. Préparation des données (Dictionnaire -> Matrice NumPy)
        ips = list(features_by_ip.keys())
        X = []
        for ip in ips:
            f = features_by_ip[ip]
            # On respecte toujours le même ordre de colonnes pour l'IA
            vector = [
                f["total_events"],
                f["unique_ports"],
                f["login_attempts"],
                f["commands_count"],
                f["unique_protocols"]
            ]
            X.append(vector)

        # Isolation Forest compare plusieurs profils. Avec une seule IP (cas
        # fréquent pendant un test Kali), fit_predict retourne forcément une
        # activité normale. Les règles explicables prennent alors le relais.
        if len(ips) < self.MIN_SAMPLES_FOR_ML:
            return {
                ip: {"is_alert": False, "risk_score": 0.0, "status": "BASELINE INSUFFICIENT"}
                for ip in ips
            }

        X_array = np.array(X)

        # 2. Entraînement et Détection
        # Dans un Honeypot, on peut "re-train" à chaque batch pour s'adapter
        predictions = self.model.fit_predict(X_array)
        
        # 3. Calcul du Score de Risque (basé sur la distance de décision)
        # Isolation Forest : Decision Function renvoie des valeurs négatives pour les anomalies
        scores = self.model.decision_function(X_array)

        results = {}
        for i, ip in enumerate(ips):
            # Normalisation du score sur 100 (plus c'est haut, plus c'est risqué)
            risk_score = round(abs(scores[i]) * 100, 2)

            is_anomaly = True if predictions[i] == -1 else False

            results[ip] = {
                "is_alert": is_anomaly,
                "risk_score": risk_score,
                "status": "ATTACK DETECTED" if is_anomaly else "✅ NORMAL"
            }
        
        return results


class ThreatDetector:
    """Détection hybride : règles comportementales et Isolation Forest."""

    SENSITIVE_COMMANDS = (
        "cat /etc/shadow", "cat /etc/passwd", "wget ", "curl ",
        "chmod +x", "nc ", "ncat ", "bash -i", "python -c",
    )

    def detect(self, log, features, ml_verdict):
        event_type = str(log["event_type"] or "").lower()
        command = str(log["extra_info"].get("input", "")).lower().strip()
        reasons = []

        # Un événement sensible est signalé immédiatement, même sans baseline.
        if any(token in command for token in self.SENSITIVE_COMMANDS):
            reasons.append("commande sensible ou téléchargement détecté")
        if features["login_attempts"] >= 5:
            reasons.append(f"brute force SSH ({features['login_attempts']} tentatives)")
        if features["unique_ports"] >= 5:
            reasons.append(f"scan de ports ({features['unique_ports']} ports distincts)")
        if "login.failed" in event_type and features["login_attempts"] >= 3:
            reasons.append(f"échecs d'authentification répétés ({features['login_attempts']})")
        if ml_verdict and ml_verdict["is_alert"]:
            reasons.append("anomalie statistique (Isolation Forest)")

        if reasons:
            risk_score = min(
                100,
                45 + 15 * len(reasons) + 2 * features["login_attempts"] + 3 * features["unique_ports"],
            )
            return {
                "is_alert": True,
                "risk_score": risk_score,
                "status": "ATTACK DETECTED",
                "reasons": reasons,
            }

        return {
            "is_alert": False,
            "risk_score": ml_verdict["risk_score"] if ml_verdict else 0.0,
            "status": "NORMAL",
            "reasons": [],
        }


# Instances globales pour le conteneur FastAPI
normalizer = LogNormalizer()
extractor = FeatureExtractor()
ml_engine = SentinelML(contamination=0.1) # 10% d'anomalies attendues
threat_detector = ThreatDetector()
memory_logs = [] # Liste pour stocker les logs récents en RAM

def process_log_for_ml(raw_log):
    global memory_logs

    # 1. Normalisation
    norm = normalizer.normalize(raw_log)
    if not norm: return

    # 2. Ajout à la mémoire (on garde les 200 derniers logs pour calculer les stats)
    memory_logs.append(norm)
    if len(memory_logs) > 200: memory_logs.pop(0)

    # 3. Extraction des features par IP
    all_features = extractor.extract_features(memory_logs)

    # 4. Diagnostic IA
    ml_verdicts = ml_engine.predict_anomalies(all_features)

    # 5. Affichage du résultat dans les logs Docker
    target_ip = norm["source_ip"]
    if target_ip in all_features:
        v = threat_detector.detect(norm, all_features[target_ip], ml_verdicts.get(target_ip))
        if v["is_alert"]:
            print(f"\n[!!! ALERT !!!] IP: {target_ip} | Score: {v['risk_score']} | Status: {v['status']} | Raisons: {', '.join(v['reasons'])}")
        else:
            print(f"[ML INFO] IP: {target_ip} analysée. Activité normale (Score: {v['risk_score']})")
