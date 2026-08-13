import numpy as np
from sklearn.ensemble import IsolationForest
from .classifier import AttackClassifier


class SentinelML:
    MIN_SAMPLES_FOR_ML = 8

    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.is_trained = False

    def predict_anomalies(self, features_by_ip):
        if not features_by_ip: return {}

        ips = list(features_by_ip.keys())
        X = []
        for ip in ips:
            f = features_by_ip[ip]
            # MISE À JOUR : On utilise danger_score ici
            vector = [
                f["total_events"],
                f["unique_ports"],
                f["login_attempts"],
                f["danger_score"], # <--- Changement ici
                f["unique_protocols"]
            ]
            X.append(vector)

        if len(ips) < self.MIN_SAMPLES_FOR_ML:
            return {ip: {"is_alert": False, "risk_score": 0.0, "status": "BASELINE INSUFFICIENT"} for ip in ips}

        X_array = np.array(X)
        predictions = self.model.fit_predict(X_array)
        scores = self.model.decision_function(X_array)

        results = {}
        for i, ip in enumerate(ips):
            risk_score = round(abs(scores[i]) * 100, 2)
            is_anomaly = True if predictions[i] == -1 else False
            results[ip] = {
                "is_alert": is_anomaly,
                "risk_score": risk_score,
                "status": "ATTACK DETECTED" if is_anomaly else "✅ NORMAL"
            }
        return results

class ThreatDetector:
    def __init__(self):
        self.classifier = AttackClassifier() # On intègre le nouveau module

    def detect(self, log, features, ml_verdict):
        # 1. On demande au module de classification de nommer l'attaque
        attack_categories = self.classifier.classify(features, log["extra_info"])
        
        reasons = []
        
        # 2. On construit les raisons de l'alerte
        for category in attack_categories:
            reasons.append(category)
            
        if ml_verdict and ml_verdict["is_alert"]:
            reasons.append("anomalie statistique (Isolation Forest)")

        # 3. Décision finale : Est-ce une alerte ?
        # On déclenche l'alerte si l'IA a vu une anomalie OU si on a des catégories d'attaque
        is_alert = ml_verdict["is_alert"] if ml_verdict else False
        # On force l'alerte si on a détecté une catégorie d'attaque critique
        if len(attack_categories) > 0 and "Unspecified Anomaly" not in attack_categories:
            is_alert = True

        if is_alert:
            # Calcul du score de risque basé sur la gravité des catégories
            risk_score = min(100, 50 + (len(attack_categories) * 10))
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