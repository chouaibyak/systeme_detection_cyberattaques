import numpy as np
from sklearn.ensemble import IsolationForest


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
                f["danger_score"], 
                f["unique_protocols"],
                f["eps"], 
                f["iat"]
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
    def detect(self, log, features, ml_verdict):
        """Retourne uniquement le verdict du détecteur d'anomalies ML."""
        if ml_verdict and ml_verdict["is_alert"]:
            return {
                "is_alert": True,
                "risk_score": ml_verdict["risk_score"],
                "status": ml_verdict["status"],
                "reasons": ["anomalie statistique (Isolation Forest)"],
            }

        return {
            "is_alert": False,
            "risk_score": ml_verdict["risk_score"] if ml_verdict else 0.0,
            "status": "NORMAL",
            "reasons": [],
        }
