import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class SentinelML:
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    def predict_anomalies(self, features_by_ip):
        if len(features_by_ip) < 2:
            # Mode Labo : Si une seule IP, on simule une baseline normale
            # pour que l'IA puisse comparer l'IP actuelle à "quelque chose"
            baseline = [1, 1, 0, 0, 1, 0.1, 10] # Un utilisateur normal type
            X = [baseline]
        else:
            X = []

        ips = list(features_by_ip.keys())
        for ip in ips:
            f = features_by_ip[ip]
            X.append([
                f["total_events"],
                f["unique_ports"],
                f["login_attempts"],
                f["danger_score"],
                f["unique_protocols"],
                f["eps"],
                f["iat"]
            ])

        X_array = np.array(X)
        
        # 1. NORMALISATION : Indispensable pour que l'IA comprenne les petites variations
        X_scaled = self.scaler.fit_transform(X_array)

        # 2. ENTRAÎNEMENT ET PRÉDICTION
        self.model.fit(X_scaled)
        predictions = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        results = {}
        # On ignore le premier index si on a ajouté la baseline manuelle
        offset = 1 if len(features_by_ip) < 2 else 0
        
        for i, ip in enumerate(ips):
            idx = i + offset
            # Un score très bas (négatif) = Anomalie forte
            risk_score = round(abs(scores[idx]) * 100, 2)
            
            # CRITÈRES D'ALERTE : ML ou Seuil de sécurité critique (Hydra)
            is_anomaly = predictions[idx] == -1
            
            # Sécurité supplémentaire pour Hydra (Heuristique)
            if features_by_ip[ip]["login_attempts"] > 10 or features_by_ip[ip]["eps"] > 15:
                is_anomaly = True
                risk_score = max(risk_score, 85.0)

            results[ip] = {
                "is_alert": is_anomaly,
                "risk_score": risk_score,
                "status": "ATTACK DETECTED" if is_anomaly else "NORMAL"
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
