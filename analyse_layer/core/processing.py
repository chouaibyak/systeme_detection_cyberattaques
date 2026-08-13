from .normalizer import LogNormalizer
from .extractor import FeatureExtractor
from .detector import SentinelML, ThreatDetector

# --- Initialisation des instances globales ---
normalizer = LogNormalizer()
extractor = FeatureExtractor()
ml_engine = SentinelML(contamination=0.1)
threat_detector = ThreatDetector()
memory_logs = [] # Liste pour stocker les logs récents en RAM

def process_log_for_ml(raw_log):
    global memory_logs

    # 1. Normalisation (utilise la classe dans normalizer.py)
    norm = normalizer.normalize(raw_log)
    if not norm: return

    # 2. Gestion de la mémoire
    memory_logs.append(norm)
    if len(memory_logs) > 200: 
        memory_logs.pop(0)

    # 3. Extraction des features (utilise la classe dans extractor.py)
    all_features = extractor.extract_features(memory_logs)

    # 4. Diagnostic IA (utilise la classe dans detector.py)
    ml_verdicts = ml_engine.predict_anomalies(all_features)

    # 5. Analyse finale et Alerte (utilise la classe dans detector.py)
    target_ip = norm["source_ip"]
    if target_ip in all_features:
        v = threat_detector.detect(norm, all_features[target_ip], ml_verdicts.get(target_ip))
        if v["is_alert"]:
            print(f"\n[!!! ALERT !!!] IP: {target_ip} | Score: {v['risk_score']} | Status: {v['status']} | Raisons: {', '.join(v['reasons'])}")
        else:
            print(f"[ML INFO] IP: {target_ip} analysée. Activité normale (Score: {v['risk_score']})")