from .normalizer import LogNormalizer
from .extractor import FeatureExtractor
from .detector import SentinelML, ThreatDetector
from .mitre_analyzer import MitreAnalyzer
from services.elastic_service import get_recent_logs # <--- Importation du nouveau service

# Instances globales
normalizer = LogNormalizer()
extractor = FeatureExtractor()
ml_engine = SentinelML(contamination=0.1)
threat_detector = ThreatDetector()
mitre_analyzer = MitreAnalyzer()

async def process_log_for_ml(raw_log):
    # 1. Normalisation du log actuel
    norm = normalizer.normalize(raw_log)
    if not norm:
        return

    # 2. RÉSOLUTION DU PROBLÈME DE MÉMOIRE
    # Au lieu d'une liste en RAM, on récupère l'historique récent depuis Elasticsearch
    # On récupère les 500 derniers logs pour avoir une baseline statistique solide
    historical_raw_logs = await get_recent_logs(limit=500)
    
    # On normalise tous les logs récupérés d'Elasticsearch
    normalized_history = []
    for raw in historical_raw_logs:
        n = normalizer.normalize(raw)
        if n: normalized_history.append(n)
    
    # On ajoute le log actuel à l'histoire pour l'analyse
    normalized_history.append(norm)

    # 3. Extraction des features sur l'historique complet
    all_features = extractor.extract_features(normalized_history)

    # 4. Diagnostic IA
    ml_verdicts = ml_engine.predict_anomalies(all_features)

    # 5. Affichage du résultat
    target_ip = norm["source_ip"]
    if target_ip in all_features:
        v = threat_detector.detect(norm, all_features[target_ip], ml_verdicts.get(target_ip))
        raw_log["analysis"] = {"ml": v, "features": all_features[target_ip]}

        # Le mapping ATT&CK enrichit tous les événements. Il reste donc
        # visible pendant la phase de baseline, même si le ML ne déclenche
        # pas encore d'alerte.
        mitre_info = mitre_analyzer.map_log_to_mitre(norm)
        if mitre_info:
            raw_log["analysis"]["mitre_attack"] = mitre_info

        if v["is_alert"]:
            print(f"\n[!!! ALERTE SÉCURITÉ !!!]")
            print(f"IP Attaquante : {target_ip}")
            if mitre_info:
                print(f"Type d'Attaque : {mitre_info['name']}")
                print(f"Phase (Tactique) : {mitre_info['tactic']}")
                print(f"Explication : {mitre_info['description']}")
                print(f"Conseil : {mitre_info['advice']}")
            print(f"Score de risque : {v['risk_score']}/100")
        return raw_log["analysis"]
