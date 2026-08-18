import asyncio
import logging
from threading import Lock

from .normalizer import LogNormalizer
from .extractor import FeatureExtractor
from .detector import SentinelML, ThreatDetector
from .mitre_analyzer import MitreAnalyzer
from .cyberdna_contract import CyberDNAAlertFactory
from services.elastic_service import get_recent_logs # <--- Importation du nouveau service
from investigation_layer.core.graph_builder import CyberDNAGraphBuilder
from investigation_layer.services.neo4j_service import Neo4jService


logger = logging.getLogger(__name__)

# Instances globales
normalizer = LogNormalizer()
extractor = FeatureExtractor()
ml_engine = SentinelML(contamination=0.1)
threat_detector = ThreatDetector()
mitre_analyzer = MitreAnalyzer()
cyberdna_alert_factory = CyberDNAAlertFactory()
neo4j_service = Neo4jService()
graph_builder = CyberDNAGraphBuilder(neo4j_service)
neo4j_schema_ready = False
neo4j_schema_lock = Lock()


def close_neo4j():
    """Libere le driver Neo4j si une connexion a ete ouverte."""
    neo4j_service.close()


def persist_cyberdna_alert(cyberdna_alert):
    """Projection best-effort : une indisponibilite Neo4j ne bloque pas ES."""
    global neo4j_schema_ready
    try:
        with neo4j_schema_lock:
            if not neo4j_schema_ready:
                graph_builder.initialise_schema()
                neo4j_schema_ready = True
        graph_builder.ingest_alert(cyberdna_alert)
    except Exception:
        logger.exception(
            "Echec de projection CyberDNA vers Neo4j pour l'alerte %s",
            cyberdna_alert.get("alert_id", "unknown"),
        )

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
            # Le contrat reste attache au log pour Elasticsearch, puis est
            # projete vers Neo4j comme destination d'investigation secondaire.
            cyberdna_alert = cyberdna_alert_factory.build(
                norm, v, all_features[target_ip], mitre_info, raw_log
            )
            raw_log["analysis"]["cyberdna_alert"] = (
                cyberdna_alert.model_dump(exclude_none=True)
                if hasattr(cyberdna_alert, "model_dump")
                else cyberdna_alert.dict(exclude_none=True)
            )
            # Neo4j ne doit pas retarder l'indexation Elasticsearch suivante.
            # L'erreur est capturee dans persist_cyberdna_alert.
            asyncio.create_task(
                asyncio.to_thread(persist_cyberdna_alert, raw_log["analysis"]["cyberdna_alert"])
            )
            print(f"\n[!!! ALERTE SÉCURITÉ !!!]")
            print(f"IP Attaquante : {target_ip}")
            if mitre_info:
                print(f"Type d'Attaque : {mitre_info['name']}")
                print(f"Phase (Tactique) : {mitre_info['tactic']}")
                print(f"Explication : {mitre_info['description']}")
                print(f"Conseil : {mitre_info['advice']}")
            print(f"Score de risque : {v['risk_score']}/100")
        return raw_log["analysis"]
