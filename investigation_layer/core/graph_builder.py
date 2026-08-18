"""Projection du contrat CyberDNA vers le graphe d'investigation Neo4j."""

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Dict, List


CONSTRAINTS = (
    "CREATE CONSTRAINT attacker_ip_unique IF NOT EXISTS FOR (n:Attacker) REQUIRE n.ip IS UNIQUE",
    "CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (n:Alert) REQUIRE n.alert_id IS UNIQUE",
    "CREATE CONSTRAINT target_asset_id_unique IF NOT EXISTS FOR (n:Target) REQUIRE n.asset_id IS UNIQUE",
    "CREATE CONSTRAINT service_key_unique IF NOT EXISTS FOR (n:Service) REQUIRE n.service_key IS UNIQUE",
    "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS FOR (n:Technique) REQUIRE n.technique_id IS UNIQUE",
    "CREATE CONSTRAINT tactic_name_unique IF NOT EXISTS FOR (n:Tactic) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT evidence_id_unique IF NOT EXISTS FOR (n:Evidence) REQUIRE n.evidence_id IS UNIQUE",
)

WRITE_GRAPH = """
MERGE (attacker:Attacker {ip: $attacker.ip})
MERGE (alert:Alert {alert_id: $alert.alert_id})
SET alert.event_id = $alert.event_id, alert.timestamp = datetime($alert.timestamp),
    alert.generated_at = datetime($alert.generated_at), alert.status = $alert.status,
    alert.risk_score = $alert.risk_score, alert.detector = $alert.detector,
    alert.reasons = $alert.reasons, alert.feature_snapshot_json = $alert.feature_snapshot_json,
    alert.correlation_key = $alert.correlation_key, alert.schema_version = $alert.schema_version
MERGE (attacker)-[:TRIGGERED]->(alert)
MERGE (target:Target {asset_id: $target.asset_id})
SET target.honeypot = $target.honeypot, target.ip = $target.ip
MERGE (alert)-[:TARGETS]->(target)
MERGE (service:Service {service_key: $service.service_key})
SET service.name = $service.name, service.port = $service.port, service.protocol = $service.protocol
MERGE (target)-[:EXPOSES]->(service)
WITH alert
UNWIND $techniques AS technique_row
MERGE (technique:Technique {technique_id: technique_row.technique_id})
SET technique.name = technique_row.name, technique.description = technique_row.description,
    technique.advice = technique_row.advice
MERGE (tactic:Tactic {name: technique_row.tactic})
MERGE (alert)-[:USES_TECHNIQUE]->(technique)
MERGE (technique)-[:BELONGS_TO]->(tactic)
WITH alert
UNWIND $evidence AS evidence_row
MERGE (evidence:Evidence {evidence_id: evidence_row.evidence_id})
SET evidence.field = evidence_row.field, evidence.value_json = evidence_row.value_json,
    evidence.is_redacted = evidence_row.is_redacted
MERGE (alert)-[:HAS_EVIDENCE]->(evidence)
RETURN alert.alert_id AS alert_id
"""

CORRELATE_ALERTS = """
MATCH (alert:Alert {alert_id: $alert_id})
MATCH (other:Alert {correlation_key: $correlation_key})
WHERE other.alert_id <> alert.alert_id
MERGE (other)-[:CORRELATED_WITH]->(alert)
RETURN count(other) AS correlated_count
"""

HISTORY_BY_IP = """
MATCH (attacker:Attacker {ip: $ip})-[:TRIGGERED]->(alert:Alert)
OPTIONAL MATCH (alert)-[:TARGETS]->(target:Target)-[:EXPOSES]->(service:Service)
RETURN alert.alert_id AS alert_id, alert.event_id AS event_id, alert.timestamp AS timestamp,
       alert.status AS status, alert.risk_score AS risk_score, target.asset_id AS target_asset_id,
       service.service_key AS service_key ORDER BY timestamp DESC
"""
TECHNIQUES_BY_IP = """
MATCH (:Attacker {ip: $ip})-[:TRIGGERED]->(:Alert)-[:USES_TECHNIQUE]->(technique:Technique)-[:BELONGS_TO]->(tactic:Tactic)
RETURN DISTINCT technique.technique_id AS technique_id, technique.name AS name, tactic.name AS tactic ORDER BY technique_id
"""
SERVICES_BY_IP = """
MATCH (:Attacker {ip: $ip})-[:TRIGGERED]->(:Alert)-[:TARGETS]->(:Target)-[:EXPOSES]->(service:Service)
RETURN DISTINCT service.service_key AS service_key, service.name AS name, service.port AS port,
       service.protocol AS protocol ORDER BY service_key
"""
EVIDENCE_BY_ALERT = """
MATCH (:Alert {alert_id: $alert_id})-[:HAS_EVIDENCE]->(evidence:Evidence)
RETURN evidence.evidence_id AS evidence_id, evidence.field AS field, evidence.value_json AS value_json,
       evidence.is_redacted AS is_redacted ORDER BY evidence.field
"""
CORRELATED_ALERTS = """
MATCH (alert:Alert {alert_id: $alert_id})-[:CORRELATED_WITH]-(related:Alert)
RETURN related.alert_id AS alert_id, related.timestamp AS timestamp, related.status AS status,
       related.risk_score AS risk_score ORDER BY timestamp DESC
"""

# Une seule lecture pour le contexte destine a une investigation. Les sous-requetes
# evitent le produit cartesien entre alertes, cibles, techniques et preuves.
INVESTIGATION_CONTEXT = """
MATCH (attacker:Attacker {ip: $source_ip})-[:TRIGGERED]->(alert:Alert {alert_id: $alert_id})
CALL {
    WITH attacker
    MATCH (attacker)-[:TRIGGERED]->(related:Alert)
    RETURN collect({
        alert_id: related.alert_id, event_id: related.event_id, timestamp: related.timestamp,
        generated_at: related.generated_at, status: related.status, risk_score: related.risk_score,
        detector: related.detector, reasons: related.reasons, correlation_key: related.correlation_key
    }) AS alerts
}
CALL {
    WITH attacker
    OPTIONAL MATCH (attacker)-[:TRIGGERED]->(:Alert)-[:TARGETS]->(target:Target)
    RETURN [item IN collect(DISTINCT {
        asset_id: target.asset_id, honeypot: target.honeypot, ip: target.ip
    }) WHERE item.asset_id IS NOT NULL] AS targets
}
CALL {
    WITH attacker
    OPTIONAL MATCH (attacker)-[:TRIGGERED]->(:Alert)-[:TARGETS]->(:Target)-[:EXPOSES]->(service:Service)
    RETURN [item IN collect(DISTINCT {
        service_key: service.service_key, name: service.name, port: service.port, protocol: service.protocol
    }) WHERE item.service_key IS NOT NULL] AS services
}
CALL {
    WITH attacker
    OPTIONAL MATCH (attacker)-[:TRIGGERED]->(:Alert)-[:USES_TECHNIQUE]->(technique:Technique)-[:BELONGS_TO]->(tactic:Tactic)
    RETURN [item IN collect(DISTINCT {
        technique_id: technique.technique_id, name: technique.name, description: technique.description,
        advice: technique.advice, tactic: tactic.name
    }) WHERE item.technique_id IS NOT NULL] AS techniques,
    [item IN collect(DISTINCT {name: tactic.name}) WHERE item.name IS NOT NULL] AS tactics
}
CALL {
    WITH alert
    OPTIONAL MATCH (alert)-[:HAS_EVIDENCE]->(evidence:Evidence)
    RETURN [item IN collect({
        evidence_id: evidence.evidence_id, field: evidence.field, value_json: evidence.value_json,
        is_redacted: evidence.is_redacted
    }) WHERE item.evidence_id IS NOT NULL] AS evidence
}
CALL {
    WITH alert
    OPTIONAL MATCH (alert)-[:CORRELATED_WITH]-(related:Alert)
    RETURN [item IN collect(DISTINCT {
        alert_id: related.alert_id, event_id: related.event_id, timestamp: related.timestamp,
        status: related.status, risk_score: related.risk_score, correlation_key: related.correlation_key
    }) WHERE item.alert_id IS NOT NULL] AS correlations
}
RETURN {ip: attacker.ip} AS attacker, alerts, targets, services, techniques, tactics, evidence, correlations
"""


@dataclass
class InvestigationContext:
    attacker: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    targets: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    techniques: List[Dict[str, Any]]
    tactics: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    correlations: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]

    @staticmethod
    def _serializable(value: Any) -> Any:
        """Convertit aussi les DateTime Neo4j en valeurs JSON sans modifier les donnees."""
        if isinstance(value, dict):
            return {key: InvestigationContext._serializable(item) for key, item in value.items()}
        if isinstance(value, list):
            return [InvestigationContext._serializable(item) for item in value]
        if hasattr(value, "isoformat"):
            return value.isoformat()
        if hasattr(value, "iso_format"):  # type DateTime du pilote Neo4j
            return value.iso_format()
        return value

    def to_dict(self) -> Dict[str, Any]:
        """Representation JSON-ready, stable pour le futur consommateur LLM."""
        return self._serializable({
            "attacker": self.attacker,
            "alerts": self.alerts,
            "targets": self.targets,
            "services": self.services,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "evidence": self.evidence,
            "correlations": self.correlations,
            "timeline": self.timeline,
        })


class CyberDNAGraphBuilder:
    """Construit le graphe a partir du seul objet `analysis.cyberdna_alert`."""

    def __init__(self, neo4j_service):
        self.neo4j = neo4j_service

    def initialise_schema(self) -> None:
        self.neo4j.ensure_constraints(CONSTRAINTS)

    @staticmethod
    def _evidence_id(alert_id: str, field: str, value: Any) -> str:
        payload = json.dumps([alert_id, field, value], sort_keys=True, default=str, separators=(",", ":"))
        return "evidence-" + sha256(payload.encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _service_key(target: Dict[str, Any]) -> str:
        endpoint = target.get("endpoint") or {}
        return "|".join((str(target["asset_id"]), str(endpoint.get("protocol") or "unknown").lower(),
                         str(endpoint.get("port") if endpoint.get("port") is not None else "unknown")))

    @staticmethod
    def _isoformat(value: Any) -> str:
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    def _parameters(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        action, target, detection = alert["action"], alert["action"]["target"], alert["detection"]
        endpoint = target.get("endpoint") or {}
        techniques = [{"technique_id": t["technique_id"], "name": t["name"], "tactic": t["tactic"],
                       "description": t.get("description"), "advice": t.get("advice")}
                      for t in alert.get("mitre_techniques", [])]
        evidence = [{"evidence_id": self._evidence_id(alert["alert_id"], field, value), "field": field,
                     "value_json": json.dumps(value, sort_keys=True, default=str), "is_redacted": value == "<redacted>"}
                    for field, value in (action.get("evidence") or {}).items()]
        return {
            "attacker": {"ip": action["source"]["ip"]},
            "alert": {"alert_id": alert["alert_id"], "event_id": action["event_id"],
                      "timestamp": self._isoformat(action["timestamp"]),
                      "generated_at": self._isoformat(alert["generated_at"]), "status": detection["status"],
                      "risk_score": detection["risk_score"], "detector": detection["detector"],
                      "reasons": detection.get("reasons", []),
                      "feature_snapshot_json": json.dumps(detection.get("feature_snapshot", {}), sort_keys=True),
                      "correlation_key": alert["correlation"]["correlation_key"], "schema_version": alert["schema_version"]},
            "target": {"asset_id": target["asset_id"], "honeypot": target["honeypot"], "ip": endpoint.get("ip")},
            "service": {"service_key": self._service_key(target), "name": target.get("service_name"),
                        "port": endpoint.get("port"), "protocol": endpoint.get("protocol")},
            "techniques": techniques, "evidence": evidence,
        }

    def ingest_alert(self, cyberdna_alert: Dict[str, Any]) -> str:
        parameters = self._parameters(cyberdna_alert)
        self.neo4j.run_write(WRITE_GRAPH, parameters)
        self.neo4j.run_write(CORRELATE_ALERTS, {"alert_id": cyberdna_alert["alert_id"],
                             "correlation_key": cyberdna_alert["correlation"]["correlation_key"]})
        return cyberdna_alert["alert_id"]

    @staticmethod
    def _decode_evidence(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Expose la valeur JSON originale, sans jamais lever la redaction du contrat."""
        decoded = []
        for row in rows:
            item = dict(row)
            raw_value = item.pop("value_json", None)
            try:
                item["value"] = json.loads(raw_value) if raw_value is not None else None
            except (TypeError, ValueError):
                item["value"] = raw_value
            decoded.append(item)
        return decoded

    def get_investigation_context(self, source_ip: str, alert_id: str) -> InvestigationContext:
        """Retourne un contexte complet en une lecture Neo4j, ou un contexte vide si inconnu."""
        rows = self.neo4j.run_read(INVESTIGATION_CONTEXT, {"source_ip": source_ip, "alert_id": alert_id})
        row = rows[0] if rows else {}
        alerts = sorted(row.get("alerts") or [], key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        timeline = [{
            "alert_id": item.get("alert_id"), "event_id": item.get("event_id"),
            "timestamp": item.get("timestamp"), "generated_at": item.get("generated_at"),
            "status": item.get("status"), "risk_score": item.get("risk_score"),
            "correlation_key": item.get("correlation_key"),
        } for item in alerts]
        attacker = dict(row.get("attacker") or {})
        if attacker:
            attacker["alert_count"] = len(alerts)
        return InvestigationContext(
            attacker=attacker,
            alerts=alerts,
            targets=row.get("targets") or [],
            services=row.get("services") or [],
            techniques=row.get("techniques") or [],
            tactics=row.get("tactics") or [],
            evidence=self._decode_evidence(row.get("evidence") or []),
            correlations=row.get("correlations") or [],
            timeline=timeline,
        )
