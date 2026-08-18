import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyse_layer"))

from core.cyberdna_contract import CyberDNAAlertFactory


class CyberDNAAlertFactoryTests(unittest.TestCase):
    def setUp(self):
        self.normalized = {
            "timestamp": "2026-08-18T10:00:00Z", "source_ip": "203.0.113.10",
            "dst_port": "22", "protocol": "ssh", "event_type": "cowrie.command.input",
            "honeypot": "cowrie", "extra_info": {"input": "wget http://example.invalid/a", "password": "secret"},
        }
        self.verdict = {"is_alert": True, "status": "ATTACK DETECTED", "risk_score": 85, "reasons": ["test"]}
        self.features = {"total_events": 12, "eps": 18.2}
        self.mitre = {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command And Control"}

    def test_builds_stable_alert_and_redacts_secrets(self):
        factory = CyberDNAAlertFactory()
        first = factory.build(self.normalized, self.verdict, self.features, self.mitre)
        second = factory.build(self.normalized, self.verdict, self.features, self.mitre)

        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual(first.action.event_id, second.action.event_id)
        self.assertEqual(first.action.target.asset_id, "honeypot:cowrie")
        self.assertEqual(first.action.evidence["password"], "<redacted>")
        self.assertEqual(first.mitre_techniques[0].technique_id, "T1105")


if __name__ == "__main__":
    unittest.main()
