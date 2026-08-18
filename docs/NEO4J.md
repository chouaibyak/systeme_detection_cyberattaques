# Neo4j — couche Investigation / CyberDNA

Neo4j ne lit jamais les formats Cowrie, Dionaea ou Honeytrap. Son unique entree
est le dictionnaire `analysis.cyberdna_alert` du contrat
[`DATA_CONTRACT.md`](DATA_CONTRACT.md).

## Modele du graphe

```text
(:Attacker {ip})-[:TRIGGERED]->(:Alert {alert_id})-[:TARGETS]->(:Target {asset_id})
(:Target)-[:EXPOSES]->(:Service {service_key})
(:Alert)-[:USES_TECHNIQUE]->(:Technique {technique_id})-[:BELONGS_TO]->(:Tactic {name})
(:Alert)-[:HAS_EVIDENCE]->(:Evidence {evidence_id})
(:Alert)-[:CORRELATED_WITH]->(:Alert)
```

Les contraintes `IF NOT EXISTS` protegent les identites Attacker, Alert,
Target, Service, Technique, Tactic et Evidence. `service_key` est
`<asset_id>|<protocol>|<port>` ; `evidence_id` est un SHA-256 deterministe de
`alert_id`, du champ et de sa valeur. Les preuves sont conservees en JSON : la
valeur `<redacted>` n'est jamais reconstruite ni remplacee.

`CORRELATED_WITH` relie les alertes avec la meme `correlation_key`. Il indique
une campagne technique commune, sans constituer une attribution a un groupe ou
a une personne.

## Configuration et lancement

Dans `.env` (non versionne) :

```dotenv
NEO4J_USER=neo4j
NEO4J_PASSWORD=choisir-un-mot-de-passe-solide
```

```bash
docker compose up -d neo4j
```

Neo4j Browser est sur `http://localhost:7474`; Bolt est expose sur `7687`.
`Neo4jService` utilise `NEO4J_URI` (par defaut `bolt://neo4j:7687`),
`NEO4J_USER` et `NEO4J_PASSWORD`.

## Tests

Les tests unitaires projettent une alerte produite par `CyberDNAAlertFactory`,
donc conforme au pipeline, dans une implementation Neo4j en memoire :

```bash
docker run --rm \
  -v "$PWD/analyse_layer:/app/analyse_layer" \
  -v "$PWD/investigation_layer:/app/investigation_layer" \
  -v "$PWD/tests:/app/tests" -w /app \
  systeme_detection_cyberattaques-fastapi \
  python -m unittest discover -s tests -v
```

Pour une validation avec Neo4j reel, installer
`investigation_layer/requirements.txt`, appeler `initialise_schema()`, puis
`ingest_alert(analysis["cyberdna_alert"])`. La methode
`get_investigation_context(ip, alert_id).to_dict()` effectue une seule lecture
Neo4j et retourne un objet directement serialisable, prevu pour le futur
consommateur LLM (qui n'est pas implemente a cette etape) :

```json
{
  "attacker": {"ip": "203.0.113.10", "alert_count": 2},
  "alerts": [{"alert_id": "alert-...", "risk_score": 85.0}],
  "targets": [{"asset_id": "honeypot:cowrie", "honeypot": "cowrie"}],
  "services": [{"name": "ssh/22", "port": 22, "protocol": "ssh"}],
  "techniques": [{"technique_id": "T1105", "tactic": "Command And Control"}],
  "tactics": [{"name": "Command And Control"}],
  "evidence": [{"field": "password", "value": "<redacted>", "is_redacted": true}],
  "correlations": [{"alert_id": "alert-..."}],
  "timeline": [{"alert_id": "alert-...", "timestamp": "2026-08-18T10:00:00+00:00"}]
}
```

Les listes restent vides lorsque les relations optionnelles sont absentes. Les
preuves sont decodees depuis leur JSON stocke, sans jamais reconstruire une
valeur redigee.
