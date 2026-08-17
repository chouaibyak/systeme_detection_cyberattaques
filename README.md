# Système de détection de cyberattaques basé sur des Honeypots et l’IA

## Persistance des logs Cowrie dans Elasticsearch

L'index `honeypot-logs-cowrie` est stocké dans le volume Docker externe
`pfa_esdata`. Il n'est donc pas supprimé par `docker compose down`, ni
par `docker compose down -v`.

Avant le premier démarrage, créez ce volume une seule fois :

```bash
docker volume create pfa_esdata
docker compose up -d --build
```

Pour arrêter et redémarrer la stack sans perdre les index :

```bash
docker compose down
docker compose up -d
```

Ne lancez `docker volume rm pfa_esdata` que si vous voulez supprimer
volontairement toutes les données Elasticsearch. Vous pouvez vérifier l'index
après le redémarrage avec :

```bash
curl http://localhost:9200/_cat/indices?v
```

## Catalogue MITRE ATT&CK

L'image `fastapi` intègre le bundle officiel Enterprise ATT&CK STIX 2.1
version 19.1. L'enrichissement MITRE fonctionne ainsi sans accès Internet au
moment où un log est analysé, y compris pendant la phase de baseline ML.

Pour mettre à jour explicitement le catalogue, reconstruisez l'image avec la
version ATT&CK voulue :

```bash
docker compose build --build-arg MITRE_ATTACK_VERSION=19.1 fastapi
docker compose up -d --force-recreate fastapi
```
