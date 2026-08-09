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
