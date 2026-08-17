from elasticsearch import AsyncElasticsearch
import datetime
import os
import asyncio

# On récupère l'URL depuis les variables d'environnement (docker-compose)
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
es = AsyncElasticsearch([ES_URL])

async def index_log_to_elastic(log_data: dict, source: str):
    """Archive le log brut dans un index spécifique à l'honeypot"""
    index_name = f"honeypot-logs-{source.lower()}"
    if "@timestamp" not in log_data:
        log_data["@timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for attempt in range(5):
        try:
            await es.index(index=index_name, document=log_data)
            return
        except Exception as error:
            if attempt == 4:
                print(f"Error Indexing to ES after retries: {error}")
                return
            await asyncio.sleep(2 ** attempt)

async def close_elastic():
    await es.close()

async def get_recent_logs(limit=500):
    """
    Récupère les derniers logs de tous les honeypots depuis Elasticsearch
    pour reconstruire la mémoire de l'IA.
    """
    try:
        # On cherche dans tous les index de honeypots
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        # On utilise le wildcard * pour chercher dans tous les index honeypot-logs-*
        response = await es.search(index="honeypot-logs-*", body=query, ignore_unavailable=True)
        
        logs = []
        for hit in response['hits']['hits']:
            log = dict(hit['_source'])
            # On ajoute la source du honeypot basée sur le nom de l'index
            index_name = hit['_index']
            if 'cowrie' in index_name: log['honeypot_source'] = 'cowrie'
            elif 'dionaea' in index_name: log['honeypot_source'] = 'dionaea'
            elif 'honeytrap' in index_name: log['honeypot_source'] = 'honeytrap'
            
            logs.append(log)
            
        return logs
    except Exception as e:
        print(f"Erreur lors de la récupération des logs ES: {e}")
        return []
