from elasticsearch import AsyncElasticsearch
import datetime
import os

# On récupère l'URL depuis les variables d'environnement (docker-compose)
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
es = AsyncElasticsearch([ES_URL])

async def index_log_to_elastic(log_data: dict, source: str):
    """Archive le log brut dans un index spécifique à l'honeypot"""
    try:
        index_name = f"honeypot-logs-{source.lower()}"
        
        # Ajout d'un timestamp si absent
        if "@timestamp" not in log_data:
            log_data["@timestamp"] = datetime.datetime.utcnow().isoformat()

        await es.index(index=index_name, document=log_data)
    except Exception as e:
        print(f"Error Indexing to ES: {e}")

async def close_elastic():
    await es.close()