from fastapi import FastAPI, BackgroundTasks, Request
from services.elastic_service import index_log_to_elastic, close_elastic
from core.processing import process_log_for_ml

app = FastAPI(title="SentinelAI - Analyse Layer")

@app.on_event("shutdown")
async def shutdown():
    await close_elastic()

@app.post("/ingest")
async def ingest_logs(request: Request, background_tasks: BackgroundTasks):
    # 1. Réception
    log_data = await request.json()
    source = log_data.get("honeypot_source", "unknown")

    # Les tâches de fond sont exécutées dans leur ordre d'ajout. L'analyse
    # précède l'archivage afin que le log courant ne soit pas compté deux fois
    # lors de la reconstruction de l'historique Elasticsearch.
    background_tasks.add_task(process_log_for_ml, log_data)
    background_tasks.add_task(index_log_to_elastic, log_data, source)

    return {"status": "received", "source": source}
