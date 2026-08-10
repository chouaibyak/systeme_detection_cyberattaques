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

    # 2. Lancement en PARALLÈLE des tâches de fond
    # Tâche 1 : Archivage brut (Elasticsearch)
    background_tasks.add_task(index_log_to_elastic, log_data, source)
    
    # Tâche 2 : Préparation pour IA (Data Processing)
    background_tasks.add_task(process_log_for_ml, log_data)

    return {"status": "received", "source": source}