from fastapi import FastAPI, Request, BackgroundTasks
from services.elastic_service import store_log

app = FastAPI()

@app.post("/ingest")
async def ingest_logs(request: Request, background_tasks: BackgroundTasks):
    # 1. Réception du log BRUT envoyé par le Shipper
    raw_log = await request.json()
    
    # 2. ENVOI DIRECT (Branche A)
    # On utilise background_tasks pour que le stockage ne ralentisse pas l'API
    background_tasks.add_task(store_log, "honeypot-logs-cowrie", raw_log)
        
    return {"status": "received"}