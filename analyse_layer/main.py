from fastapi import FastAPI, Request, BackgroundTasks
from services.elastic_service import store_log
from core.processing import clean_cowrie_log

app = FastAPI()

# Cette fonction gère le Pipeline B (Analyse -> ML -> Investigation)
async def start_ml_pipeline(raw_data):
    # 1. Data Processing & Feature Extraction
    cleaned_data = clean_cowrie_log(raw_data)
    
    # 2. Ici tu appelleras ton ML Engine (Isolation Forest comme sur ton schéma)
    # is_anomaly = ml_engine.predict(cleaned_data)
    
    # 3. Si anomalie détectée -> Envoi vers l'index d'investigation
    # if is_anomaly:
    #     store_log("cyberdna-investigation", cleaned_data)
    pass

@app.post("/ingest")
async def ingest_logs(request: Request, background_tasks: BackgroundTasks):
    # Réception du log envoyé par le Shipper
    raw_log = await request.json()
    
    # --- PIPELINE A : STOCKAGE BRUT (SentinelAI - Branche Directe) ---
    # Enregistre le log tel quel, sans aucune modification
    background_tasks.add_task(store_log, "honeypot-logs-cowrie", raw_log)
    
    # --- PIPELINE B : ANALYSE LAYER (SentinelAI - Branche ML) ---
    # Lance le traitement ML en arrière-plan
    background_tasks.add_task(start_ml_pipeline, raw_log)
        
    return {"status": "received"}