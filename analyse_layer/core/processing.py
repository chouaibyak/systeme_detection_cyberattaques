def process_log_for_ml(log_data: dict):
    """
    Nettoie et transforme le log brut en format 'Features' 
    pour l'Isolation Forest.
    """
    source = log_data.get("honeypot_source")
    processed_data = {}

    if source == "cowrie":
        # Exemple : on garde la commande et la longueur
        processed_data["event_id"] = log_data.get("eventid")
        processed_data["input"] = log_data.get("input", "")
        processed_data["input_len"] = len(log_data.get("input", ""))
        
    elif source == "dionaea":
        processed_data["connection_type"] = log_data.get("connection", {}).get("type")
        processed_data["remote_port"] = log_data.get("remote_port")

    # TODO: Ajouter ici la conversion en nombres (LabelEncoding)
    # print(f"Processing done for {source}")
    return processed_data