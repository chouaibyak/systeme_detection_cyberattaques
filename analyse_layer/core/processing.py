def clean_cowrie_log(raw_log):
    # Liste des champs importants que tu as choisis
    champs_a_garder = [
        "timestamp", "src_ip", "session", "eventid", 
        "src_port", "dst_port", "username", "password", "input"
    ]
    
    # On crée un nouveau dictionnaire avec seulement ces champs
    processed_log = {k: v for k, v in raw_log.items() if k in champs_a_garder}
    
    # Ajout du type de honeypot pour le tri dans Elasticsearch
    processed_log["honeypot_type"] = "cowrie"
    
    return processed_log