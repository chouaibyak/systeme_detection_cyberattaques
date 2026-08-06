from elasticsearch import Elasticsearch

# Connexion à Elasticsearch (le nom 'elasticsearch' vient du docker-compose)
es = Elasticsearch(["http://elasticsearch:9200"])

def store_log(index_name, log_data):
    try:
        res = es.index(index=index_name, document=log_data)
        return res['_id']
    except Exception as e:
        print(f" Erreur stockage Elasticsearch : {e}")
        return None