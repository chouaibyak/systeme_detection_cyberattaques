from collections import defaultdict

class FeatureExtractor:
    def __init__(self):
        # 1. Poids pour Cowrie (Commandes)
        self.COWRIE_WEIGHTS = {
            "ls": 1, "pwd": 1, "whoami": 1, "uname": 1,
            "cat /etc/passwd": 10, "ifconfig": 5,
            "wget": 15, "curl": 15, "chmod +x": 15,
            "cat /etc/shadow": 50, "bash -i": 50, "nc -e": 50
        }
        
        # 2. Poids pour Dionaea (Protocoles/Services critiques)
        self.DIONAEA_WEIGHTS = {
            "smb": 20, "rpc": 15, "mssql": 15, "mysql": 10, "ftp": 5
        }
        
        # 3. Poids pour Honeytrap (Comportements HTTP)
        self.HONEYTRAP_WEIGHTS = {
            "POST": 10, "PUT": 15, "DELETE": 15, "GET": 1,
            "admin": 20, ".env": 30, "config": 20, "passwd": 30, "shell": 40
        }

    def _calculate_universal_danger(self, log):
        """Calcule la dangerosité peu importe la source du honeypot."""
        source = log.get("honeypot", "unknown")
        extra = log.get("extra_info", {})
        score = 0

        if source == "cowrie":
            # Analyse des commandes saisies
            cmd = str(extra.get("input", "")).lower()
            for kw, weight in self.COWRIE_WEIGHTS.items():
                if kw in cmd: score = max(score, weight)

        elif source == "dionaea":
            # Analyse du protocole utilisé
            proto = str(log.get("protocol", "")).lower()
            for proto_name, weight in self.DIONAEA_WEIGHTS.items():
                if proto_name in proto: score = max(score, weight)

        elif source == "honeytrap":
            # Analyse de la méthode HTTP et de l'URL
            method = str(extra.get("http.method", "")).upper()
            url = str(extra.get("http.url", "")).lower()
            
            # Poids de la méthode
            score += self.HONEYTRAP_WEIGHTS.get(method, 0)
            
            # Poids des mots-clés dans l'URL
            for kw, weight in self.HONEYTRAP_WEIGHTS.items():
                if kw in url: score = max(score, weight)

        return score

    def extract_features(self, normalized_logs):
        sessions = defaultdict(list)
        for log in normalized_logs:
            if log and log["source_ip"]:
                sessions[log["source_ip"]].append(log)

        features_by_ip = {}
        for ip, logs in sessions.items():
            # Features universelles
            total_events = len(logs)
            unique_ports = len(set([l["dst_port"] for l in logs if l["dst_port"]]))
            login_attempts = sum(1 for l in logs if "login" in str(l["event_type"]).lower() or "password" in l["extra_info"])
            unique_protocols = len(set([l["protocol"] for l in logs if l["protocol"]]))

            # Calcul du danger score universel (Somme des dangers de chaque log de la session)
            universal_danger_score = sum(self._calculate_universal_danger(l) for l in logs)

            features_by_ip[ip] = {
                "total_events": total_events,
                "unique_ports": unique_ports,
                "login_attempts": login_attempts,
                "danger_score": universal_danger_score,
                "unique_protocols": unique_protocols
            }
        return features_by_ip