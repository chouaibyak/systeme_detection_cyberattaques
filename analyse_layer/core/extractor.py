from collections import defaultdict
from datetime import datetime, timezone

class FeatureExtractor:
    def __init__(self):
        # (On garde tes poids de dangerosité ici...)
        self.COWRIE_WEIGHTS = {
            "ls": 1, "pwd": 1, "whoami": 1, "uname": 1,
            "cat /etc/passwd": 10, "ifconfig": 5,
            "wget": 15, "curl": 15, "chmod +x": 15,
            "cat /etc/shadow": 50, "bash -i": 50, "nc -e": 50
        }
        self.DIONAEA_WEIGHTS = {"smb": 20, "rpc": 15, "mssql": 15, "mysql": 10, "ftp": 5}
        self.HONEYTRAP_WEIGHTS = {
            "POST": 10, "PUT": 15, "DELETE": 15, "GET": 1,
            "admin": 20, ".env": 30, "config": 20, "passwd": 30, "shell": 40
        }

    def _parse_timestamp(self, ts_str):
        """Convertit la chaîne timestamp en objet datetime."""
        try:
            parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except:
            return datetime.now(timezone.utc)

    def _calculate_universal_danger(self, log):
        # (Garder la même fonction _calculate_universal_danger que précédemment)
        source = log.get("honeypot", "unknown")
        extra = log.get("extra_info", {})
        score = 0
        if source == "cowrie":
            cmd = str(extra.get("input", "")).lower()
            for kw, weight in self.COWRIE_WEIGHTS.items():
                if kw in cmd: score = max(score, weight)
        elif source == "dionaea":
            proto = str(log.get("protocol", "")).lower()
            for proto_name, weight in self.DIONAEA_WEIGHTS.items():
                if proto_name in proto: score = max(score, weight)
        elif source == "honeytrap":
            method = str(extra.get("http.method", "")).upper()
            url = str(extra.get("http.url", "")).lower()
            score += self.HONEYTRAP_WEIGHTS.get(method, 0)
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
            # --- 1. Features Classiques ---
            total_events = len(logs)
            unique_ports = len(set([l["dst_port"] for l in logs if l["dst_port"]]))
            login_attempts = sum(1 for l in logs if "login" in str(l["event_type"]).lower() or "password" in l["extra_info"])
            unique_protocols = len(set([l["protocol"] for l in logs if l["protocol"]]))
            universal_danger_score = sum(self._calculate_universal_danger(l) for l in logs)

            # --- 2. FEATURES DE VÉLOCITÉ (Nouveau) ---
            # On trie les logs par temps pour être sûr du calcul
            sorted_logs = sorted(logs, key=lambda x: x["timestamp"])
            
            if total_events > 1:
                t_start = self._parse_timestamp(sorted_logs[0]["timestamp"])
                t_end = self._parse_timestamp(sorted_logs[-1]["timestamp"])
                duration = (t_end - t_start).total_seconds()
                
                # Événements par seconde (EPS)
                # Si la durée est 0 (tout arrive en même temps), on met un score très haut
                eps = total_events / duration if duration > 0 else total_events * 10
                
                # Intervalle moyen entre événements (IAT)
                iat = duration / (total_events - 1) if duration > 0 else 0
            else:
                eps = 0
                iat = 10 # Valeur neutre pour un seul log

            # Vecteur Final Enrichi
            features_by_ip[ip] = {
                "total_events": total_events,
                "unique_ports": unique_ports,
                "login_attempts": login_attempts,
                "danger_score": universal_danger_score,
                "unique_protocols": unique_protocols,
                "eps": eps, # Nouvelle feature
                "iat": iat   # Nouvelle feature
            }
        return features_by_ip
