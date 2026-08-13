class LogNormalizer:
    def __init__(self):
        self.mappings = {
            "cowrie": {"source_ip": "src_ip", "dst_port": "dst_port", "protocol": "protocol", "event_type": "eventid"},
            "dionaea": {"source_ip": "src_ip", "dst_port": "dst_port", "protocol": "connection.protocol", "event_type": "connection.type"},
            "honeytrap": {"source_ip": "source-ip", "dst_port": "destination-port", "protocol": "category", "event_type": "type"}
        }
        self.whitelists = {
            "cowrie": ["username", "password", "input", "session", "hassh"],
            "dionaea": ["credentials", "transport", "file_hash", "src_port"],
            "honeytrap": ["http.url", "http.method", "http.header.user-agent", "token"]
        }

    def _get_nested_value(self, data, key_path):
        keys = key_path.split('.')
        for k in keys:
            if isinstance(data, dict): data = data.get(k)
            else: return None
        return data

    def normalize(self, raw_log):
        source = raw_log.get("honeypot_source", "unknown")
        if source not in self.mappings: return None
        mapping = self.mappings[source]
        whitelist = self.whitelists.get(source, [])
        normalized = {
            "timestamp": raw_log.get("timestamp") or raw_log.get("date") or datetime.now().isoformat(),
            "source_ip": None,
            "dst_port": None,
            "protocol": None,
            "event_type": None,
            "honeypot": source,
            "extra_info": {}
        }
        for std_key, raw_key in mapping.items():
            val = self._get_nested_value(raw_log, raw_key) if '.' in raw_key else raw_log.get(raw_key)
            normalized[std_key] = val
        for field in whitelist:
            val = self._get_nested_value(raw_log, field) if '.' in field else raw_log.get(field)
            if val is not None: normalized["extra_info"][field] = val
        return normalized