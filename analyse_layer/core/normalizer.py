from datetime import datetime, timezone


class LogNormalizer:
    def __init__(self):
        self.mappings = {
            "cowrie": {"source_ip": ("src_ip",), "dst_port": ("dst_port",), "protocol": ("protocol",), "event_type": ("eventid",)},
            # Dionaea connection incidents use the nested connection object,
            # while its download/login incidents expose fields at the root.
            "dionaea": {
                "source_ip": ("src_ip", "connection.src_ip"),
                "dst_port": ("dst_port", "connection.dst_port"),
                "protocol": ("connection.protocol", "protocol"),
                "event_type": ("connection.type", "type", "incident"),
            },
            # Honeytrap keys are normally flattened with hyphens, but accept
            # nested/dotted variants so upgrades do not silently drop data.
            "honeytrap": {
                "source_ip": ("source-ip", "source.ip", "src_ip"),
                "dst_port": ("destination-port", "destination.port", "dst_port"),
                "protocol": ("category", "protocol"),
                "event_type": ("type", "event_type"),
            },
        }
        self.whitelists = {
            "cowrie": ["username", "password", "input", "session", "hassh"],
            "dionaea": ["credentials", "transport", "file_hash", "src_port"],
            "honeytrap": ["http.url", "http.method", "http.header.user-agent", "token"]
        }

    def _get_nested_value(self, data, key_path):
        # Honeytrap utilise des clés aplaties (ex. "http.url"), tandis que
        # Dionaea expose des objets imbriqués (ex. connection.protocol).
        if key_path in data:
            return data[key_path]

        keys = key_path.split('.')
        for k in keys:
            if isinstance(data, dict): data = data.get(k)
            else: return None
        return data

    def _first_value(self, data, paths):
        for path in paths:
            value = self._get_nested_value(data, path)
            if value is not None:
                return value
        return None

    def normalize(self, raw_log):
        source = raw_log.get("honeypot_source", "unknown")
        if source not in self.mappings: return None
        mapping = self.mappings[source]
        whitelist = self.whitelists.get(source, [])
        normalized = {
            "timestamp": raw_log.get("timestamp") or raw_log.get("date") or datetime.now(timezone.utc).isoformat(),
            "source_ip": None,
            "dst_port": None,
            "protocol": None,
            "event_type": None,
            "honeypot": source,
            "extra_info": {}
        }
        for std_key, raw_keys in mapping.items():
            normalized[std_key] = self._first_value(raw_log, raw_keys)
        for field in whitelist:
            val = self._get_nested_value(raw_log, field) if '.' in field else raw_log.get(field)
            if val is not None: normalized["extra_info"][field] = val
        return normalized
