from pyattck import Attck
import re

class MitreAnalyzer:
    def __init__(self):
        # On charge le framework une seule fois
        self.attck = Attck()

       # 1. PRÉ-TRAITEMENT : On compile les Regex pour la performance
        # On utilise re.IGNORECASE pour ne pas se soucier de la casse
        self.COMMAND_PATTERNS = {
            # --- DISCOVERY ---
            "T1087": re.compile(r"\b(whoami|id|getent|useradd|groupadd)\b|cat.*/etc/(passwd|shadow|group)", re.I),
            "T1082": re.compile(r"\b(uname|hostname|uptime|dmesg)\b|cat.*/proc/(cpuinfo|meminfo|version)", re.I),
            "T1016": re.compile(r"\b(ifconfig|ip\s+addr|netstat|route|arp|nmcli|ufw|iptables)\b", re.I),
            "T1083": re.compile(r"\b(ls|find|locate|pwd|tree|du|df)\b\s+.*", re.I),
            "T1057": re.compile(r"\b(ps|top|htop|pgrep|pkill)\b", re.I),

            # --- EXECUTION ---
            "T1059": re.compile(r"\b(python\d?|perl|ruby|lua|node|bash|sh|zsh)\b", re.I),
            "T1203": re.compile(r"\b(gcc|make|g\+\+|clang|cc)\b|./configure", re.I),

            # --- PERSISTENCE ---
            "T1543": re.compile(r"\b(systemctl|service)\b|/etc/rc\.local|cron(\.d)?", re.I),
            "T1098": re.compile(r"authorized_keys|\.ssh/id_.*|ssh-keygen", re.I),

            # --- PRIVILEGE ESCALATION ---
            "T1548": re.compile(r"\b(sudo|su\s+-|pkexec|visudo)\b|chmod\s+([421]777|\+s)", re.I),

            # --- DEFENSE EVASION ---
            "T1070": re.compile(r"\b(history\s+-c|clear)\b|HISTFILE|rm\s+.*(\.log|history)", re.I),
            "T1140": re.compile(r"\b(base64|openssl|gpg)\b.*\s+(-d|--decode|decrypt)", re.I),

            # --- CREDENTIAL ACCESS ---
            "T1552": re.compile(r"cat.*\.(bash|mysql)_history|env|printenv", re.I),

            # --- COMMAND AND CONTROL (Transferts) ---
            "T1105": re.compile(r"\b(wget|curl|tftp|scp|rsync|nc|netcat|ncat|socat)\b", re.I),

            # --- IMPACT ---
            "T1485": re.compile(r"rm\s+-rf\s+/|mkfs|shred|dd\s+if=/dev/zero", re.I),
            "T1496": re.compile(r"\b(minerd|xmrig|cpuminer|cryptonight)\b", re.I),
        }
        
        # MAPPING GÉNÉRIQUE : Si rien ne match, on utilise le port pour deviner l'intention
        # Cela permet de classifier l'inconnu.
        self.GENERIC_PORT_MAP = {
            21: "T1110",    # FTP -> Brute Force
            22: "T1110",    # SSH -> Brute Force
            23: "T1110",    # Telnet -> Brute Force
            25: "T1566",    # SMTP -> Phishing/Mail exploit
            53: "T1568",    # DNS -> Dynamic Resolution
            80: "T1190",    # HTTP -> Exploit Public-Facing Application
            443: "T1190",   # HTTPS -> Exploit Public-Facing Application
            445: "T1210",   # SMB -> Exploitation of Remote Services
            1433: "T1190",  # MSSQL -> Exploit Public-Facing Application
            3306: "T1190",  # MySQL -> Exploit Public-Facing Application
            3389: "T1110",  # RDP -> Brute Force
            5900: "T1021.005", # VNC -> Remote Services
        }

    def get_technique_info(self, technique_id):
        """Récupère les détails officiels depuis la base MITRE"""
        for technique in self.attck.enterprise.techniques:
            if technique.technique_id == technique_id:
                # On nettoie la description pour qu'elle soit courte et compréhensible
                desc = technique.description.split('.')[0] + "." if technique.description else "Pas de description."
                return {
                    "id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactics[0].name if technique.tactics else "Inconnu",
                    "description": desc,
                    "advice": technique.mitigations[0].name if technique.mitigations else "Surveiller et bloquer l'IP source"
                }
        return None

    def clean_command(self, cmd):
        """
        Nettoyage de base pour contrer l'obfuscation simple 
        ex: c''at /et""c/pass''wd -> cat /etc/passwd
        """
        if not cmd: return ""
        # Supprime les guillemets vides ou simples qui cassent les strings
        return cmd.replace("''", "").replace('""', "")

    def map_log_to_mitre(self, normalized_log):
        extra = normalized_log.get("extra_info", {})
        port = normalized_log.get("dst_port")
        tech_id = None

        if normalized_log["honeypot"] == "cowrie":
            if "password" in extra:
                tech_id = "T1110"
            elif "input" in extra:
                # 1. Nettoyage de la commande
                raw_cmd = extra["input"]
                clean_cmd = self.clean_command(raw_cmd)
                
                # 2. MATCHING PAR REGEX
                for tid, pattern in self.COMMAND_PATTERNS.items():
                    if pattern.search(clean_cmd):
                        tech_id = tid
                        break
                
                if not tech_id:
                    tech_id = "T1059"

        elif normalized_log["honeypot"] == "dionaea":
            # 1. Capture de malware (Fichiers)
            if "file_hash" in extra:
                tech_id = "T1547" # Boot or Logon Autostart (Persistance via Malware)

            # 2. SMB (Port 445)
            elif port == 445:
                # Si Dionaea a capturé des identifiants NTLM/SMB
                if "credentials" in extra or "username" in str(extra):
                    tech_id = "T1078" # Valid Accounts (Tentative d'utilisation de comptes)
                else:
                    tech_id = "T1210" # Exploitation of Remote Services (ex: EternalBlue)

            # 3. MSSQL (Port 1433) ou MySQL (Port 3306)
            elif port in [1433, 3306]:
                # On récupère la requête SQL si elle existe dans les logs
                sql_query = str(extra.get("query", "") or extra.get("sql", ""))
                
                if sql_query:
                    for tid, pattern in self.DB_ATTACK_PATTERNS.items():
                        if pattern.search(sql_query):
                            tech_id = tid
                            break
                
                # Si pas de pattern matché mais tentative de login
                if not tech_id:
                    if "credentials" in extra:
                        tech_id = "T1110" # Brute Force sur base de données
                    else:
                        tech_id = "T1190" # Exploit Public-Facing Application

        # --- LOGIQUE DE REPLI (FALLBACK) ---
        if not tech_id:
            tech_id = self.GENERIC_PORT_MAP.get(port)
            
        if not tech_id:
            if normalized_log["honeypot"] == "honeytrap":
                tech_id = "T1046"
            elif normalized_log["honeypot"] == "cowrie":
                tech_id = "T1021"
            else:
                tech_id = "T1352"

        return self.get_technique_info(tech_id)