class AttackClassifier:
    """
    Module dédié à la classification sémantique des attaques.
    Il transforme des vecteurs de caractéristiques en catégories d'attaques.
    """
    def __init__(self):
        # On définit des seuils de classification
        self.THRESHOLDS = {
            "brute_force": {"login_attempts": 5},
            "scanning": {"unique_ports": 5},
            "intrusion": {"danger_score": 30}
        }

    def classify(self, features, log_extra_info):
        """
        Analyse les features et les infos du log pour déterminer le type d'attaque.
        Retourne une liste de catégories détectées.
        """
        attack_types = []

        # 1. Détection du Brute Force
        if features.get("login_attempts", 0) >= self.THRESHOLDS["brute_force"]["login_attempts"]:
            attack_types.append("Brute Force SSH/Service")

        # 2. Détection du Scanning
        if features.get("unique_ports", 0) >= self.THRESHOLDS["scanning"]["unique_ports"]:
            attack_types.append("Network Reconnaissance (Scanning)")

        # 3. Détection de l'Intrusion / Exploitation
        if features.get("danger_score", 0) >= self.THRESHOLDS["intrusion"]["danger_score"]:
            attack_types.append("System Intrusion / Exploitation")
        
        # 4. Analyse spécifique des commandes critiques (Sémantique)
        # On regarde si une commande très critique est présente dans le log actuel
        critical_commands = ["cat /etc/shadow", "bash -i", "nc -e", "sudo su"]
        command = str(log_extra_info.get("input", "")).lower()
        if any(cmd in command for cmd in critical_commands):
            attack_types.append("Critical System Access Attempt")

        # Si aucune règle ne correspond, on classifie comme "Anomalie Inconnue"
        if not attack_types:
            attack_types.append("Unspecified Anomaly")

        return attack_types