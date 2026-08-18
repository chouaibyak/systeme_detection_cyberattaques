"""Contrat versionne entre la detection et le futur mapper CyberDNA.

Ce module ne connait ni Neo4j ni le schema de graphe. Il stabilise seulement
la representation d'une alerte enrichie, afin que les etapes suivantes ne
dependent pas des formats propres a Cowrie, Dionaea ou Honeytrap.
"""

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


CONTRACT_VERSION = "1.0"


class NetworkEndpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None

    @validator("ip")
    def validate_ip(cls, value):
        if value is not None:
            ip_address(value)
        return value


class TargetService(BaseModel):
    """Service vise ou observe par un honeypot."""

    asset_id: str
    honeypot: str
    endpoint: NetworkEndpoint
    service_name: Optional[str] = None


class ObservedAction(BaseModel):
    event_id: str
    timestamp: datetime
    honeypot: str
    event_type: Optional[str] = None
    source: NetworkEndpoint
    target: TargetService
    evidence: Dict[str, Any] = Field(default_factory=dict)


class DetectionVerdict(BaseModel):
    is_alert: bool
    status: str
    risk_score: float = Field(..., ge=0, le=100)
    detector: str
    reasons: List[str] = Field(default_factory=list)
    feature_snapshot: Dict[str, float] = Field(default_factory=dict)


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: Optional[str] = None
    advice: Optional[str] = None


class CorrelationContext(BaseModel):
    """Cle stable pour reunir les alertes appartenant a la meme campagne."""

    correlation_key: str
    source_ip: str
    target_asset_id: str
    time_window_start: datetime


class CyberDNAAlert(BaseModel):
    """Enveloppe canonique remise au mapper CyberDNA (etape 4)."""

    schema_version: str = CONTRACT_VERSION
    alert_id: str
    generated_at: datetime
    detection: DetectionVerdict
    action: ObservedAction
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    correlation: CorrelationContext


class CyberDNAAlertFactory:
    """Construit le contrat a partir des objets deja produits par le pipeline."""

    SENSITIVE_EVIDENCE_MARKERS = ("password", "credential", "token", "authorization", "secret")

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        else:
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except (TypeError, ValueError):
                parsed = datetime.now(timezone.utc)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @staticmethod
    def _port(value: Any) -> Optional[int]:
        try:
            port = int(value)
            return port if 0 <= port <= 65535 else None
        except (TypeError, ValueError):
            return None

    @classmethod
    def _safe_evidence(cls, extra_info: Dict[str, Any]) -> Dict[str, Any]:
        safe = {}
        for key, value in extra_info.items():
            if any(marker in key.lower() for marker in cls.SENSITIVE_EVIDENCE_MARKERS):
                safe[key] = "<redacted>"
            else:
                safe[key] = value
        return safe

    @staticmethod
    def _stable_id(prefix: str, payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        return "%s-%s" % (prefix, sha256(serialized.encode("utf-8")).hexdigest()[:24])

    def build(
        self,
        normalized_log: Dict[str, Any],
        verdict: Dict[str, Any],
        features: Dict[str, Any],
        mitre_info: Optional[Dict[str, Any]],
        raw_log: Optional[Dict[str, Any]] = None,
    ) -> CyberDNAAlert:
        timestamp = self._timestamp(normalized_log.get("timestamp"))
        source_ip = normalized_log["source_ip"]
        port = self._port(normalized_log.get("dst_port"))
        honeypot = normalized_log["honeypot"]
        target_ip = (raw_log or {}).get("dst_ip") or (raw_log or {}).get("destination_ip")
        asset_id = "honeypot:%s" % honeypot
        service_name = "%s/%s" % (normalized_log.get("protocol") or "unknown", port or "unknown")
        event_fingerprint = {
            "timestamp": timestamp.isoformat(),
            "source_ip": source_ip,
            "honeypot": honeypot,
            "port": port,
            "event_type": normalized_log.get("event_type"),
        }
        event_id = self._stable_id("evt", event_fingerprint)
        alert_id = self._stable_id("alert", {"event_id": event_id, "status": verdict.get("status")})
        extra_info = normalized_log.get("extra_info") or {}
        mitre = [
            MitreTechnique(
                technique_id=mitre_info["id"], name=mitre_info["name"], tactic=mitre_info["tactic"],
                description=mitre_info.get("description"), advice=mitre_info.get("advice"),
            )
        ] if mitre_info else []

        return CyberDNAAlert(
            alert_id=alert_id,
            generated_at=datetime.now(timezone.utc),
            detection=DetectionVerdict(
                is_alert=bool(verdict["is_alert"]), status=verdict["status"],
                risk_score=float(verdict["risk_score"]), detector="IsolationForest",
                reasons=verdict.get("reasons", []),
                feature_snapshot={key: float(value) for key, value in features.items()},
            ),
            action=ObservedAction(
                event_id=event_id, timestamp=timestamp, honeypot=honeypot,
                event_type=normalized_log.get("event_type"),
                source=NetworkEndpoint(ip=source_ip),
                target=TargetService(
                    asset_id=asset_id, honeypot=honeypot,
                    endpoint=NetworkEndpoint(ip=target_ip, port=port, protocol=normalized_log.get("protocol")),
                    service_name=service_name,
                ),
                evidence=self._safe_evidence(extra_info),
            ),
            mitre_techniques=mitre,
            correlation=CorrelationContext(
                correlation_key="%s:%s" % (source_ip, asset_id), source_ip=source_ip,
                target_asset_id=asset_id, time_window_start=timestamp,
            ),
        )
