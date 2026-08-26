"""
Unified normalized security event schema for GraphSOC.

Every event ingested into the system — regardless of source (synthetic
generator, CICIDS2017 adapter, Zeek adapter, etc.) — is normalized into
this common shape before it touches detection, graph, or agent logic.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK_CONNECTION = "network_connection"
    DNS = "dns"
    PROCESS_EXECUTION = "process_execution"
    FILE_ACCESS = "file_access"
    PRIVILEGE_CHANGE = "privilege_change"
    CLOUD_ACTIVITY = "cloud_activity"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType
    source: str = Field(description="Ingestion source, e.g. 'synthetic', 'cicids2017', 'zeek'")

    user_id: Optional[str] = None
    device_id: Optional[str] = None

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None

    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None

    resource: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None

    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

    severity: Optional[Severity] = None

    # Ground-truth label — only populated for labeled/training data, never
    # invented for live events.
    label: Optional[str] = None
    attack_type: Optional[str] = None

    metadata: dict = Field(default_factory=dict)

    @field_validator("source_port", "destination_port")
    @classmethod
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 65535):
            raise ValueError("port must be between 0 and 65535")
        return v

    class Config:
        use_enum_values = True


class EventBulkIngest(BaseModel):
    events: list[SecurityEvent]


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    triggering_event_id: str
    detector: str  # "ml_baseline" | "anomaly" | "graph" | "rule"
    threat_type: Optional[str] = None
    confidence: float = 0.0
    risk_score: float = 0.0
    severity: Severity = Severity.LOW
    affected_user: Optional[str] = None
    affected_device: Optional[str] = None
    evidence_event_ids: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "OPEN"
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    risk_score: float = 0.0

    affected_users: list[str] = Field(default_factory=list)
    affected_devices: list[str] = Field(default_factory=list)
    affected_ips: list[str] = Field(default_factory=list)

    attack_chain: list[str] = Field(default_factory=list)
    attack_techniques: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    risk_factors: list[dict] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    investigation_summary: str = ""
