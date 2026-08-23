"""Canonical security event schema.

All telemetry sources (CIC-IDS2017 flows, synthetic scenario events,
future live feeds) are normalized into `SecurityEvent` before entering
the SENTINEL-X pipeline.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventType(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS_EXECUTION = "process_execution"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    PRIVILEGE_CHANGE = "privilege_change"


class Action(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    EXECUTE = "execute"
    CONNECT = "connect"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_READ = "file_read"
    PRIVILEGE_ESCALATE = "privilege_escalate"


class Label(StrEnum):
    BENIGN = "benign"
    ATTACK = "attack"


class SecurityEvent(BaseModel):
    """Single normalized telemetry record."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=1)
    timestamp: datetime
    source: str = Field(description="Telemetry source: edr, firewall, auth_log, flow_sensor")
    event_type: EventType
    action: Action
    user: str | None = None
    host: str | None = None
    process: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    file_path: str | None = None
    bytes_transferred: int | None = Field(default=None, ge=0)
    severity: int = Field(default=1, ge=0, le=10, description="Raw sensor severity 0-10")

    # Ground truth (populated by datasets / generator; absent in production inference)
    label: Label = Label.BENIGN
    attack_category: str | None = None
    technique_id: str | None = None
    incident_id: str | None = Field(
        default=None, description="Ground-truth incident grouping from dataset/generator"
    )

    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentGroundTruth(BaseModel):
    """Ground-truth incident definition used for correlation + agent evaluation."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    scenario: str = Field(description="Scenario template name, e.g. ransomware_encryption")
    technique_ids: list[str]
    start_time: datetime
    end_time: datetime
    compromised_users: list[str]
    compromised_hosts: list[str]
    description: str
