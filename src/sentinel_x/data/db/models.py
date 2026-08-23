"""SQLAlchemy models: knowledge documents, security events, incidents,
knowledge-graph entities/edges, and investigations."""

import uuid
from datetime import UTC, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    Computed,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import UserDefinedType

from sentinel_x.common.settings import get_settings

EMBEDDING_DIM = get_settings().embedding_dim


class TSVector(UserDefinedType):
    """PostgreSQL tsvector type for full-text search columns."""

    def get_col_spec(self) -> str:
        return "tsvector"


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class TSVector(UserDefinedType):
    """PostgreSQL tsvector type for full-text search columns."""

    def get_col_spec(self) -> str:
        return "tsvector"


class Base(DeclarativeBase):
    pass


class Document(Base):
    """Knowledge-base chunk for RAG (ATT&CK techniques, Sigma rules, playbooks)."""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String(100))  # mitre_attack / sigma / playbook
    document_type: Mapped[str] = mapped_column(String(50))  # technique / detection_rule / playbook
    external_id: Mapped[str | None] = mapped_column(String(100), index=True)  # T1059 / rule uuid
    title: Mapped[str] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text)
    content_tsv = mapped_column(
        TSVector(),
        Computed("to_tsvector('english', coalesce(title,'') || ' ' || content)", persisted=True),
    )
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    embedding = mapped_column(Vector(EMBEDDING_DIM))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        Index("ix_documents_source_type", "source", "document_type"),
        Index(
            "ux_documents_natural_key",
            "source",
            "external_id",
            "title",
            unique=True,
        ),
        Index(
            "ix_documents_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


class SecurityEventRow(Base):
    """Persisted canonical security event."""

    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(50))
    user: Mapped[str | None] = mapped_column(String(200), index=True)
    host: Mapped[str | None] = mapped_column(String(200), index=True)
    process: Mapped[str | None] = mapped_column(String(300))
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    file_path: Mapped[str | None] = mapped_column(Text)
    bytes_transferred: Mapped[float | None] = mapped_column(BigInteger)
    severity: Mapped[int] = mapped_column(Integer, default=0)
    label: Mapped[str] = mapped_column(String(20), default="benign")
    attack_category: Mapped[str | None] = mapped_column(String(50))
    technique_id: Mapped[str | None] = mapped_column(String(20))
    incident_id: Mapped[str | None] = mapped_column(String(64), index=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)


class IncidentRow(Base):
    """Correlated incident produced by the correlation engine."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="open")
    severity_label: Mapped[str] = mapped_column(String(20), default="medium")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    attack_probability: Mapped[float | None] = mapped_column(Float)
    correlated_event_ids: Mapped[list] = mapped_column(JSONB, default=list)
    entities: Mapped[dict] = mapped_column(JSONB, default=dict)  # users/hosts/ips involved
    ground_truth_incident_id: Mapped[str | None] = mapped_column(String(64), index=True)


class EntityRow(Base):
    """Knowledge-graph node."""

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)  # e.g. user:alice
    entity_type: Mapped[str] = mapped_column(
        String(30), index=True
    )  # user/host/ip/process/file/technique/ioc
    name: Mapped[str] = mapped_column(String(300))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)


class EdgeRow(Base):
    """Knowledge-graph edge with temporal validity."""

    __tablename__ = "edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    src_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    dst_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    relation: Mapped[str] = mapped_column(
        String(60), index=True
    )  # logged_into/executed/connected_to/accessed/associated_with
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (Index("ix_edges_src_rel_dst", "src_id", "relation", "dst_id"),)


class InvestigationRow(Base):
    """Agent investigation output for an incident."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    status: Mapped[str] = mapped_column(String(20), default="completed")  # completed/failed
    finding: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    tool_calls: Mapped[list] = mapped_column(JSONB, default=list)
    model_name: Mapped[str | None] = mapped_column(String(100))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
