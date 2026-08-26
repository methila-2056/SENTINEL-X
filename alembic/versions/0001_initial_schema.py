"""initial schema from models

Revision ID: 0001
Revises:
Create Date: 2026-08-26

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(100), unique=True, nullable=False, index=True),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column(
            "role",
            sa.String(20),
            nullable=False,
            server_default="viewer",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("document_type", sa.String(50), nullable=False),
        sa.Column("external_id", sa.String(100), index=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "content_tsv",
            postgresql.TSVector(),
            sa.Computed(
                "to_tsvector('english', coalesce(title,'') || ' ' || content)",
                persisted=True,
            ),
        ),
        sa.Column("metadata", postgresql.JSONB(), server_default="{}"),
        sa.Column("embedding", postgresql.Vector(384)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Index("ix_documents_source_type", "source", "document_type"),
        sa.Index(
            "ux_documents_natural_key",
            "source",
            "external_id",
            "title",
            unique=True,
        ),
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("user", sa.String(200), index=True),
        sa.Column("host", sa.String(200), index=True),
        sa.Column("process", sa.String(300)),
        sa.Column("src_ip", sa.String(45), index=True),
        sa.Column("dst_ip", sa.String(45), index=True),
        sa.Column("dst_port", sa.Integer),
        sa.Column("file_path", sa.Text()),
        sa.Column("bytes_transferred", sa.BigInteger),
        sa.Column("severity", sa.Integer(), server_default="0"),
        sa.Column("label", sa.String(50), server_default="benign"),
        sa.Column("attack_category", sa.String(50)),
        sa.Column("technique_id", sa.String(20)),
        sa.Column("incident_id", sa.String(36), index=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            server_default="{}",
        ),
    )

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20)),
        sa.Column("severity_label", sa.String(20)),
        sa.Column("risk_score", sa.Float),
        sa.Column("anomaly_score", sa.Float),
        sa.Column("attack_probability", sa.Float),
        sa.Column("correlated_event_ids", postgresql.ARRAY(sa.Text())),
        sa.Column("entities", postgresql.JSONB()),
        sa.Column("signals", postgresql.JSONB()),
        sa.Column("report", postgresql.JSONB()),
        sa.Column("ground_truth_incident_id", sa.String(36)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "entities",
        sa.Column("id", sa.String(200), primary_key=True),
        sa.Column("kind", sa.String(50), nullable=False, index=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "edges",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("src_id", sa.String(200), nullable=False, index=True),
        sa.Column("dst_id", sa.String(200), nullable=False, index=True),
        sa.Column("relation", sa.String(50), nullable=False),
        sa.Column("weight", sa.Float(), server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("edges")
    op.drop_table("entities")
    op.drop_table("incidents")
    op.drop_table("security_events")
    op.drop_table("documents")
    op.drop_table("users")
