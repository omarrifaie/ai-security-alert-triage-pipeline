"""initial schema

Revision ID: 202604250001
Revises:
Create Date: 2026-04-25 00:00:00

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "202604250001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SEVERITY_VALUES = ("info", "low", "medium", "high", "critical")
REMEDIATION_VALUES = (
    "open",
    "in_progress",
    "fixed",
    "false_positive",
    "wont_fix",
    "suppressed",
)


def upgrade() -> None:
    bind = op.get_bind()
    postgresql.ENUM(*SEVERITY_VALUES, name="severity_enum").create(bind, checkfirst=True)
    postgresql.ENUM(
        *REMEDIATION_VALUES, name="remediation_status_enum"
    ).create(bind, checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("repository", sa.String(length=255), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("branch", sa.String(length=255), nullable=True),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=True),
        sa.Column("sarif_path", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("ix_scans_repository", "scans", ["repository"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_name", sa.String(length=512), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column(
            "severity_hint",
            postgresql.ENUM(*SEVERITY_VALUES, name="severity_enum", create_type=False),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("help_uri", sa.String(length=1024), nullable=True),
        sa.Column(
            "tags",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
        sa.Column(
            "properties",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_severity_hint", "findings", ["severity_hint"])

    op.create_table(
        "triage_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "severity",
            postgresql.ENUM(*SEVERITY_VALUES, name="severity_enum", create_type=False),
            nullable=False,
        ),
        sa.Column("false_positive_likelihood", sa.Float(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("suggested_action", sa.Text(), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column(
            "raw_response",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("ix_triage_results_finding_id", "triage_results", ["finding_id"])

    op.create_table(
        "remediations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                *REMEDIATION_VALUES,
                name="remediation_status_enum",
                create_type=False,
            ),
            nullable=False,
            server_default="open",
        ),
        sa.Column("assignee", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("pull_request_url", sa.String(length=1024), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("ix_remediations_finding_id", "remediations", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_remediations_finding_id", table_name="remediations")
    op.drop_table("remediations")
    op.drop_index("ix_triage_results_finding_id", table_name="triage_results")
    op.drop_table("triage_results")
    op.drop_index("ix_findings_severity_hint", table_name="findings")
    op.drop_index("ix_findings_rule_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_repository", table_name="scans")
    op.drop_table("scans")

    bind = op.get_bind()
    postgresql.ENUM(
        *REMEDIATION_VALUES,
        name="remediation_status_enum",
        create_type=False,
    ).drop(bind, checkfirst=True)
    postgresql.ENUM(
        *SEVERITY_VALUES,
        name="severity_enum",
        create_type=False,
    ).drop(bind, checkfirst=True)
