"""Typer based command line interface."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ai_triage.config import get_settings
from ai_triage.db import models, repositories
from ai_triage.db.session import init_engine, session_scope
from ai_triage.services import ingest_sarif, run_triage
from ai_triage.triage import TriageAgent

app = typer.Typer(
    add_completion=False,
    help="Operate the AI security alert triage pipeline.",
    no_args_is_help=True,
)
console = Console()


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@app.callback()
def _root(
    log_level: str = typer.Option(
        None,
        "--log-level",
        envvar="LOG_LEVEL",
        help="Override the default log level.",
    ),
) -> None:
    settings = get_settings()
    _configure_logging(log_level or settings.log_level)
    init_engine(settings.database_url)


@app.command("ingest")
def ingest_command(
    sarif: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True),
    repository: str = typer.Option(
        None,
        "--repository",
        "-r",
        help="GitHub-style repository identifier (defaults to DEFAULT_REPOSITORY).",
    ),
    commit_sha: str | None = typer.Option(None, "--commit", help="Commit SHA tied to the scan."),
    branch: str | None = typer.Option(None, "--branch", help="Branch the scan was run against."),
) -> None:
    """Parse a SARIF file and store its findings in PostgreSQL."""
    settings = get_settings()
    repo = repository or settings.default_repository

    with session_scope() as session:
        report = ingest_sarif(
            session,
            sarif,
            repository=repo,
            commit_sha=commit_sha,
            branch=branch,
        )

    console.print(
        f"[green]Ingested[/green] scan [bold]{report.scan_id}[/bold] for "
        f"[cyan]{report.repository}[/cyan] with [bold]{report.total_findings}[/bold] findings."
    )


@app.command("triage")
def triage_command(
    limit: int | None = typer.Option(
        None, "--limit", "-n", help="Maximum number of pending findings to triage."
    ),
    fail_fast: bool = typer.Option(False, "--fail-fast", help="Re-raise the first triage error."),
) -> None:
    """Run the triage agent over every pending finding."""
    agent = TriageAgent()
    with session_scope() as session:
        summary = run_triage(session, agent, limit=limit, raise_on_error=fail_fast)

    console.print(
        f"Triage complete: [green]{summary.processed}[/green] processed, "
        f"[red]{summary.failed}[/red] failed, [yellow]{summary.skipped}[/yellow] skipped."
    )


@app.command("status")
def status_command(
    repository: str | None = typer.Option(None, "--repository", "-r"),
    severity: str | None = typer.Option(None, "--severity"),
    state: str | None = typer.Option(
        None, "--status", help="Filter by remediation status (open, in_progress, fixed, ...)."
    ),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """Print a table of findings and their remediation state."""
    sev = _parse_enum(models.Severity, severity)
    rem_status = _parse_enum(models.RemediationStatus, state)

    with session_scope() as session:
        findings = repositories.list_findings_with_filters(
            session,
            repository=repository,
            severity=sev,
            status=rem_status,
            limit=limit,
        )

        table = Table(title="Findings", expand=True)
        table.add_column("ID", justify="right", style="bold")
        table.add_column("Repository")
        table.add_column("Rule")
        table.add_column("Severity")
        table.add_column("Triage")
        table.add_column("Status")
        table.add_column("File")

        for finding in findings:
            triage = finding.triage
            remediation = finding.remediation
            table.add_row(
                str(finding.id),
                finding.scan.repository,
                finding.rule_id,
                finding.severity_hint.value,
                triage.severity.value if triage else "-",
                remediation.status.value if remediation else "-",
                finding.file_path or "-",
            )

    console.print(table)


@app.command("set-status")
def set_status_command(
    finding_id: int = typer.Argument(..., help="Finding ID to update."),
    status: str = typer.Argument(..., help="New remediation status."),
    notes: str | None = typer.Option(None, "--notes"),
    assignee: str | None = typer.Option(None, "--assignee"),
    pr_url: str | None = typer.Option(None, "--pr-url"),
) -> None:
    """Update the remediation status for a single finding."""
    rem_status = _parse_enum(models.RemediationStatus, status, required=True)
    assert rem_status is not None  # narrowing for type checkers

    with session_scope() as session:
        repositories.update_remediation(
            session,
            finding_id=finding_id,
            status=rem_status,
            notes=notes,
            assignee=assignee,
            pull_request_url=pr_url,
        )

    console.print(
        f"Updated finding [bold]{finding_id}[/bold] to status [cyan]{rem_status.value}[/cyan]."
    )


@app.command("scans")
def scans_command(limit: int = typer.Option(10, "--limit", "-n")) -> None:
    """Show the most recent scans."""
    with session_scope() as session:
        scans = repositories.list_recent_scans(session, limit=limit)

        table = Table(title="Recent scans", expand=True)
        table.add_column("ID", justify="right")
        table.add_column("Repository")
        table.add_column("Branch")
        table.add_column("Tool")
        table.add_column("Findings", justify="right")
        table.add_column("Created")

        for scan in scans:
            table.add_row(
                str(scan.id),
                scan.repository,
                scan.branch or "-",
                f"{scan.tool_name} {scan.tool_version or ''}".strip(),
                str(len(scan.findings)),
                scan.created_at.strftime("%Y-%m-%d %H:%M"),
            )

    console.print(table)


def _parse_enum(enum_cls, value, required: bool = False):
    if value is None:
        if required:
            console.print(
                f"[red]Status is required, expected one of {[m.value for m in enum_cls]}[/red]"
            )
            raise typer.Exit(code=2)
        return None
    try:
        return enum_cls(value.lower())
    except ValueError:
        valid = ", ".join(m.value for m in enum_cls)
        console.print(f"[red]Invalid value '{value}'. Valid options: {valid}[/red]")
        raise typer.Exit(code=2) from None


def main() -> None:  # pragma: no cover - entry point shim
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
