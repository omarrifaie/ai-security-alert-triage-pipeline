"""FastAPI application that renders the triage dashboard."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ai_triage.config import get_settings
from ai_triage.db import models, repositories
from ai_triage.db.session import get_session, init_engine
from ai_triage.enums import coerce_enum

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _db_session() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def create_app() -> FastAPI:
    settings = get_settings()
    init_engine(settings.database_url)

    application = FastAPI(
        title="AI Security Alert Triage",
        description=("Dashboard for browsing CodeQL findings triaged by an OpenAI-backed agent."),
        version="0.1.0",
    )

    if _STATIC_DIR.exists():
        application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @application.get("/health", response_class=HTMLResponse, include_in_schema=False)
    def healthcheck() -> HTMLResponse:
        return HTMLResponse("<h1>OK</h1>")

    @application.get("/", response_class=HTMLResponse)
    def index(
        request: Request,
        repository: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        status: str | None = Query(default=None),
        rule: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
        session: Session = Depends(_db_session),
    ) -> HTMLResponse:
        sev = coerce_enum(models.Severity, severity)
        rem_status = coerce_enum(models.RemediationStatus, status)

        findings = repositories.list_findings_with_filters(
            session,
            repository=repository,
            severity=sev,
            status=rem_status,
            rule_id=rule,
            limit=limit,
        )
        severity_counts = repositories.severity_breakdown(session, repository=repository)
        remediation_counts = repositories.remediation_summary(session)
        recent_scans = repositories.list_recent_scans(session, limit=10)

        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "findings": findings,
                "severity_counts": severity_counts,
                "remediation_counts": remediation_counts,
                "recent_scans": recent_scans,
                "filters": {
                    "repository": repository or "",
                    "severity": severity or "",
                    "status": status or "",
                    "rule": rule or "",
                    "limit": limit,
                },
                "severity_options": [member.value for member in models.Severity],
                "status_options": [member.value for member in models.RemediationStatus],
            },
        )

    @application.get("/findings/{finding_id}", response_class=HTMLResponse, name="finding_detail")
    def finding_detail(
        request: Request,
        finding_id: int,
        session: Session = Depends(_db_session),
    ) -> HTMLResponse:
        finding = repositories.get_finding(session, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found.")

        return templates.TemplateResponse(
            request,
            "finding.html",
            {
                "finding": finding,
                "status_options": [member.value for member in models.RemediationStatus],
            },
        )

    @application.post("/findings/{finding_id}/remediation")
    def update_remediation(
        request: Request,
        finding_id: int,
        status: str = Form(...),
        notes: str = Form(default=""),
        assignee: str = Form(default=""),
        pr_url: str = Form(default=""),
        session: Session = Depends(_db_session),
    ) -> RedirectResponse:
        rem_status = coerce_enum(models.RemediationStatus, status)
        if rem_status is None:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

        finding = repositories.get_finding(session, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found.")

        repositories.update_remediation(
            session,
            finding_id=finding_id,
            status=rem_status,
            notes=notes or None,
            assignee=assignee or None,
            pull_request_url=pr_url or None,
        )
        session.commit()
        return RedirectResponse(
            url=str(request.url_for("finding_detail", finding_id=finding_id)),
            status_code=303,
        )

    return application


app = create_app()
