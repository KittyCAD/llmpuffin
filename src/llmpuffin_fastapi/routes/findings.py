"""Finding routes."""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import distinct, func, or_, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import fork_audit
from llmpuffin.config import Profile
from llmpuffin.db import async_session
from llmpuffin.github import GitHubClient
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import AuditProfile, AuditRun, AuditThread, Finding

from llmpuffin_fastapi.deps import get_db, get_github_client, spawn_audit, toast
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/findings/", response_class=HTMLResponse)
async def findings_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    profile_id: str = "",
    severity: str = "",
    difficulty: str = "",
    validated: str = "",  # "yes" | "no" | ""
    has_issue: str = "",  # "yes" | "no" | ""
    q: str = "",
):
    profile_id_int: int | None
    try:
        profile_id_int = int(profile_id) if profile_id else None
    except ValueError:
        profile_id_int = None

    stmt = (
        select(Finding)
        .options(selectinload(Finding.audit_run).selectinload(AuditRun.profile))
        .where(Finding.deleted.is_(False))
        .order_by(Finding.created_at.desc())
    )
    if profile_id_int is not None:
        stmt = stmt.join(AuditRun, Finding.audit_run_id == AuditRun.id).where(
            AuditRun.profile_id == profile_id_int
        )
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if difficulty:
        stmt = stmt.where(Finding.difficulty == difficulty)
    if validated == "yes":
        stmt = stmt.where(Finding.validated.is_(True))
    elif validated == "no":
        stmt = stmt.where(Finding.validated.is_(False))
    if has_issue == "yes":
        stmt = stmt.where(Finding.github_issue_url != "")
    elif has_issue == "no":
        stmt = stmt.where(Finding.github_issue_url == "")
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.rule_id.ilike(pattern),
                Finding.scenario_id.ilike(pattern),
            )
        )

    findings = (await db.execute(stmt)).scalars().all()

    # Collect filter-option facets.
    profiles = (
        (await db.execute(select(AuditProfile).order_by(AuditProfile.name)))
        .scalars()
        .all()
    )
    severities = [
        s
        for (s,) in (
            await db.execute(
                select(distinct(Finding.severity))
                .where(Finding.deleted.is_(False))
                .where(Finding.severity != "")
            )
        ).all()
    ]
    difficulties = [
        d
        for (d,) in (
            await db.execute(
                select(distinct(Finding.difficulty))
                .where(Finding.deleted.is_(False))
                .where(Finding.difficulty != "")
            )
        ).all()
    ]

    # Severity counts (for the chip row).
    sev_counts_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.deleted.is_(False))
            .group_by(Finding.severity)
        )
    ).all()
    sev_counts = {s or "": n for s, n in sev_counts_rows}

    return templates.TemplateResponse(
        request,
        "findings_list.html",
        {
            "findings": findings,
            "profiles": profiles,
            "severities": sorted(severities),
            "difficulties": sorted(difficulties),
            "sev_counts": sev_counts,
            "filters": {
                "profile_id": profile_id_int,
                "severity": severity,
                "difficulty": difficulty,
                "validated": validated,
                "has_issue": has_issue,
                "q": q,
            },
        },
    )


async def _get_finding(db: AsyncSession, finding_id: int) -> Finding | None:
    return (
        await db.execute(
            select(Finding)
            .options(
                selectinload(Finding.audit_run).selectinload(AuditRun.profile),
                selectinload(Finding.locations),
            )
            .where(Finding.id == finding_id)
        )
    ).scalar_one_or_none()


@router.get("/findings/{finding_id}/", response_class=HTMLResponse)
async def finding_detail(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "finding": finding,
            "audit_run": finding.audit_run,
            "github_configured": bool(gh and gh.configured
            and finding.audit_run.github_repo_url),
            "locations": finding.locations,
        },
    )


@router.post("/findings/{finding_id}/issue/")
async def finding_create_issue(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)
    audit_run = finding.audit_run
    redirect = f"/findings/{finding_id}/"

    if not gh or not gh.configured or not audit_run.github_repo_url:
        return toast(
            request, "error", "GitHub App not configured", redirect_to=redirect
        )

    if not finding.title:
        return toast(
            request,
            "error",
            "Title is required to create GitHub issue",
            redirect_to=redirect,
        )

    repo = audit_run.github_repo_url.rstrip("/").removeprefix("https://github.com/")

    repo_info = gh.check_repo_access(repo)
    if repo_info is None:
        return toast(
            request,
            "error",
            "Cannot access repo — is the GitHub App installed?",
            redirect_to=redirect,
        )
    if not repo_info.get("private", False):
        return toast(
            request,
            "error",
            "Refusing to create issues in a public repo (would leak vulnerability details)",
            redirect_to=redirect,
        )

    title = f"{finding.title}"
    body = f"**Severity:** {finding.severity} \n **Difficulty:** {finding.difficulty}\n"
    body += f"**Scenario:** {finding.scenario_id}\n\n"
    body += f"### Description\n\n{finding.description}\n\n"
    body += f"### Impact\n\n{finding.impact}\n\n"
    body += f"### Recommendations\n\n{finding.recommendations}\n"
    if finding.locations:
        body += "\n### Locations\n\n"
        for loc in finding.locations:
            url = audit_run.github_file_url(loc.file_path, loc.start_line)
            if url:
                body += f"{url}\n"
            else:
                body += f"\n {loc.file_path}:{loc.start_line}\n"
    body += "\n---\n*Generated by llmpuffin*"

    if finding.github_issue_url:
        try:
            issue_number = int(
                finding.github_issue_url.rstrip("/").rsplit("/issues/", 1)[1]
            )
        except (IndexError, ValueError):
            return toast(
                request,
                "error",
                f"Cannot parse issue number from {finding.github_issue_url}",
                redirect_to=redirect,
            )
        try:
            issue_url = gh.update_issue(
                repo=repo,
                issue_number=issue_number,
                title=title,
                body=body,
            )
            return toast(
                request,
                "success",
                f"Issue updated: {issue_url}",
                redirect_to=redirect,
                refresh=True,
            )
        except Exception as exc:
            log.exception("Failed to update GitHub issue")
            return toast(
                request,
                "error",
                f"Failed to update issue: {exc}",
                redirect_to=redirect,
            )

    try:
        issue_url = gh.create_issue(
            repo=repo,
            title=title,
            body=body,
            labels=["vulnerability"],
        )
        await db.execute(
            sa_update(Finding)
            .where(Finding.id == finding_id)
            .values(github_issue_url=issue_url)
        )
        await db.commit()
        return toast(
            request,
            "success",
            f"Issue created: {issue_url}",
            redirect_to=redirect,
            refresh=True,
        )
    except Exception as exc:
        log.exception("Failed to create GitHub issue")
        return toast(
            request, "error", f"Failed to create issue: {exc}", redirect_to=redirect
        )


@router.post("/findings/{finding_id}/fork/")
async def finding_fork(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
    message: Annotated[str, Form()] = "",
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)
    run = finding.audit_run
    redirect = f"/findings/{finding_id}/"

    if not finding.thread_id:
        return toast(
            request,
            "error",
            "Finding has no originating thread",
            redirect_to=redirect,
        )

    source_thread = (
        await db.execute(
            select(AuditThread).where(AuditThread.thread_id == finding.thread_id)
        )
    ).scalar_one_or_none()
    if source_thread and source_thread.status == "running":
        return toast(
            request,
            "error",
            "Source thread is still running, cannot fork",
            redirect_to=redirect,
        )

    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return toast(
            request, "error", "No config available for fork", redirect_to=redirect
        )

    finding_context = (
        f"This conversation is forked to investigate finding #{finding.local_id}.\n"
        f"Title: {finding.title}\n"
        f"Scenario: {finding.scenario_id}\n"
        f"Severity: {finding.severity} | Difficulty: {finding.difficulty}\n"
        f"Description: {finding.description[:500]}\n\n"
    )
    user_input = message.strip()
    user_message = finding_context + (
        user_input or "Investigate this finding further. Try to validate or refute it."
    )

    # Pre-generate thread ID so we can link it immediately and navigate to it.
    new_thread_id = uuid.uuid4().hex[:12]
    await db.execute(
        sa_update(Finding)
        .where(Finding.id == finding_id)
        .values(fork_thread_id=new_thread_id)
    )
    await db.commit()

    async def _do_fork():
        profile = Profile.from_toml_string(toml_str)
        harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
        try:
            await fork_audit(
                harness_config,
                source_thread_id=finding.thread_id,
                user_message=user_message,
                thread_id=new_thread_id,
                github_client=gh,
            )
        except Exception:
            log.exception("Background finding fork failed")

    spawn_audit(_do_fork())
    return toast(
        request,
        "success",
        "Fork started",
        redirect_to=f"/checkpoints/{new_thread_id}/",
        refresh=True,
    )
