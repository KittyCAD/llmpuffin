"""Finding routes."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import fork_audit
from llmpuffin.config import Config, Profile
from llmpuffin.github import GitHubClient
from llmpuffin.agent.harness import HarnessConfig
from llmpuffin.services.finding import FindingService
from llmpuffin.models import (
    AuditProfile,
    AuditRun,
    AuditThread,
    Finding,
    FindingAttachment,
)

from llmpuffin.db import DB
from llmpuffin.agent.harness import Harness
from llmpuffin_fastapi.deps import (
    get_base_url,
    get_config,
    get_db,
    get_finding_service,
    get_github_client,
    get_harness,
    get_llmpuffin_db,
    toast,
)
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


@router.get("/findings/", response_class=HTMLResponse)
async def findings_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    profile_id: str = "",
    status: str = "",  # "open" | "fixed" | "invalid" | "deleted" | "duplicate" | ""
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
        .options(
            selectinload(Finding.audit_run).selectinload(AuditRun.profile),
            selectinload(Finding.github_link),
        )
        .order_by(Finding.created_at.desc())
    )
    # By default hide deleted and duplicates; explicit status filter overrides.
    if status:
        stmt = stmt.where(Finding.status == status)
    else:
        stmt = stmt.where(Finding.status.notin_(["deleted", "duplicate"]))
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
        stmt = stmt.where(Finding.github_link.has())
    elif has_issue == "no":
        stmt = stmt.where(~Finding.github_link.has())
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(Finding.title.ilike(pattern))

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
                .where(Finding.status != "deleted")
                .where(Finding.severity != "")
            )
        ).all()
    ]
    difficulties = [
        d
        for (d,) in (
            await db.execute(
                select(distinct(Finding.difficulty))
                .where(Finding.status != "deleted")
                .where(Finding.difficulty != "")
            )
        ).all()
    ]

    # Severity counts (for the chip row).
    sev_counts_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.status != "deleted")
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
                "status": status,
                "severity": severity,
                "difficulty": difficulty,
                "validated": validated,
                "has_issue": has_issue,
                "q": q,
            },
            "show_filters": True,
            "show_profile": True,
            "show_run": True,
        },
    )


@router.get("/findings/clusters/", response_class=HTMLResponse)
async def findings_clusters(
    request: Request,
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    db: Annotated[AsyncSession, Depends(get_db)],
    threshold: float = 0.8,
):
    from llmpuffin.services.embeddings import cluster_findings

    clusters = cluster_findings(db=llmpuffin_db, threshold=threshold)

    # Load full Finding objects for each cluster.
    all_ids = [fid for c in clusters for fid in c.finding_ids]
    findings_by_id: dict[int, Finding] = {}
    if all_ids:
        rows = (
            (
                await db.execute(
                    select(Finding)
                    .where(Finding.id.in_(all_ids))
                    .options(
                        selectinload(Finding.audit_run).selectinload(AuditRun.profile),
                    )
                )
            )
            .scalars()
            .all()
        )
        findings_by_id = {f.id: f for f in rows}

    enriched_clusters = []
    for cluster in clusters:
        findings = [
            findings_by_id[fid] for fid in cluster.finding_ids if fid in findings_by_id
        ]
        if len(findings) >= 2:
            enriched_clusters.append(findings)

    return templates.TemplateResponse(
        request,
        "findings_clusters.html",
        {
            "clusters": enriched_clusters,
            "threshold": threshold,
            "total_findings": sum(len(c) for c in enriched_clusters),
        },
    )


@router.post("/findings/merge/")
async def findings_merge(
    request: Request,
    svc: Annotated[FindingService, Depends(get_finding_service)],
):
    """Merge findings: keep one as canonical, mark the rest as duplicate.

    Expects form data with:
      - keep_id: the finding ID to keep
      - finding_ids: IDs of all selected findings (including keep_id)
    """
    form = await request.form()
    keep_id = str(form.get("keep_id", ""))
    finding_ids = [str(v) for v in form.getlist("finding_ids")]

    if not keep_id or not finding_ids:
        return toast(
            request, "error", "No findings selected", redirect_to="/findings/clusters/"
        )

    keep_id_int = int(keep_id)
    all_ids = [int(fid) for fid in finding_ids]

    if len(all_ids) < 2:
        return toast(
            request,
            "error",
            "Select at least two findings",
            redirect_to="/findings/clusters/",
        )

    count = await svc.merge_duplicates(keep_id_int, all_ids)

    return toast(
        request,
        "success",
        f"Merged {count} finding(s) as duplicate",
        redirect_to="/findings/clusters/",
        refresh=True,
    )


async def _get_finding(db: AsyncSession, finding_id: int) -> Finding | None:
    return (
        await db.execute(
            select(Finding)
            .options(
                selectinload(Finding.audit_run).selectinload(AuditRun.profile),
                selectinload(Finding.locations),
                selectinload(Finding.attachments),
                selectinload(Finding.validation_notes),
                selectinload(Finding.github_link),
                selectinload(Finding.comments),
            )
            .where(Finding.id == finding_id)
        )
    ).scalar_one_or_none()


@router.get("/findings/{finding_id}/", response_class=HTMLResponse)
async def finding_detail(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)

    from llmpuffin.agent.checkpoint import get_session

    fork_session = None
    fork_thread = None
    if finding.fork_thread_id:
        fork_session = await get_session(finding.fork_thread_id, db=llmpuffin_db)
        fork_thread = (
            await db.execute(
                select(AuditThread).where(
                    AuditThread.thread_id == finding.fork_thread_id
                )
            )
        ).scalar_one_or_none()

    from llmpuffin.services.embeddings import find_similar_findings

    similar_findings = await find_similar_findings(finding_id, db=llmpuffin_db)

    return templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "finding": finding,
            "audit_run": finding.audit_run,
            "github_configured": bool(
                gh and gh.configured and finding.audit_run.github_repo_url
            ),
            "locations": finding.locations,
            "fork_session": fork_session,
            "fork_thread": fork_thread,
            "similar_findings": similar_findings,
        },
    )


@router.post("/findings/{finding_id}/edit/")
async def finding_edit(
    finding_id: int,
    request: Request,
    svc: Annotated[FindingService, Depends(get_finding_service)],
    title: Annotated[str | None, Form()] = None,
    status: Annotated[str | None, Form()] = None,
    severity: Annotated[str | None, Form()] = None,
    difficulty: Annotated[str | None, Form()] = None,
    validated: Annotated[str | None, Form()] = None,
):
    redirect = f"/findings/{finding_id}/"
    values: dict = {}
    if title is not None:
        values["title"] = title
    if status is not None and status in (
        "open",
        "fixed",
        "invalid",
        "deleted",
        "duplicate",
    ):
        values["status"] = status
    if severity is not None and severity in ("high", "medium", "low", "informational"):
        values["severity"] = severity
    if difficulty is not None and difficulty in ("high", "medium", "low"):
        values["difficulty"] = difficulty
    if validated is not None:
        values["validated"] = validated == "yes"
    if values:
        if not await svc.update_by_pk(finding_id, **values):
            raise HTTPException(status_code=404)
    return toast(
        request, "success", "Finding updated", redirect_to=redirect, refresh=True
    )


@router.post("/findings/{finding_id}/report/")
async def finding_report_to_github(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    base_url: Annotated[str, Depends(get_base_url)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)
    redirect = f"/findings/{finding_id}/"

    if not gh or not gh.configured:
        return toast(
            request, "error", "GitHub App not configured", redirect_to=redirect
        )

    from llmpuffin.services.github import report_finding_to_github

    result = await report_finding_to_github(
        finding, gh=gh, db=llmpuffin_db, base_url=base_url
    )
    level = "success" if result.success else "error"
    return toast(
        request, level, result.message, redirect_to=redirect, refresh=result.success
    )


@router.post("/findings/{finding_id}/fork/")
async def finding_fork(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
    svc: Annotated[FindingService, Depends(get_finding_service)],
    harness: Annotated[Harness, Depends(get_harness)],
    config: Annotated[Config, Depends(get_config)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
    message: Annotated[str, Form()] = "",
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)
    run = finding.audit_run

    def _fork_error(message: str):
        """Return 204 + toast error — don't replace the form."""
        return Response(
            status_code=204,
            headers={
                "HX-Trigger": json.dumps(
                    {"toast": {"level": "error", "message": message}}
                )
            },
        )

    if not finding.thread_id:
        return _fork_error("Finding has no originating thread")

    if finding.fork_thread_id:
        return _fork_error("Finding already has a fork")

    source_thread = (
        await db.execute(
            select(AuditThread).where(AuditThread.thread_id == finding.thread_id)
        )
    ).scalar_one_or_none()
    if (
        source_thread
        and source_thread.status == "running"
        and not config.features.enabled("fork_running_threads")
    ):
        return _fork_error("Source thread is still running, cannot fork")

    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return _fork_error("No config available for fork")

    user_message = svc.build_fork_message(finding, message)

    # Capture values before the session closes — _do_fork runs in background.
    source_thread_id = finding.thread_id
    new_thread_id = uuid.uuid4().hex[:12]

    await svc.set_fork_thread(finding_id, new_thread_id)

    async def _do_fork():
        profile = Profile.from_toml_string(toml_str)
        harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
        try:
            await fork_audit(
                harness_config,
                source_thread_id=source_thread_id,
                user_message=user_message,
                db=llmpuffin_db,
                global_config=config,
                thread_id=new_thread_id,
                github_client=gh,
            )
        except Exception as exc:
            log.exception("Background finding fork failed", exc)

    harness.spawn(new_thread_id, _do_fork())

    # Re-fetch to get updated fork_thread_id, load fork session/thread for the
    # conversation partial (may be empty — messages div will start polling immediately).
    await db.refresh(finding)
    from llmpuffin.agent.checkpoint import get_session

    fork_session = await get_session(new_thread_id, db=llmpuffin_db)
    fork_thread = (
        await db.execute(
            select(AuditThread).where(AuditThread.thread_id == new_thread_id)
        )
    ).scalar_one_or_none()

    return templates.TemplateResponse(
        request,
        "_finding_fork.html",
        {
            "finding": finding,
            "fork_session": fork_session,
            "fork_thread": fork_thread,
        },
        headers={
            "HX-Trigger": json.dumps(
                {"toast": {"level": "success", "message": "Fork started"}}
            )
        },
    )


@router.get("/findings/{finding_id}/attachments/{attachment_id}/")
async def finding_attachment_download(
    finding_id: int,
    attachment_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    att = (
        await db.execute(
            select(FindingAttachment).where(
                FindingAttachment.id == attachment_id,
                FindingAttachment.finding_id == finding_id,
            )
        )
    ).scalar_one_or_none()
    if att is None:
        raise HTTPException(status_code=404)

    import mimetypes

    basename = att.filename.rsplit("/", 1)[-1] if "/" in att.filename else att.filename
    mime, _ = mimetypes.guess_type(basename)
    return Response(
        content=att.content,
        media_type=mime or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{basename}"',
        },
    )


# ─── Comments ───


@router.post("/findings/{finding_id}/comments/")
async def finding_comment_add(
    finding_id: int,
    request: Request,
    svc: Annotated[FindingService, Depends(get_finding_service)],
    body: Annotated[str, Form()],
):
    redirect = f"/findings/{finding_id}/"
    if not body.strip():
        return toast(request, "error", "Comment cannot be empty", redirect_to=redirect)
    await svc.add_comment(finding_id, body.strip())
    return toast(
        request, "success", "Comment added", redirect_to=redirect, refresh=True
    )


@router.post("/findings/{finding_id}/comments/{comment_id}/edit/")
async def finding_comment_edit(
    finding_id: int,
    comment_id: int,
    request: Request,
    svc: Annotated[FindingService, Depends(get_finding_service)],
    body: Annotated[str, Form()],
):
    redirect = f"/findings/{finding_id}/"
    if not await svc.update_comment(comment_id, finding_id, body.strip()):
        raise HTTPException(status_code=404)
    return toast(
        request, "success", "Comment updated", redirect_to=redirect, refresh=True
    )


@router.post("/findings/{finding_id}/comments/{comment_id}/delete/")
async def finding_comment_delete(
    finding_id: int,
    comment_id: int,
    request: Request,
    svc: Annotated[FindingService, Depends(get_finding_service)],
):
    redirect = f"/findings/{finding_id}/"
    if not await svc.delete_comment(comment_id, finding_id):
        raise HTTPException(status_code=404)
    return toast(
        request, "success", "Comment deleted", redirect_to=redirect, refresh=True
    )
