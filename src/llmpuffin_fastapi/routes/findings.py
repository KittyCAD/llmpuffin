"""Finding routes."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import distinct, func, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from llmpuffin.agent import fork_audit
from llmpuffin.config import Config, Profile
from llmpuffin.github import GitHubClient
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import (
    AuditProfile,
    AuditRun,
    AuditThread,
    Finding,
    FindingAttachment,
    FindingComment,
    FindingLocation,
    GitHubLink,
)

from llmpuffin.db import DB
from llmpuffin.harness import Harness
from llmpuffin_fastapi.deps import (
    get_base_url,
    get_config,
    get_db,
    get_github_client,
    get_harness,
    get_llmpuffin_db,
    toast,
)
from llmpuffin_fastapi.templates_env import templates

log = logging.getLogger("llmpuffin")
router = APIRouter()


def _repo_from_github_url(url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL like https://github.com/owner/repo/..."""
    url = url.rstrip("/")
    if "github.com/" not in url:
        return None
    parts = url.split("github.com/", 1)[1].split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


@router.get("/findings/", response_class=HTMLResponse)
async def findings_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    profile_id: str = "",
    status: str = "",  # "open" | "fixed" | "invalid" | "deleted" | ""
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
    # By default hide deleted; explicit status filter overrides.
    if status:
        stmt = stmt.where(Finding.status == status)
    else:
        stmt = stmt.where(Finding.status != "deleted")
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


async def _find_similar(
    db: AsyncSession, finding: Finding, *, threshold: float = 0.3, limit: int = 10
) -> list[tuple[Finding, float]]:
    """Find other findings with at least one location whose file_path is
    similar (trigram similarity) to any of this finding's locations.

    The score combines file path similarity (70%) with line proximity (30%).
    Line proximity is 1/(1 + abs(line_diff)/20), so lines within ~20 of each
    other score high, and distant lines still get partial credit.

    Returns (finding, best_score) pairs sorted by score descending.
    """
    if not finding.locations:
        return []

    # For each of our locations, build a combined score expression against
    # each candidate location: path_sim * 0.7 + line_proximity * 0.3
    score_exprs = []
    for loc in finding.locations:
        path_sim = func.similarity(FindingLocation.file_path, loc.file_path)
        line_diff = func.abs(FindingLocation.start_line - loc.start_line)
        line_prox = 1.0 / (1.0 + line_diff / 20.0)
        score_exprs.append(path_sim * 0.7 + line_prox * 0.3)

    best_score = (
        score_exprs[0] if len(score_exprs) == 1 else func.greatest(*score_exprs)
    )

    # Subquery: candidate finding IDs with their best combined score.
    candidates = (
        select(
            FindingLocation.finding_id,
            func.max(best_score).label("score"),
        )
        .where(
            FindingLocation.finding_id != finding.id,
            best_score >= threshold,
        )
        .group_by(FindingLocation.finding_id)
        .subquery()
    )

    rows = (
        await db.execute(
            select(Finding, candidates.c.score)
            .join(candidates, Finding.id == candidates.c.finding_id)
            .where(Finding.status != "deleted")
            .options(
                selectinload(Finding.locations),
                selectinload(Finding.audit_run).selectinload(AuditRun.profile),
            )
            .order_by(candidates.c.score.desc())
            .limit(limit)
        )
    ).all()

    return [(row[0], round(row[1], 2)) for row in rows]


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

    from llmpuffin.checkpoint import get_session

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

    similar_findings = await _find_similar(db, finding)

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
    db: Annotated[AsyncSession, Depends(get_db)],
    title: Annotated[str | None, Form()] = None,
    status: Annotated[str | None, Form()] = None,
    severity: Annotated[str | None, Form()] = None,
    difficulty: Annotated[str | None, Form()] = None,
    validated: Annotated[str | None, Form()] = None,
):
    finding = await _get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=404)
    redirect = f"/findings/{finding_id}/"
    values: dict = {}
    if title is not None:
        values["title"] = title
    if status is not None and status in ("open", "fixed", "invalid", "deleted"):
        values["status"] = status
    if severity is not None and severity in ("high", "medium", "low", "informational"):
        values["severity"] = severity
    if difficulty is not None and difficulty in ("high", "medium", "low"):
        values["difficulty"] = difficulty
    if validated is not None:
        values["validated"] = validated == "yes"
    if values:
        await db.execute(
            sa_update(Finding).where(Finding.id == finding_id).values(**values)
        )
        await db.commit()
    return toast(
        request, "success", "Finding updated", redirect_to=redirect, refresh=True
    )


@router.post("/findings/{finding_id}/report/")
async def finding_report_to_github(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    base_url: Annotated[str, Depends(get_base_url)],
    gh: Annotated[GitHubClient | None, Depends(get_github_client)] = None,
):
    """Report a finding to GitHub.

    Public repos + findings_repo configured → issue in the private issues repo.
    Public repos (no findings_repo)         → draft security advisory.
    Private repos                         → GitHub issue in the source repo.
    """
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
        return toast(request, "error", "Title is required", redirect_to=redirect)

    repo = audit_run.github_repo_url.rstrip("/").removeprefix("https://github.com/")
    repo_info = gh.check_repo_access(repo)
    if repo_info is None:
        return toast(
            request,
            "error",
            "Cannot access repo — is the GitHub App installed?",
            redirect_to=redirect,
        )

    is_private = repo_info.get("private", False)

    # Build the body (shared between advisory and issue).
    title = f"{finding.title}"
    body = (
        f"**Severity:** {finding.severity} | **Difficulty:** {finding.difficulty}\n\n"
    )
    body += f"## Description\n\n{finding.description}\n\n"
    body += f"## Exploit Scenario\n\n{finding.exploit_scenario}\n\n"
    body += f"## Recommendations\n\n{finding.recommendations}\n"
    if finding.locations:
        body += "\n## Locations\n\n"
        for loc in finding.locations:
            url = loc.github_url()
            if url:
                body += f"{url}\n\n"
            else:
                body += f"- {loc.file_path}:{loc.start_line}\n\n"
    if base_url:
        body += f"\n---\n*Generated by [llmpuffin]({base_url}/findings/{finding_id}/)*"
    else:
        body += "\n---\n*Generated by llmpuffin*"

    # If an issue/advisory already exists, update it.
    if finding.github_link:
        link = finding.github_link
        # Derive the repo the issue/advisory lives in from the stored URL,
        # since it may be in findings_repo rather than the source repo.
        link_repo = _repo_from_github_url(link.github_url) or repo
        # If the issue lives in a different repo (findings_repo), include source context.
        update_body = body
        if link_repo != repo:
            update_body = f"**Source repo:** {audit_run.github_repo_url}\n\n{body}"
        if link.github_type == "issue":
            issue_state = (
                "closed"
                if finding.status in ("fixed", "invalid", "deleted")
                else "open"
            )
            try:
                gh.update_issue(
                    repo=link_repo,
                    issue_number=int(link.github_id),
                    title=title,
                    body=update_body,
                    state=issue_state,
                )
                return toast(
                    request,
                    "success",
                    "Issue updated",
                    redirect_to=redirect,
                    refresh=True,
                )
            except Exception as exc:
                log.exception("Failed to update GitHub issue")
                return toast(
                    request,
                    "error",
                    f"Failed to update: {exc}",
                    redirect_to=redirect,
                )
        else:
            if finding.status != "open":
                log.warning(
                    "Finding %d has status '%s' but advisory state sync is not supported — "
                    "advisory %s must be managed manually on GitHub",
                    finding_id,
                    finding.status,
                    link.github_id,
                )
            try:
                gh.update_advisory(
                    repo=link_repo,
                    ghsa_id=link.github_id,
                    summary=title,
                    description=body,
                    severity=finding.severity,
                )
                return toast(
                    request,
                    "success",
                    "Advisory updated",
                    redirect_to=redirect,
                    refresh=True,
                )
            except Exception as exc:
                log.exception("Failed to update GitHub advisory")
                return toast(
                    request,
                    "error",
                    f"Failed to update: {exc}",
                    redirect_to=redirect,
                )

    # Public repo + findings_repo configured → issue in the private issues repo.
    if not is_private and gh.findings_repo:
        findings_repo_info = gh.check_repo_access(gh.findings_repo)
        if findings_repo_info is None:
            return toast(
                request,
                "error",
                f"Cannot access issues repo '{gh.findings_repo}' — is the GitHub App installed?",
                redirect_to=redirect,
            )
        if not findings_repo_info.get("private", False):
            return toast(
                request,
                "error",
                f"Issues repo '{gh.findings_repo}' is not private — refusing to post findings to a public repo",
                redirect_to=redirect,
            )
        try:
            issue_url = gh.create_issue(
                repo=gh.findings_repo,
                title=title,
                body=f"**Source repo:** {audit_run.github_repo_url}\n\n{body}",
                labels=["vulnerability"],
            )
            issue_number = issue_url.rstrip("/").rsplit("/", 1)[-1]
            db.add(
                GitHubLink(
                    finding_id=finding_id,
                    github_type="issue",
                    github_id=issue_number,
                    github_url=issue_url,
                )
            )
            await db.commit()
            return toast(
                request,
                "success",
                f"Issue created in {gh.findings_repo}",
                redirect_to=redirect,
                refresh=True,
            )
        except Exception as exc:
            log.exception("Failed to create issue in findings_repo")
            return toast(
                request,
                "error",
                f"Failed to create issue: {exc}",
                redirect_to=redirect,
            )

    # Public repo (no findings_repo) → draft security advisory (safe, not publicly visible).
    if not is_private:
        try:
            advisory_url = gh.create_draft_advisory(
                repo=repo,
                summary=title,
                description=body,
                severity=finding.severity,
            )
            # Extract GHSA-* id from URL.
            ghsa_id = advisory_url.rstrip("/").rsplit("/", 1)[-1]
            db.add(
                GitHubLink(
                    finding_id=finding_id,
                    github_type="advisory",
                    github_id=ghsa_id,
                    github_url=advisory_url,
                )
            )
            await db.commit()
            return toast(
                request,
                "success",
                "Draft security advisory created",
                redirect_to=redirect,
                refresh=True,
            )
        except Exception as exc:
            log.exception("Failed to create advisory")
            return toast(
                request,
                "error",
                f"Failed to create advisory: {exc}",
                redirect_to=redirect,
            )

    # Private repo → GitHub issue.
    try:
        issue_url = gh.create_issue(
            repo=repo,
            title=title,
            body=body,
            labels=["vulnerability"],
        )
        issue_number = issue_url.rstrip("/").rsplit("/", 1)[-1]
        db.add(
            GitHubLink(
                finding_id=finding_id,
                github_type="issue",
                github_id=issue_number,
                github_url=issue_url,
            )
        )
        await db.commit()
        return toast(
            request,
            "success",
            "Issue created",
            redirect_to=redirect,
            refresh=True,
        )
    except Exception as exc:
        log.exception("Failed to create GitHub issue")
        return toast(
            request,
            "error",
            f"Failed to create issue: {exc}",
            redirect_to=redirect,
        )


@router.post("/findings/{finding_id}/fork/")
async def finding_fork(
    finding_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    llmpuffin_db: Annotated[DB, Depends(get_llmpuffin_db)],
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
    if source_thread and source_thread.status == "running":
        return _fork_error("Source thread is still running, cannot fork")

    toml_str = run.profile_toml or (run.profile.profile_toml if run.profile else "")
    if not toml_str:
        return _fork_error("No config available for fork")

    finding_context = (
        f"This conversation is forked to investigate finding #{finding.local_id}.\n"
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity} | Difficulty: {finding.difficulty}\n"
        f"Description: {finding.description[:500]}\n\n"
    )
    user_input = message.strip()
    user_message = finding_context + (
        user_input or "Investigate this finding further. Try to validate or refute it."
    )

    # Capture values before the session closes — _do_fork runs in background.
    source_thread_id = finding.thread_id
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
                source_thread_id=source_thread_id,
                user_message=user_message,
                db=llmpuffin_db,
                global_config=config,
                thread_id=new_thread_id,
                github_client=gh,
            )
        except Exception:
            log.exception("Background finding fork failed")

    harness.spawn(new_thread_id, _do_fork())

    # Re-fetch to get updated fork_thread_id, load fork session/thread for the
    # conversation partial (may be empty — messages div will start polling immediately).
    await db.refresh(finding)
    from llmpuffin.checkpoint import get_session

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
    db: Annotated[AsyncSession, Depends(get_db)],
    body: Annotated[str, Form()],
):
    redirect = f"/findings/{finding_id}/"
    if not body.strip():
        return toast(request, "error", "Comment cannot be empty", redirect_to=redirect)
    db.add(FindingComment(finding_id=finding_id, body=body.strip()))
    await db.commit()
    return toast(
        request, "success", "Comment added", redirect_to=redirect, refresh=True
    )


@router.post("/findings/{finding_id}/comments/{comment_id}/edit/")
async def finding_comment_edit(
    finding_id: int,
    comment_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    body: Annotated[str, Form()],
):
    redirect = f"/findings/{finding_id}/"
    comment = (
        await db.execute(
            select(FindingComment).where(
                FindingComment.id == comment_id,
                FindingComment.finding_id == finding_id,
            )
        )
    ).scalar_one_or_none()
    if comment is None:
        raise HTTPException(status_code=404)
    comment.body = body.strip()
    await db.commit()
    return toast(
        request, "success", "Comment updated", redirect_to=redirect, refresh=True
    )


@router.post("/findings/{finding_id}/comments/{comment_id}/delete/")
async def finding_comment_delete(
    finding_id: int,
    comment_id: int,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    redirect = f"/findings/{finding_id}/"
    comment = (
        await db.execute(
            select(FindingComment).where(
                FindingComment.id == comment_id,
                FindingComment.finding_id == finding_id,
            )
        )
    ).scalar_one_or_none()
    if comment is None:
        raise HTTPException(status_code=404)
    await db.delete(comment)
    await db.commit()
    return toast(
        request, "success", "Comment deleted", redirect_to=redirect, refresh=True
    )
