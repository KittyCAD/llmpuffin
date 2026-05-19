"""Views for the llmpuffin web UI."""

from __future__ import annotations

import asyncio
import logging
import threading

import tomllib
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from llmpuffin.agent import fork_audit, run_audit
from llmpuffin.config import Profile
from llmpuffin.harness import HarnessConfig
from llmpuffin.models import AuditProfile, AuditRun, AuditThread, Finding
from llmpuffin_web.checkpoint import get_session, list_sessions
from llmpuffin_web.store import list_items as list_store_items
from llmpuffin_web.store import list_namespaces as list_store_namespaces

log = logging.getLogger("llmpuffin")


def _run_coro(coro):
    """Run a coroutine with an executor that survives interpreter shutdown.

    Sets a custom default executor on the loop that ignores the global
    concurrent.futures _shutdown flag. This ensures Django's async ORM
    (asave/afirst via sync_to_async → loop.run_in_executor) can still
    write to the DB during finalization after Ctrl+C.
    """
    import concurrent.futures.thread as _cft
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures._base import Future
    from concurrent.futures.thread import _WorkItem

    class _Executor(ThreadPoolExecutor):
        def _adjust_thread_count(self):
            super()._adjust_thread_count()
            for t in self._threads:
                _cft._threads_queues.pop(t, None)  # type: ignore[attr-defined]

        def submit(self, fn, /, *args, **kwargs):
            with self._shutdown_lock:
                if self._broken:
                    raise RuntimeError(self._broken)
                if self._shutdown:
                    raise RuntimeError("cannot schedule new futures after shutdown")
                f = Future()
                w = _WorkItem(f, fn, args, kwargs)
                self._work_queue.put(w)
                self._adjust_thread_count()
                return f

    loop = asyncio.new_event_loop()
    executor = _Executor(max_workers=4)
    loop.set_default_executor(executor)
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            executor.shutdown(wait=True)
            asyncio.set_event_loop(None)
            loop.close()


def checkpoints_list(request: HttpRequest) -> HttpResponse:
    sessions = list_sessions()
    return render(
        request, "llmpuffin_web/checkpoints_list.html", {"sessions": sessions}
    )


def checkpoint_detail(request: HttpRequest, thread_id: str) -> HttpResponse:
    session = get_session(thread_id)
    if session is None:
        return render(
            request,
            "llmpuffin_web/error.html",
            {
                "title": "Checkpoint not found",
                "message": f"No checkpoint data for thread {thread_id}.",
            },
            status=404,
        )
    audit_thread = (
        AuditThread.objects.filter(thread_id=thread_id)
        .select_related("audit_run")
        .first()
    )
    ctx: dict = {"session": session, "audit_thread": audit_thread}
    if request.GET.get("success"):
        ctx["success"] = request.GET["success"]
    if request.GET.get("error"):
        ctx["error"] = request.GET["error"]
    return render(request, "llmpuffin_web/checkpoint_detail.html", ctx)


def checkpoint_messages(request: HttpRequest, thread_id: str) -> HttpResponse:
    """HTMX partial: just the messages for a checkpoint thread."""
    session = get_session(thread_id)
    if session is None:
        return HttpResponse("")
    audit_thread = (
        AuditThread.objects.filter(thread_id=thread_id)
        .select_related("audit_run")
        .first()
    )
    return render(
        request,
        "llmpuffin_web/_checkpoint_messages.html",
        {"session": session, "audit_thread": audit_thread},
    )


def checkpoint_resume(request: HttpRequest, thread_id: str) -> HttpResponse:
    """Resume a thread from the checkpoint detail page."""
    audit_thread = get_object_or_404(AuditThread, thread_id=thread_id)
    if audit_thread.status == "running":
        return redirect(f"/checkpoints/{thread_id}/?error=Thread+is+already+running")

    run = audit_thread.audit_run
    toml_str = run.profile_toml
    if not toml_str and run.profile:
        toml_str = run.profile.profile_toml
    if not toml_str:
        return redirect(f"/checkpoints/{thread_id}/?error=No+config+available")

    user_message = request.POST.get("message", "").strip()
    if not user_message:
        return redirect(f"/checkpoints/{thread_id}/?error=Message+is+required")

    thread = threading.Thread(
        target=_run_audit_in_thread,
        args=(toml_str,),
        kwargs={"resume_thread_id": thread_id, "user_message": user_message},
        daemon=False,
    )
    thread.start()
    return redirect(f"/checkpoints/{thread_id}/?success=Resumed")


def profiles_list(request: HttpRequest) -> HttpResponse:
    profiles_qs = AuditProfile.objects.filter(jit=False)
    profiles = []
    for p in profiles_qs:
        try:
            config = p.parsed_config()
            image = config.get("audit", {}).get("image", "")
        except Exception:
            image = "(invalid TOML)"
        profiles.append(
            {"id": p.id, "name": p.name, "image": image, "updated_at": p.updated_at}
        )
    return render(request, "llmpuffin_web/profiles_list.html", {"profiles": profiles})


def profile_create(request: HttpRequest) -> HttpResponse:
    name = request.POST.get("name", "").strip()
    profile_toml = request.POST.get("profile_toml", "").strip()

    if not name or not profile_toml:
        return redirect("/profiles/?error=Name+and+config+are+required")

    try:
        tomllib.loads(profile_toml)
    except Exception as exc:
        profiles = AuditProfile.objects.all()
        return render(
            request,
            "llmpuffin_web/profiles_list.html",
            {
                "profiles": profiles,
                "error": f"Invalid TOML: {exc}",
            },
        )

    AuditProfile.objects.create(name=name, profile_toml=profile_toml)
    return redirect("/profiles/")


def profile_detail(request: HttpRequest, profile_id: int) -> HttpResponse:
    profile = get_object_or_404(AuditProfile, id=profile_id)
    ctx: dict = {"profile": profile, "runs": profile.runs.all()}

    if request.GET.get("error"):
        ctx["error"] = request.GET["error"]
    if request.GET.get("success"):
        ctx["success"] = request.GET["success"]

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        profile_toml = request.POST.get("profile_toml", "").strip()

        try:
            tomllib.loads(profile_toml)
        except Exception as exc:
            ctx["error"] = f"Invalid TOML: {exc}"
            return render(request, "llmpuffin_web/profile_detail.html", ctx)

        profile.name = name
        profile.profile_toml = profile_toml
        profile.save()
        ctx["success"] = "Profile saved."
        ctx["profile"] = profile

    return render(request, "llmpuffin_web/profile_detail.html", ctx)


def runs_list(request: HttpRequest) -> HttpResponse:
    from django.db.models import Count, Q

    runs = (
        AuditRun.objects.select_related("profile")
        .prefetch_related("threads")
        .annotate(
            thread_count=Count("threads", distinct=True),
            finding_count=Count(
                "findings", distinct=True, filter=Q(findings__deleted=False)
            ),
        )
        .order_by("-started_at")
    )
    return render(request, "llmpuffin_web/runs_list.html", {"runs": runs})


def run_delete(request: HttpRequest, run_id: int) -> HttpResponse:
    run = get_object_or_404(AuditRun, id=run_id)
    if run.status == "running":
        return redirect(f"/runs/{run_id}/?error=Cannot+delete+a+running+audit")
    run.delete()
    return redirect("/")


def run_detail(request: HttpRequest, run_id: int) -> HttpResponse:
    run = get_object_or_404(AuditRun, id=run_id)
    ctx: dict = {
        "run": run,
        "threads": run.threads.all(),
        "findings": run.findings.all(),
    }
    if request.GET.get("success"):
        ctx["success"] = request.GET["success"]
    return render(request, "llmpuffin_web/run_detail.html", ctx)


def run_resume(request: HttpRequest, run_id: int, thread_id: str) -> HttpResponse:
    run = get_object_or_404(AuditRun, id=run_id)
    audit_thread = get_object_or_404(AuditThread, audit_run=run, thread_id=thread_id)
    if audit_thread.status == "running":
        return redirect(f"/runs/{run_id}/?error=Thread+is+already+running")

    # Get config TOML from the run itself, or fall back to profile
    toml_str = run.profile_toml
    if not toml_str and run.profile:
        toml_str = run.profile.profile_toml
    if not toml_str:
        return redirect(f"/runs/{run_id}/?error=No+config+available+for+resume")

    user_message = request.POST.get("message", "").strip() or None

    thread = threading.Thread(
        target=_run_audit_in_thread,
        args=(toml_str,),
        kwargs={"resume_thread_id": thread_id, "user_message": user_message},
        daemon=False,
    )
    thread.start()
    return redirect(f"/runs/{run_id}/?success=Resumed+from+thread+{thread_id}")


def run_fork(request: HttpRequest, run_id: int, thread_id: str) -> HttpResponse:
    run = get_object_or_404(AuditRun, id=run_id)
    audit_thread = get_object_or_404(AuditThread, audit_run=run, thread_id=thread_id)
    if audit_thread.status == "running":
        return redirect(f"/runs/{run_id}/?error=Thread+is+still+running,+cannot+fork")

    toml_str = run.profile_toml
    if not toml_str and run.profile:
        toml_str = run.profile.profile_toml
    if not toml_str:
        return redirect(f"/runs/{run_id}/?error=No+config+available+for+fork")

    user_message = request.POST.get("message", "").strip()
    if not user_message:
        return redirect(f"/runs/{run_id}/?error=Fork+requires+a+message")

    thread = threading.Thread(
        target=_fork_audit_in_thread,
        args=(toml_str, thread_id, user_message),
        daemon=False,
    )
    thread.start()
    return redirect(f"/runs/{run_id}/?success=Forked+from+thread+{thread_id}")


def store_list(request: HttpRequest) -> HttpResponse:
    namespaces = list_store_namespaces()
    return render(request, "llmpuffin_web/store_list.html", {"namespaces": namespaces})


def store_namespace(request: HttpRequest, prefix: str) -> HttpResponse:
    items = list_store_items(prefix)
    return render(
        request,
        "llmpuffin_web/store_namespace.html",
        {"prefix": prefix, "items": items},
    )


def finding_detail(request: HttpRequest, finding_id: int) -> HttpResponse:
    from llmpuffin.config import Config

    gh_config = Config.load().github
    finding = get_object_or_404(Finding, id=finding_id)
    ctx: dict = {
        "finding": finding,
        "audit_run": finding.audit_run,
        "github_configured": gh_config.configured
        and bool(finding.audit_run.github_repo_url),
        "locations": finding.locations.all(),
    }
    if request.GET.get("success"):
        ctx["success"] = request.GET["success"]
    if request.GET.get("error"):
        ctx["error"] = request.GET["error"]
    return render(request, "llmpuffin_web/finding_detail.html", ctx)


def finding_create_issue(request: HttpRequest, finding_id: int) -> HttpResponse:
    """Create a GitHub issue for a finding via the GitHub App."""
    from pathlib import Path

    from llmpuffin.config import Config

    from llmpuffin_web.github import create_issue

    finding = get_object_or_404(Finding, id=finding_id)
    audit_run = finding.audit_run
    gh_config = Config.load().github

    if not gh_config.configured or not audit_run.github_repo_url:
        return redirect(f"/findings/{finding_id}/?error=GitHub+App+not+configured")

    # Extract repo path from github_repo_url (e.g. "https://github.com/KittyCAD/engine" → "KittyCAD/engine")
    repo = audit_run.github_repo_url.rstrip("/").removeprefix("https://github.com/")

    title = f"[{finding.severity}] {finding.title or finding.rule_id}"
    body = f"## {finding.title or finding.rule_id}\n\n"
    body += f"**Severity:** {finding.severity} | **Difficulty:** {finding.difficulty}\n"
    body += f"**Scenario:** {finding.scenario_id}\n\n"
    body += f"### Description\n\n{finding.description}\n\n"
    body += f"### Impact\n\n{finding.impact}\n\n"
    body += f"### Recommendations\n\n{finding.recommendations}\n"
    locs = finding.locations.all()
    if locs:
        body += "\n### Locations\n\n"
        for loc in locs:
            url = audit_run.github_file_url(loc.file_path, loc.start_line)
            if url:
                body += f"- [{loc.file_path}:{loc.start_line}]({url})\n"
            else:
                body += f"- {loc.file_path}:{loc.start_line}\n"
    body += "\n---\n*Generated by llmpuffin*"

    try:
        private_key = Path(gh_config.private_key_path).read_text()
        issue_url = create_issue(
            repo=repo,
            title=title,
            body=body,
            app_id=gh_config.app_id,
            private_key=private_key,
            installation_id=gh_config.installation_id,
            labels=["security", finding.severity],
        )
        return redirect(f"/findings/{finding_id}/?success=Issue+created:+{issue_url}")
    except Exception as exc:
        log.exception("Failed to create GitHub issue")
        return redirect(f"/findings/{finding_id}/?error=Failed+to+create+issue:+{exc}")


def finding_fork(request: HttpRequest, finding_id: int) -> HttpResponse:
    """Fork the conversation from the finding's originating thread to investigate further."""
    finding = get_object_or_404(Finding, id=finding_id)
    run = finding.audit_run

    if not finding.thread_id:
        return redirect(
            f"/findings/{finding_id}/?error=Finding+has+no+originating+thread"
        )

    source_thread = AuditThread.objects.filter(thread_id=finding.thread_id).first()
    if source_thread and source_thread.status == "running":
        return redirect(
            f"/findings/{finding_id}/?error=Source+thread+is+still+running,+cannot+fork"
        )

    toml_str = run.profile_toml
    if not toml_str and run.profile:
        toml_str = run.profile.profile_toml
    if not toml_str:
        return redirect(f"/findings/{finding_id}/?error=No+config+available+for+fork")

    finding_context = (
        f"This conversation is forked to investigate finding #{finding.local_id}.\n"
        f"Title: {finding.title}\n"
        f"Scenario: {finding.scenario_id}\n"
        f"Severity: {finding.severity} | Difficulty: {finding.difficulty}\n"
        f"Description: {finding.description[:500]}\n\n"
    )
    user_input = request.POST.get("message", "").strip()
    user_message = finding_context + (
        user_input or "Investigate this finding further. Try to validate or refute it."
    )

    thread = threading.Thread(
        target=_fork_finding_in_thread,
        args=(toml_str, finding.thread_id, user_message, finding.id),
        daemon=False,
    )
    thread.start()
    return redirect(f"/findings/{finding_id}/?success=Fork+started")


def _run_audit_in_thread(
    toml_str: str,
    resume_thread_id: str | None = None,
    user_message: str | None = None,
) -> None:
    """Run an audit in a background thread."""
    try:
        profile = Profile.from_toml_string(toml_str)
        harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
        _run_coro(
            run_audit(
                harness_config,
                thread_id=resume_thread_id,
                user_message=user_message,
            )
        )
    except Exception:
        log.exception("Background audit failed")


def _fork_audit_in_thread(
    toml_str: str, source_thread_id: str, user_message: str
) -> None:
    """Fork an audit in a background thread."""
    try:
        profile = Profile.from_toml_string(toml_str)
        harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
        _run_coro(
            fork_audit(
                harness_config,
                source_thread_id=source_thread_id,
                user_message=user_message,
            )
        )
    except Exception:
        log.exception("Background fork failed")


def _fork_finding_in_thread(
    toml_str: str, source_thread_id: str, user_message: str, finding_id: int
) -> None:
    """Fork an audit for a finding, then link the new thread to the finding."""
    try:
        profile = Profile.from_toml_string(toml_str)
        harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
        result = _run_coro(
            fork_audit(
                harness_config,
                source_thread_id=source_thread_id,
                user_message=user_message,
            )
        )
        if result.thread_id:
            Finding.objects.filter(pk=finding_id).update(  # type: ignore[attr-defined]
                fork_thread_id=result.thread_id,
            )
    except Exception:
        log.exception("Background finding fork failed")


def profile_run(request: HttpRequest, profile_id: int) -> HttpResponse:
    profile = get_object_or_404(AuditProfile, id=profile_id)

    try:
        Profile.from_toml_string(profile.profile_toml)
    except Exception as exc:
        return redirect(f"/profiles/{profile_id}/?error=Invalid+config:+{exc}")

    thread = threading.Thread(
        target=_run_audit_in_thread,
        args=(profile.profile_toml,),
        daemon=False,
    )
    thread.start()
    return redirect(f"/profiles/{profile_id}/?success=Audit+started")
