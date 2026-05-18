"""Views for the llmpuffin web UI."""

from __future__ import annotations

import asyncio
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
    return render(request, "llmpuffin_web/checkpoint_detail.html", {"session": session})


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

    runs = AuditRun.objects.annotate(
        thread_count=Count("threads", distinct=True),
        finding_count=Count(
            "findings", distinct=True, filter=Q(findings__deleted=False)
        ),
    ).order_by("-started_at")
    return render(request, "llmpuffin_web/runs_list.html", {"runs": runs})


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
    get_object_or_404(AuditThread, audit_run=run, thread_id=thread_id)

    if run.status == "running":
        return redirect(f"/runs/{run_id}/?error=Run+is+already+in+progress")

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
        daemon=True,
    )
    thread.start()
    return redirect(f"/runs/{run_id}/?success=Resumed+from+thread+{thread_id}")


def run_fork(request: HttpRequest, run_id: int, thread_id: str) -> HttpResponse:
    run = get_object_or_404(AuditRun, id=run_id)
    get_object_or_404(AuditThread, audit_run=run, thread_id=thread_id)

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
        daemon=True,
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
    finding = get_object_or_404(Finding, id=finding_id)
    ctx: dict = {
        "finding": finding,
        "audit_run": finding.audit_run,
        "locations": finding.locations.all(),
    }
    if request.GET.get("success"):
        ctx["success"] = request.GET["success"]
    if request.GET.get("error"):
        ctx["error"] = request.GET["error"]
    return render(request, "llmpuffin_web/finding_detail.html", ctx)


def finding_fork(request: HttpRequest, finding_id: int) -> HttpResponse:
    """Fork the conversation from the finding's originating thread to investigate further."""
    finding = get_object_or_404(Finding, id=finding_id)
    run = finding.audit_run

    if not finding.thread_id:
        return redirect(
            f"/findings/{finding_id}/?error=Finding+has+no+originating+thread"
        )

    toml_str = run.profile_toml
    if not toml_str and run.profile:
        toml_str = run.profile.profile_toml
    if not toml_str:
        return redirect(f"/findings/{finding_id}/?error=No+config+available+for+fork")

    user_message = request.POST.get("message", "").strip()
    if not user_message:
        user_message = (
            f"Investigate finding {finding.id} further: "
            f"{finding.title or finding.description[:200]}"
        )

    thread = threading.Thread(
        target=_fork_finding_in_thread,
        args=(toml_str, finding.thread_id, user_message, finding.id),
        daemon=True,
    )
    thread.start()
    return redirect(f"/findings/{finding_id}/?success=Fork+started")


def _run_audit_in_thread(
    toml_str: str,
    resume_thread_id: str | None = None,
    user_message: str | None = None,
) -> None:
    """Run an audit in a background thread."""
    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    asyncio.run(
        run_audit(
            harness_config,
            thread_id=resume_thread_id,
            user_message=user_message,
        )
    )


def _fork_audit_in_thread(
    toml_str: str, source_thread_id: str, user_message: str
) -> None:
    """Fork an audit in a background thread."""
    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    asyncio.run(
        fork_audit(
            harness_config,
            source_thread_id=source_thread_id,
            user_message=user_message,
        )
    )


def _fork_finding_in_thread(
    toml_str: str, source_thread_id: str, user_message: str, finding_id: int
) -> None:
    """Fork an audit for a finding, then link the new thread to the finding."""
    profile = Profile.from_toml_string(toml_str)
    harness_config = HarnessConfig(profile=profile, profile_toml=toml_str)
    result = asyncio.run(
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


def profile_run(request: HttpRequest, profile_id: int) -> HttpResponse:
    profile = get_object_or_404(AuditProfile, id=profile_id)

    try:
        Profile.from_toml_string(profile.profile_toml)
    except Exception as exc:
        return redirect(f"/profiles/{profile_id}/?error=Invalid+config:+{exc}")

    thread = threading.Thread(
        target=_run_audit_in_thread,
        args=(profile.profile_toml,),
        daemon=True,
    )
    thread.start()
    return redirect(f"/profiles/{profile_id}/?success=Audit+started")
