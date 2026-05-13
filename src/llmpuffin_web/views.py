"""Views for the llmpuffin web UI."""

from __future__ import annotations

import subprocess
import sys
import tempfile

import tomllib
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from llmpuffin.models import AuditProfile
from llmpuffin_web.checkpoint import get_session, list_sessions


def checkpoints_list(request: HttpRequest) -> HttpResponse:
    sessions = list_sessions()
    return render(request, "llmpuffin_web/checkpoints_list.html", {"sessions": sessions})


def checkpoint_detail(request: HttpRequest, thread_id: str) -> HttpResponse:
    session = get_session(thread_id)
    if session is None:
        return HttpResponse("Checkpoint not found", status=404)
    return render(request, "llmpuffin_web/checkpoint_detail.html", {"session": session})


def profiles_list(request: HttpRequest) -> HttpResponse:
    profiles_qs = AuditProfile.objects.all()
    profiles = []
    for p in profiles_qs:
        try:
            config = p.parsed_config()
            image = config.get("audit", {}).get("image", "")
        except Exception:
            image = "(invalid TOML)"
        profiles.append({"id": p.id, "name": p.name, "image": image, "updated_at": p.updated_at})
    return render(request, "llmpuffin_web/profiles_list.html", {"profiles": profiles})


def profile_create(request: HttpRequest) -> HttpResponse:
    name = request.POST.get("name", "").strip()
    config_toml = request.POST.get("config_toml", "").strip()

    if not name or not config_toml:
        return redirect("/profiles/?error=Name+and+config+are+required")

    try:
        tomllib.loads(config_toml)
    except Exception as exc:
        profiles = AuditProfile.objects.all()
        return render(request, "llmpuffin_web/profiles_list.html", {
            "profiles": profiles,
            "error": f"Invalid TOML: {exc}",
        })

    AuditProfile.objects.create(name=name, config_toml=config_toml)
    return redirect("/profiles/")


def profile_detail(request: HttpRequest, profile_id: int) -> HttpResponse:
    profile = get_object_or_404(AuditProfile, id=profile_id)
    ctx: dict = {"profile": profile, "runs": profile.runs.all()}

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        config_toml = request.POST.get("config_toml", "").strip()

        try:
            tomllib.loads(config_toml)
        except Exception as exc:
            ctx["error"] = f"Invalid TOML: {exc}"
            return render(request, "llmpuffin_web/profile_detail.html", ctx)

        profile.name = name
        profile.config_toml = config_toml
        profile.save()
        ctx["success"] = "Profile saved."
        ctx["profile"] = profile

    return render(request, "llmpuffin_web/profile_detail.html", ctx)


def profile_run(request: HttpRequest, profile_id: int) -> HttpResponse:
    profile = get_object_or_404(AuditProfile, id=profile_id)

    try:
        config = profile.parsed_config()
    except Exception as exc:
        return redirect(f"/profiles/{profile_id}/?error=Invalid+TOML:+{exc}")

    image = config.get("audit", {}).get("image", "")
    if not image:
        return redirect(f"/profiles/{profile_id}/?error=Missing+[audit]+image")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(profile.config_toml)
        config_path = f.name

    subprocess.Popen(
        [sys.executable, "-m", "llmpuffin", image, "-c", config_path, "-v"],
        start_new_session=True,
    )
    return redirect(f"/profiles/{profile_id}/?success=Audit+started")
