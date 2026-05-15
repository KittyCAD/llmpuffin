import threading

from django.contrib import admin, messages

from llmpuffin.config import Profile
from llmpuffin.models import (
    AuditProfile,
    AuditRun,
    AuditThread,
    Finding,
    FindingLocation,
)
from llmpuffin_web.views import _run_audit_in_thread


# -- AuditProfile --


class AuditRunInline(admin.TabularInline):
    model = AuditRun
    extra = 0
    show_change_link = True
    fields = ("status", "model_name", "started_at", "finished_at")
    readonly_fields = fields

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(AuditProfile)
class AuditProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "updated_at", "created_at")
    search_fields = ("name",)
    readonly_fields = ("created_at", "updated_at")
    inlines = [AuditRunInline]
    actions = ["start_run"]

    @admin.action(description="Start audit run from selected profiles")
    def start_run(self, request, queryset):
        for profile in queryset:
            try:
                Profile.from_toml_string(profile.profile_toml)
            except Exception as exc:
                self.message_user(
                    request,
                    f"Invalid config in '{profile.name}': {exc}",
                    messages.ERROR,
                )
                continue

            thread = threading.Thread(
                target=_run_audit_in_thread,
                args=(profile.profile_toml,),
                daemon=True,
            )
            thread.start()
            self.message_user(
                request, f"Started audit run for '{profile.name}'", messages.SUCCESS
            )


# -- AuditRun --


class AuditThreadInline(admin.TabularInline):
    model = AuditThread
    extra = 0
    readonly_fields = ("thread_id", "created_at")

    def has_add_permission(self, request, obj=None):
        return False


class FindingLocationInline(admin.TabularInline):
    model = FindingLocation
    extra = 0


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    show_change_link = True
    fields = ("rule_id", "scenario_id", "severity", "difficulty", "level")
    readonly_fields = fields


@admin.register(AuditRun)
class AuditRunAdmin(admin.ModelAdmin):
    list_display = (
        "__str__",
        "profile",
        "container_image",
        "model_name",
        "status",
        "started_at",
        "finished_at",
    )
    list_filter = ("status", "model_name", "profile")
    search_fields = ("container_image", "threads__thread_id")
    readonly_fields = ("started_at",)
    inlines = [AuditThreadInline, FindingInline]


# -- Finding --


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "rule_id",
        "scenario_id",
        "severity",
        "difficulty",
        "audit_run",
        "created_at",
    )
    list_filter = ("severity", "difficulty", "scenario_id")
    search_fields = ("rule_id", "description", "scenario_id")
    readonly_fields = ("created_at",)
    inlines = [FindingLocationInline]
