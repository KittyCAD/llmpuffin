import subprocess
import sys

from django.contrib import admin, messages

from llmpuffin.models import AuditProfile, AuditRun, Finding, FindingLocation


# -- AuditProfile --

class AuditRunInline(admin.TabularInline):
    model = AuditRun
    extra = 0
    show_change_link = True
    fields = ("thread_id", "status", "model_name", "started_at", "finished_at")
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
                config = profile.parsed_config()
            except Exception as exc:
                self.message_user(request, f"Invalid TOML in '{profile.name}': {exc}", messages.ERROR)
                continue

            audit = config.get("audit", {})
            image = audit.get("image")
            if not image:
                self.message_user(request, f"Profile '{profile.name}' missing [audit] image", messages.ERROR)
                continue

            # Write config to a temp file and launch llmpuffin in background
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
                f.write(profile.config_toml)
                config_path = f.name

            subprocess.Popen(
                [sys.executable, "-m", "llmpuffin", image, "-c", config_path, "-v"],
                start_new_session=True,
            )
            self.message_user(request, f"Started audit run for '{profile.name}'", messages.SUCCESS)


# -- AuditRun --

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
    list_display = ("thread_id", "profile", "container_image", "model_name", "status", "started_at", "finished_at")
    list_filter = ("status", "model_name", "profile")
    search_fields = ("thread_id", "container_image")
    readonly_fields = ("thread_id", "started_at")
    inlines = [FindingInline]


# -- Finding --

@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "scenario_id", "severity", "difficulty", "audit_run", "created_at")
    list_filter = ("severity", "difficulty", "scenario_id")
    search_fields = ("rule_id", "description", "scenario_id")
    readonly_fields = ("created_at",)
    inlines = [FindingLocationInline]
