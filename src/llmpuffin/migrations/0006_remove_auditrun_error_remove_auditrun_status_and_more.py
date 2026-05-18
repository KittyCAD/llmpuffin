# Move status/error from AuditRun to AuditThread.

from django.db import migrations, models


def copy_status_to_threads(apps, schema_editor):
    """Copy run status to all its threads before removing from the run."""
    AuditThread = apps.get_model("llmpuffin", "AuditThread")
    for thread in AuditThread.objects.select_related("audit_run").all():
        thread.status = thread.audit_run.status or "completed"
        thread.error = thread.audit_run.error or ""
        thread.save(update_fields=["status", "error"])


class Migration(migrations.Migration):
    dependencies = [
        ("llmpuffin", "0005_finding_fork_thread_id"),
    ]

    operations = [
        # 1. Add fields to AuditThread first
        migrations.AddField(
            model_name="auditthread",
            name="status",
            field=models.CharField(default="completed", max_length=32),
        ),
        migrations.AddField(
            model_name="auditthread",
            name="error",
            field=models.TextField(blank=True, default=""),
        ),
        # 2. Copy data from AuditRun to its threads
        migrations.RunPython(copy_status_to_threads, migrations.RunPython.noop),
        # 3. Remove from AuditRun
        migrations.RemoveField(
            model_name="auditrun",
            name="status",
        ),
        migrations.RemoveField(
            model_name="auditrun",
            name="error",
        ),
    ]
