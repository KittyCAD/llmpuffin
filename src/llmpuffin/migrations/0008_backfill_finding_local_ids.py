"""Backfill local_id on findings that all have 0."""

from django.db import migrations


def backfill_local_ids(apps, schema_editor):
    """Assign sequential local_ids per audit run, ordered by created_at."""
    Finding = apps.get_model("llmpuffin", "Finding")
    AuditRun = apps.get_model("llmpuffin", "AuditRun")

    for run in AuditRun.objects.all():
        findings = Finding.objects.filter(audit_run=run).order_by("created_at")
        for i, finding in enumerate(findings):
            if finding.local_id != i:
                finding.local_id = i
                finding.save(update_fields=["local_id"])


class Migration(migrations.Migration):
    dependencies = [
        ("llmpuffin", "0007_finding_local_id_alter_auditthread_status"),
    ]

    operations = [
        migrations.RunPython(backfill_local_ids, migrations.RunPython.noop),
    ]
