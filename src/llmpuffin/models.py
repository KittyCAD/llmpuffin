"""Django models for llmpuffin audit data.

These models are the canonical storage for audit runs, findings, and
their relationship to threat model scenarios. The langgraph checkpoint
tables (managed by checkpointer.setup()) live alongside these in the
same PostgreSQL database.
"""

import tomllib

from django.db import models


class AuditProfile(models.Model):
    """A reusable audit configuration (llmpuffin.toml stored in DB).

    This is the core llmpuffin concept of a config file — it defines
    what image to audit, which threat model to use, and how the agent
    should behave. Runs are created from profiles.
    """

    name = models.CharField(max_length=256, unique=True)
    profile_toml = models.TextField(help_text="llmpuffin TOML configuration content")
    jit = models.BooleanField(
        default=False,
        help_text="Auto-created from CLI run, hidden from web profile list",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "llmpuffin"
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def parsed_config(self) -> dict:
        """Parse the TOML config content and return as dict."""
        return tomllib.loads(self.profile_toml)


class AuditRun(models.Model):
    """A single execution of the audit harness.

    Currently one thread per run. Resuming reuses the same thread_id
    (langgraph appends to the checkpoint chain). Forking (multiple
    divergent threads from the same checkpoint) is not yet supported.
    """

    profile = models.ForeignKey(
        AuditProfile,
        on_delete=models.CASCADE,
        related_name="runs",
    )
    profile_toml = models.TextField(blank=True, default="")
    container_image = models.CharField(max_length=512)
    model_name = models.CharField(max_length=128)
    github_repo_url = models.CharField(max_length=512, blank=True, default="")
    git_commit = models.CharField(max_length=64, blank=True, default="")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "llmpuffin"
        ordering = ["-started_at"]

    @property
    def status(self) -> str:
        """Derived from thread statuses: running if any thread is running, else worst status."""
        statuses = list(self.threads.values_list("status", flat=True))
        if not statuses:
            return "pending"
        if "running" in statuses:
            return "running"
        if "error" in statuses:
            return "error"
        if "recursion_limit" in statuses:
            return "recursion_limit"
        return "completed"

    @property
    def error(self) -> str:
        """Aggregate errors from all threads."""
        errors = self.threads.exclude(error="").values_list("error", flat=True)
        return "\n".join(errors)

    def __str__(self) -> str:
        threads = ", ".join(t.thread_id for t in self.threads.all()[:3])
        return f"Run {self.pk} [{threads}] ({self.status})"

    def github_file_url(
        self, file_path: str, line: int | None = None, end_line: int | None = None
    ) -> str | None:
        """Build a GitHub URL for a file path, or None if no repo configured."""
        base = self.github_repo_url.rstrip("/")
        if not base:
            return None
        ref = self.git_commit or "main"
        clean_path = file_path.lstrip("/")
        if clean_path.startswith("src/"):
            clean_path = clean_path[4:]
        url = f"{base}/blob/{ref}/{clean_path}"
        if line and end_line:
            url += f"#L{line}-L{end_line}"
        elif line:
            url += f"#L{line}"
        return url


class AuditThread(models.Model):
    """A checkpoint thread belonging to an audit run.

    Each agent invocation (start or resume) creates a new thread.
    """

    audit_run = models.ForeignKey(
        AuditRun, on_delete=models.CASCADE, related_name="threads"
    )
    thread_id = models.CharField(max_length=64, unique=True, db_index=True)
    status = models.CharField(max_length=32, default="running")
    error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "llmpuffin"
        ordering = ["created_at"]

    def __str__(self) -> str:
        return self.thread_id


class Finding(models.Model):
    """A security finding discovered during an audit."""

    audit_run = models.ForeignKey(
        AuditRun, on_delete=models.CASCADE, related_name="findings"
    )
    thread_id = models.CharField(max_length=64, blank=True, default="", db_index=True)
    rule_id = models.CharField(max_length=128, db_index=True)
    title = models.CharField(max_length=512, blank=True, default="")
    scenario_id = models.CharField(max_length=128, db_index=True)
    severity = models.CharField(max_length=32)  # high, medium, low, informational
    difficulty = models.CharField(max_length=32)  # high, medium, low
    level = models.CharField(max_length=32)  # error, warning, note
    description = models.TextField()
    impact = models.TextField()
    recommendations = models.TextField()
    validated = models.BooleanField(default=False)
    validated_evidence = models.TextField(blank=True, default="")
    deleted = models.BooleanField(default=False)
    fork_thread_id = models.CharField(
        max_length=64, blank=True, default="", db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "llmpuffin"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.rule_id}: {self.title or self.description[:80]}"


class FindingLocation(models.Model):
    """A source location associated with a finding."""

    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name="locations"
    )
    file_path = models.CharField(max_length=1024)
    start_line = models.IntegerField(default=0)
    end_line = models.IntegerField(null=True, blank=True)

    class Meta:
        app_label = "llmpuffin"

    def __str__(self) -> str:
        return f"{self.file_path}:{self.start_line}"
