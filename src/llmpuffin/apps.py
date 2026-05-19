from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _setup_checkpoint_tables(sender, **kwargs):
    """Create langgraph checkpoint/store tables after migrations run."""
    from llmpuffin.db import get_postgres_url

    postgres_url = get_postgres_url()
    try:
        from langgraph.checkpoint.postgres import PostgresSaver
        from langgraph.store.postgres import PostgresStore

        with PostgresSaver.from_conn_string(postgres_url) as checkpointer:
            checkpointer.setup()
        with PostgresStore.from_conn_string(postgres_url) as store:
            store.setup()
    except Exception as exc:
        import logging

        logging.getLogger("llmpuffin").warning(
            "Could not create checkpoint tables: %s", exc
        )


def _abort_orphaned_threads():
    """On startup, mark any 'running' threads as 'aborted'.

    When the reloader restarts or the process was killed, daemon threads
    are lost without finalizing. This cleans up on next startup.
    """
    try:
        from llmpuffin.models import AuditThread

        count = AuditThread.objects.filter(status="running").update(
            status="aborted", error="Aborted: process restarted"
        )
        if count:
            import logging

            logging.getLogger("llmpuffin").info(
                "Marked %d orphaned running thread(s) as aborted on startup", count
            )
    except Exception:
        pass


_orphan_cleanup_done = False


def _abort_orphaned_threads_once(**kwargs):
    """Run orphan cleanup once on first request after reloader restart."""
    global _orphan_cleanup_done
    if _orphan_cleanup_done:
        return
    _orphan_cleanup_done = True

    import logging

    logging.getLogger("llmpuffin").warning(
        "Reloader detected, aborting orphaned threads"
    )
    _abort_orphaned_threads()


class LlmpuffinConfig(AppConfig):
    name = "llmpuffin"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        import os

        post_migrate.connect(_setup_checkpoint_tables, sender=self)
        if os.environ.get("RUN_MAIN") == "true":
            from django.db.backends.signals import connection_created

            connection_created.connect(_abort_orphaned_threads_once)
