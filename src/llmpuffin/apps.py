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


class LlmpuffinConfig(AppConfig):
    name = "llmpuffin"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        post_migrate.connect(_setup_checkpoint_tables, sender=self)
