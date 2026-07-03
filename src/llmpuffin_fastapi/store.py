"""Read langgraph store data from PostgreSQL for display."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

import psycopg


@dataclass
class StoreNamespace:
    prefix: str
    count: int


@dataclass
class StoreItem:
    prefix: str
    key: str
    value: dict
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def value_json(self) -> str:
        return json.dumps(self.value, indent=2, default=str)

    @property
    def kind(self) -> str:
        """Best-effort guess at how to render this item.

        Returns one of: "markdown", "text", "json".
        """
        if not isinstance(self.value, dict):
            return "json"
        # langgraph-style file objects often have a content/body field.
        body = self._body()
        if body is None:
            return "json"
        if self.key.endswith(".md") or self.key.endswith(".markdown"):
            return "markdown"
        if isinstance(body, str):
            return "text"
        return "json"

    @property
    def body(self) -> str:
        """Extracted human-readable body, or the full JSON if none."""
        b = self._body()
        if isinstance(b, str):
            return b
        return self.value_json

    @property
    def extra(self) -> dict:
        """Other dict fields besides the body, for display as a metadata strip."""
        if not isinstance(self.value, dict):
            return {}
        body_key = self._body_key()
        return {k: v for k, v in self.value.items() if k != body_key}

    def _body_key(self) -> str | None:
        if not isinstance(self.value, dict):
            return None
        for k in ("content", "body", "text", "value", "markdown"):
            if k in self.value:
                return k
        return None

    def _body(self) -> object | None:
        k = self._body_key()
        if k is None:
            return None
        return self.value[k]


async def list_namespaces(postgres_url: str) -> list[StoreNamespace]:
    async with await psycopg.AsyncConnection.connect(
        postgres_url, autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                SELECT prefix, COUNT(*) as cnt
                FROM store
                GROUP BY prefix
                ORDER BY prefix
            """)
            rows = await cur.fetchall()
            return [StoreNamespace(prefix=r[0], count=r[1]) for r in rows]


async def update_item(prefix: str, key: str, value: dict, postgres_url: str) -> None:
    async with await psycopg.AsyncConnection.connect(
        postgres_url, autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE store
                SET value = %s, updated_at = NOW()
                WHERE prefix = %s AND key = %s
            """,
                (json.dumps(value), prefix, key),
            )


async def delete_item(prefix: str, key: str, postgres_url: str) -> None:
    async with await psycopg.AsyncConnection.connect(
        postgres_url, autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM store WHERE prefix = %s AND key = %s",
                (prefix, key),
            )


async def delete_all(postgres_url: str) -> int:
    async with await psycopg.AsyncConnection.connect(
        postgres_url, autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute("DELETE FROM store")
            return cur.rowcount or 0


async def list_items(prefix: str, postgres_url: str) -> list[StoreItem]:
    async with await psycopg.AsyncConnection.connect(
        postgres_url, autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT prefix, key, value, created_at, updated_at
                FROM store
                WHERE prefix = %s
                ORDER BY updated_at DESC
            """,
                (prefix,),
            )
            rows = await cur.fetchall()
            return [
                StoreItem(
                    prefix=r[0],
                    key=r[1],
                    value=r[2],
                    created_at=r[3],
                    updated_at=r[4],
                )
                for r in rows
            ]
