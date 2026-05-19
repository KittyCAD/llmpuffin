"""Read langgraph store data from PostgreSQL for display."""

from __future__ import annotations

import json
from dataclasses import dataclass

import psycopg

from llmpuffin.db import get_postgres_url


@dataclass
class StoreNamespace:
    prefix: str
    count: int


@dataclass
class StoreItem:
    prefix: str
    key: str
    value: dict
    created_at: str
    updated_at: str

    @property
    def value_json(self) -> str:
        return json.dumps(self.value, indent=2)


async def list_namespaces() -> list[StoreNamespace]:
    async with await psycopg.AsyncConnection.connect(
        get_postgres_url(), autocommit=True
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


async def list_items(prefix: str) -> list[StoreItem]:
    async with await psycopg.AsyncConnection.connect(
        get_postgres_url(), autocommit=True
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
                    created_at=str(r[3]),
                    updated_at=str(r[4]),
                )
                for r in rows
            ]
