"""Read langgraph store data from PostgreSQL for display."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass

import psycopg

CONNSTRING = os.environ.get(
    "LLMPUFFIN_POSTGRES", "postgresql://localhost:5434/llmpuffin"
)


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


async def _list_namespaces(connstring: str) -> list[StoreNamespace]:
    async with await psycopg.AsyncConnection.connect(
        connstring, autocommit=True
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


async def _list_items(connstring: str, prefix: str) -> list[StoreItem]:
    async with await psycopg.AsyncConnection.connect(
        connstring, autocommit=True
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


def list_namespaces(connstring: str | None = None) -> list[StoreNamespace]:
    return asyncio.run(_list_namespaces(connstring or CONNSTRING))


def list_items(prefix: str, connstring: str | None = None) -> list[StoreItem]:
    return asyncio.run(_list_items(connstring or CONNSTRING, prefix))
