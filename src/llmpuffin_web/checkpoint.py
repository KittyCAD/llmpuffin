"""Read checkpoint data from PostgreSQL for display."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field

import psycopg
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

CONNSTRING = os.environ.get(
    "LLMPUFFIN_POSTGRES", "postgresql://localhost:5434/llmpuffin"
)

_serde = JsonPlusSerializer()


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class Message:
    role: str  # "human", "ai", "tool"
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class Session:
    thread_id: str
    steps: int
    status: str | None = None
    messages: list[Message] = field(default_factory=list)


async def _list_sessions(connstring: str) -> list[Session]:
    async with await psycopg.AsyncConnection.connect(connstring, autocommit=True) as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                SELECT
                    c.thread_id,
                    COUNT(*) as steps,
                    r.status
                FROM checkpoints c
                LEFT JOIN llmpuffin_auditthread t ON t.thread_id = c.thread_id
                LEFT JOIN llmpuffin_auditrun r ON r.id = t.audit_run_id
                GROUP BY c.thread_id, r.status
                ORDER BY c.thread_id DESC
            """)
            rows = await cur.fetchall()
            return [Session(thread_id=r[0], steps=r[1], status=r[2]) for r in rows]


async def _get_session(connstring: str, thread_id: str) -> Session | None:
    async with await psycopg.AsyncConnection.connect(connstring, autocommit=True) as conn:
        async with conn.cursor() as cur:
            # Get step count
            await cur.execute(
                "SELECT COUNT(*) FROM checkpoints WHERE thread_id = %s",
                (thread_id,),
            )
            row = await cur.fetchone()
            if not row or row[0] == 0:
                return None

            steps = row[0]

            # Get messages from checkpoint_writes
            await cur.execute("""
                SELECT type, blob
                FROM checkpoint_writes
                WHERE thread_id = %s AND channel = 'messages'
                ORDER BY checkpoint_id, idx
            """, (thread_id,))
            rows = await cur.fetchall()

            messages: list[Message] = []
            for typ, blob in rows:
                data = _serde.loads_typed((typ, blob))
                items = data if isinstance(data, list) else [data]
                for msg in items:
                    cls_name = type(msg).__name__

                    # Handle raw dict messages (human input via astream)
                    if isinstance(msg, dict):
                        role = msg.get("role", "human")
                        if role == "user":
                            role = "human"
                        messages.append(Message(
                            role=role,
                            content=msg.get("content", ""),
                        ))
                        continue

                    content = str(getattr(msg, "content", ""))
                    tc = getattr(msg, "tool_calls", None)
                    tool_call_objs = [
                        ToolCall(name=c["name"], args=c.get("args", {}))
                        for c in tc
                    ] if tc else []

                    if cls_name == "HumanMessage":
                        role = "human"
                    elif cls_name == "AIMessage":
                        role = "ai"
                    elif cls_name == "ToolMessage":
                        role = "tool"
                    else:
                        role = cls_name.lower()

                    messages.append(Message(
                        role=role,
                        content=content,
                        tool_calls=tool_call_objs,
                    ))

            return Session(thread_id=thread_id, steps=steps, messages=messages)


def list_sessions(connstring: str | None = None) -> list[Session]:
    return asyncio.run(_list_sessions(connstring or CONNSTRING))


def get_session(thread_id: str, connstring: str | None = None) -> Session | None:
    return asyncio.run(_get_session(connstring or CONNSTRING, thread_id))
