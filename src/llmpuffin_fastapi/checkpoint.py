"""Read langgraph checkpoint data from PostgreSQL for display."""

from __future__ import annotations

from dataclasses import dataclass, field

import psycopg
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from llmpuffin.db import get_postgres_url

_serde = JsonPlusSerializer()


@dataclass
class ToolCall:
    name: str
    args: dict

    @property
    def args_json(self) -> str:
        import json

        return json.dumps(self.args, indent=2)


@dataclass
class Message:
    role: str
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class Session:
    thread_id: str
    steps: int
    status: str | None = None
    messages: list[Message] = field(default_factory=list)


async def list_sessions() -> list[Session]:
    async with await psycopg.AsyncConnection.connect(
        get_postgres_url(), autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                SELECT
                    c.thread_id,
                    COUNT(*) as steps,
                    t.status
                FROM checkpoints c
                LEFT JOIN audit_thread t ON t.thread_id = c.thread_id
                GROUP BY c.thread_id, t.status
                ORDER BY c.thread_id DESC
            """)
            rows = await cur.fetchall()
            return [Session(thread_id=r[0], steps=r[1], status=r[2]) for r in rows]


async def get_session(thread_id: str) -> Session | None:
    async with await psycopg.AsyncConnection.connect(
        get_postgres_url(), autocommit=True
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT COUNT(*) FROM checkpoints WHERE thread_id = %s",
                (thread_id,),
            )
            row = await cur.fetchone()
            if not row or row[0] == 0:
                return None
            steps = row[0]

            await cur.execute(
                """
                SELECT type, blob
                FROM checkpoint_writes
                WHERE thread_id = %s AND channel = 'messages'
                ORDER BY checkpoint_id, idx
            """,
                (thread_id,),
            )
            rows = await cur.fetchall()

            messages: list[Message] = []
            for typ, blob in rows:
                data = _serde.loads_typed((typ, blob))
                items = data if isinstance(data, list) else [data]
                for msg in items:
                    cls_name = type(msg).__name__

                    if isinstance(msg, dict):
                        role = msg.get("role", "human")
                        if role == "user":
                            role = "human"
                        messages.append(
                            Message(role=role, content=msg.get("content", ""))
                        )
                        continue

                    raw_content = getattr(msg, "content", "")
                    if isinstance(raw_content, list):
                        content = "\n".join(
                            block.get("text", "")
                            for block in raw_content
                            if isinstance(block, dict) and block.get("type") == "text"
                        )
                    else:
                        content = str(raw_content)
                    tc = getattr(msg, "tool_calls", None)
                    tool_call_objs = (
                        [ToolCall(name=c["name"], args=c.get("args", {})) for c in tc]
                        if tc
                        else []
                    )

                    if cls_name == "HumanMessage":
                        role = "human"
                    elif cls_name == "AIMessage":
                        role = "ai"
                    elif cls_name == "ToolMessage":
                        role = "tool"
                    else:
                        role = cls_name.lower()

                    messages.append(
                        Message(role=role, content=content, tool_calls=tool_call_objs)
                    )

            return Session(thread_id=thread_id, steps=steps, messages=messages)
