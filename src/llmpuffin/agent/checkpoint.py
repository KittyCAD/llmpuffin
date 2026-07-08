"""Read langgraph checkpoint data from PostgreSQL for display."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import psycopg
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

if TYPE_CHECKING:
    from llmpuffin.db import DB

_serde = JsonPlusSerializer()


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict
    result: str | None = None  # filled in when paired with its ToolMessage

    @property
    def args_json(self) -> str:
        import json

        return json.dumps(self.args, indent=2)


@dataclass
class Message:
    role: str
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    # ToolMessage-only: id linking back to the originating AIMessage.tool_calls[i].id
    tool_call_id: str | None = None
    tool_name: str | None = None


@dataclass
class Session:
    thread_id: str
    steps: int
    status: str | None = None
    messages: list[Message] = field(default_factory=list)


async def list_sessions(*, db: DB) -> list[Session]:
    async with await psycopg.AsyncConnection.connect(db.url, autocommit=True) as conn:
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


async def get_session(thread_id: str, *, db: DB) -> Session | None:
    async with await psycopg.AsyncConnection.connect(db.url, autocommit=True) as conn:
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
                ORDER BY checkpoint_id, idx, task_id
            """,
                (thread_id,),
            )
            rows = await cur.fetchall()

            messages: list[Message] = []
            # Map tool_call_id → ToolCall on the most recent AI message that
            # emitted it, so we can attach the ToolMessage's content as `result`.
            pending_calls: dict[str, ToolCall] = {}

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

                    if cls_name == "HumanMessage":
                        messages.append(Message(role="human", content=content))
                        continue

                    if cls_name == "AIMessage":
                        tc = getattr(msg, "tool_calls", None) or []
                        tool_call_objs = [
                            ToolCall(
                                id=c.get("id", ""),
                                name=c["name"],
                                args=c.get("args", {}),
                            )
                            for c in tc
                        ]
                        for obj in tool_call_objs:
                            if obj.id:
                                pending_calls[obj.id] = obj
                        messages.append(
                            Message(
                                role="ai",
                                content=content,
                                tool_calls=tool_call_objs,
                            )
                        )
                        continue

                    if cls_name == "ToolMessage":
                        tc_id = getattr(msg, "tool_call_id", None)
                        tool_name = getattr(msg, "name", None)
                        # Pair result back to its originating AIMessage tool call.
                        if tc_id and tc_id in pending_calls:
                            pending_calls[tc_id].result = content
                        messages.append(
                            Message(
                                role="tool",
                                content=content,
                                tool_call_id=tc_id,
                                tool_name=tool_name,
                            )
                        )
                        continue

                    messages.append(Message(role=cls_name.lower(), content=content))

            return Session(thread_id=thread_id, steps=steps, messages=messages)
