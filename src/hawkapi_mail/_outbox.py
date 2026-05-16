"""Persistent outbox + retry worker."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import aiosqlite

from ._backends import Backend, SendError
from ._message import Attachment, EmailMessage

if TYPE_CHECKING:  # pragma: no cover
    pass


logger = logging.getLogger("hawkapi_mail.outbox")


@dataclass(slots=True)
class OutboxEntry:
    id: int
    message: EmailMessage
    attempts: int
    next_attempt_at: float
    created_at: float
    last_error: str = ""


class Outbox(Protocol):
    async def enqueue(self, message: EmailMessage) -> int: ...
    async def pull_due(self, *, now: float, limit: int = 10) -> list[OutboxEntry]: ...
    async def mark_sent(self, entry_id: int) -> None: ...
    async def mark_failed(self, entry_id: int, *, error: str, next_attempt_at: float) -> None: ...
    async def pending_count(self) -> int: ...
    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


@dataclass
class MemoryOutbox:
    _entries: dict[int, OutboxEntry] = field(default_factory=dict)
    _next_id: int = 1
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def enqueue(self, message: EmailMessage) -> int:
        async with self._lock:
            eid = self._next_id
            self._next_id += 1
            now = time.time()
            self._entries[eid] = OutboxEntry(
                id=eid,
                message=message,
                attempts=0,
                next_attempt_at=now,
                created_at=now,
            )
            return eid

    async def pull_due(self, *, now: float, limit: int = 10) -> list[OutboxEntry]:
        async with self._lock:
            due = [e for e in self._entries.values() if e.next_attempt_at <= now]
            due.sort(key=lambda e: e.next_attempt_at)
            return due[:limit]

    async def mark_sent(self, entry_id: int) -> None:
        async with self._lock:
            self._entries.pop(entry_id, None)

    async def mark_failed(self, entry_id: int, *, error: str, next_attempt_at: float) -> None:
        async with self._lock:
            entry = self._entries.get(entry_id)
            if entry is None:
                return
            entry.attempts += 1
            entry.last_error = error
            entry.next_attempt_at = next_attempt_at

    async def pending_count(self) -> int:
        async with self._lock:
            return len(self._entries)

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# SQLite implementation
# ---------------------------------------------------------------------------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    created_at REAL NOT NULL,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_outbox_next_attempt ON outbox(next_attempt_at);
"""


@dataclass
class SQLiteOutbox:
    path: str | Path = ":memory:"
    _db: aiosqlite.Connection | None = field(default=None, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    async def _connect(self) -> aiosqlite.Connection:
        if self._db is None:
            self._db = await aiosqlite.connect(str(self.path))
            await self._db.executescript(_SCHEMA)
            await self._db.commit()
        return self._db

    async def enqueue(self, message: EmailMessage) -> int:
        db = await self._connect()
        async with self._lock:
            now = time.time()
            cur = await db.execute(
                "INSERT INTO outbox(message_json, next_attempt_at, created_at) VALUES (?, ?, ?)",
                (_dump_message(message), now, now),
            )
            await db.commit()
            return cur.lastrowid or 0

    async def pull_due(self, *, now: float, limit: int = 10) -> list[OutboxEntry]:
        db = await self._connect()
        async with self._lock:
            cur = await db.execute(
                "SELECT id, message_json, attempts, next_attempt_at, created_at, last_error "
                "FROM outbox WHERE next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?",
                (now, limit),
            )
            rows = await cur.fetchall()
        return [
            OutboxEntry(
                id=r[0],
                message=_load_message(r[1]),
                attempts=r[2],
                next_attempt_at=r[3],
                created_at=r[4],
                last_error=r[5],
            )
            for r in rows
        ]

    async def mark_sent(self, entry_id: int) -> None:
        db = await self._connect()
        async with self._lock:
            await db.execute("DELETE FROM outbox WHERE id = ?", (entry_id,))
            await db.commit()

    async def mark_failed(self, entry_id: int, *, error: str, next_attempt_at: float) -> None:
        db = await self._connect()
        async with self._lock:
            await db.execute(
                "UPDATE outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? "
                "WHERE id = ?",
                (error, next_attempt_at, entry_id),
            )
            await db.commit()

    async def pending_count(self) -> int:
        db = await self._connect()
        async with self._lock:
            cur = await db.execute("SELECT COUNT(*) FROM outbox")
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None


def _dump_message(message: EmailMessage) -> str:
    import base64

    return json.dumps(
        {
            "subject": message.subject,
            "sender": message.sender,
            "to": message.to,
            "cc": message.cc,
            "bcc": message.bcc,
            "reply_to": message.reply_to,
            "text_body": message.text_body,
            "html_body": message.html_body,
            "attachments": [
                {
                    "filename": a.filename,
                    "content": base64.b64encode(a.content).decode("ascii"),
                    "mime_type": a.mime_type,
                    "inline": a.inline,
                    "content_id": a.content_id,
                }
                for a in message.attachments
            ],
            "headers": message.headers,
            "tags": message.tags,
            "metadata": message.metadata,
            "message_id": message.message_id,
        }
    )


def _load_message(blob: str) -> EmailMessage:
    import base64

    data = json.loads(blob)
    return EmailMessage(
        subject=data["subject"],
        sender=data.get("sender", ""),
        to=list(data.get("to", [])),
        cc=list(data.get("cc", [])),
        bcc=list(data.get("bcc", [])),
        reply_to=list(data.get("reply_to", [])),
        text_body=data.get("text_body", ""),
        html_body=data.get("html_body", ""),
        attachments=[
            Attachment(
                filename=a["filename"],
                content=base64.b64decode(a["content"]),
                mime_type=a["mime_type"],
                inline=a["inline"],
                content_id=a.get("content_id"),
            )
            for a in data.get("attachments", [])
        ],
        headers=dict(data.get("headers", {})),
        tags=list(data.get("tags", [])),
        metadata=dict(data.get("metadata", {})),
        message_id=data["message_id"],
    )


# ---------------------------------------------------------------------------
# Retry policy + worker
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RetryPolicy:
    max_attempts: int = 5
    base_seconds: float = 5.0
    max_seconds: float = 3600.0

    def delay_for(self, attempt: int) -> float:
        """Exponential backoff: 5s, 10s, 20s, 40s, ... capped at max_seconds."""
        return min(self.base_seconds * (2 ** max(attempt - 1, 0)), self.max_seconds)


@dataclass
class OutboxWorker:
    outbox: Outbox
    backend: Backend
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    poll_interval: float = 1.0
    batch_size: int = 10
    _task: asyncio.Task[None] | None = field(default=None, init=False)
    _stop: asyncio.Event = field(default_factory=asyncio.Event, init=False)

    async def drain_once(self) -> int:
        """Process one batch; returns the number of entries handled."""
        now = time.time()
        entries = await self.outbox.pull_due(now=now, limit=self.batch_size)
        for entry in entries:
            await self._send_one(entry)
        return len(entries)

    async def run(self) -> None:
        self._stop.clear()
        while not self._stop.is_set():
            handled = 0
            try:
                handled = await self.drain_once()
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("outbox drain failed: %s", exc)
            if handled == 0:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)

    def start(self) -> asyncio.Task[None]:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run())
        return self._task

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self._task = None

    async def _send_one(self, entry: OutboxEntry) -> None:
        try:
            await self.backend.send(entry.message)
        except SendError as exc:
            err = str(exc)
            if entry.attempts + 1 >= self.retry.max_attempts:
                logger.error(
                    "outbox entry %s exhausted retries after %d attempts: %s",
                    entry.id,
                    entry.attempts + 1,
                    err,
                )
                await self.outbox.mark_sent(entry.id)
                return
            delay = self.retry.delay_for(entry.attempts + 1)
            await self.outbox.mark_failed(entry.id, error=err, next_attempt_at=time.time() + delay)
        else:
            await self.outbox.mark_sent(entry.id)


async def iter_due(outbox: Outbox, *, limit: int = 10) -> AsyncIterator[OutboxEntry]:
    """Helper for tests — yield currently-due entries one at a time."""
    entries = await outbox.pull_due(now=time.time(), limit=limit)
    for e in entries:
        yield e


__all__ = [
    "MemoryOutbox",
    "Outbox",
    "OutboxEntry",
    "OutboxWorker",
    "RetryPolicy",
    "SQLiteOutbox",
    "iter_due",
]


# Re-export Any so dataclass forward refs resolve cleanly under pyright strict.
_ = Any
