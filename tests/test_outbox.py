"""Persistent outbox + retry worker."""

from __future__ import annotations

import asyncio
import time

from hawkapi_mail import (
    EmailMessage,
    InMemoryBackend,
    MemoryOutbox,
    OutboxWorker,
    RetryPolicy,
    SendError,
    SQLiteOutbox,
)


def _make_message() -> EmailMessage:
    return EmailMessage.build(subject="hi", sender="a@b.c", to="x@y.z", text="body")


async def test_memory_outbox_enqueue_and_pull() -> None:
    ob = MemoryOutbox()
    eid = await ob.enqueue(_make_message())
    assert eid > 0
    entries = await ob.pull_due(now=time.time())
    assert len(entries) == 1
    assert entries[0].message.subject == "hi"


async def test_memory_outbox_pending_count() -> None:
    ob = MemoryOutbox()
    await ob.enqueue(_make_message())
    await ob.enqueue(_make_message())
    assert await ob.pending_count() == 2


async def test_memory_outbox_mark_sent_drops_entry() -> None:
    ob = MemoryOutbox()
    eid = await ob.enqueue(_make_message())
    await ob.mark_sent(eid)
    assert await ob.pending_count() == 0


async def test_memory_outbox_mark_failed_defers() -> None:
    ob = MemoryOutbox()
    eid = await ob.enqueue(_make_message())
    future = time.time() + 60
    await ob.mark_failed(eid, error="boom", next_attempt_at=future)
    entries = await ob.pull_due(now=time.time())
    assert entries == []  # not yet due
    entries = await ob.pull_due(now=future + 1)
    assert len(entries) == 1
    assert entries[0].attempts == 1
    assert entries[0].last_error == "boom"


async def test_sqlite_outbox_roundtrip(tmp_path: object) -> None:
    from pathlib import Path

    db = Path(tmp_path) / "out.db"  # type: ignore[arg-type]
    ob = SQLiteOutbox(path=db)
    eid = await ob.enqueue(_make_message())
    assert eid > 0
    entries = await ob.pull_due(now=time.time())
    assert len(entries) == 1
    assert entries[0].message.subject == "hi"
    await ob.mark_sent(eid)
    assert await ob.pending_count() == 0
    await ob.close()


async def test_sqlite_outbox_preserves_attachments(tmp_path: object) -> None:
    from pathlib import Path

    from hawkapi_mail import Attachment

    db = Path(tmp_path) / "out.db"  # type: ignore[arg-type]
    ob = SQLiteOutbox(path=db)
    msg = _make_message()
    msg.attachments.append(Attachment(filename="a.txt", content=b"data", mime_type="text/plain"))
    await ob.enqueue(msg)
    entries = await ob.pull_due(now=time.time())
    att = entries[0].message.attachments[0]
    assert att.filename == "a.txt"
    assert att.content == b"data"
    await ob.close()


def test_retry_policy_backoff() -> None:
    p = RetryPolicy(base_seconds=5, max_seconds=100)
    assert p.delay_for(1) == 5
    assert p.delay_for(2) == 10
    assert p.delay_for(3) == 20
    assert p.delay_for(10) == 100  # capped


async def test_worker_drains_pending() -> None:
    ob = MemoryOutbox()
    backend = InMemoryBackend()
    await ob.enqueue(_make_message())
    await ob.enqueue(_make_message())
    w = OutboxWorker(outbox=ob, backend=backend)
    handled = await w.drain_once()
    assert handled == 2
    assert await ob.pending_count() == 0
    assert len(backend.sent) == 2


async def test_worker_retries_on_send_error() -> None:
    class FlakyBackend(InMemoryBackend):
        attempts: int = 0

        async def send(self, message):  # type: ignore[override]
            self.attempts += 1
            if self.attempts < 2:
                raise SendError("temporary")
            return await super().send(message)

    ob = MemoryOutbox()
    backend = FlakyBackend()
    await ob.enqueue(_make_message())
    w = OutboxWorker(
        outbox=ob, backend=backend, retry=RetryPolicy(max_attempts=5, base_seconds=0.01)
    )
    await w.drain_once()
    assert await ob.pending_count() == 1
    # wait briefly for backoff (0.02s ~ delay_for(1)=0.01s*2 = 0.02s)
    await asyncio.sleep(0.05)
    await w.drain_once()
    assert await ob.pending_count() == 0
    assert len(backend.sent) == 1


async def test_worker_drops_after_max_attempts() -> None:
    class AlwaysFail(InMemoryBackend):
        async def send(self, message):  # type: ignore[override]
            raise SendError("permanent")

    ob = MemoryOutbox()
    backend = AlwaysFail()
    await ob.enqueue(_make_message())
    w = OutboxWorker(
        outbox=ob, backend=backend, retry=RetryPolicy(max_attempts=2, base_seconds=0.0)
    )
    await w.drain_once()
    assert await ob.pending_count() == 1
    await w.drain_once()
    assert await ob.pending_count() == 0  # dropped after max_attempts


async def test_worker_start_stop_runs_background_loop() -> None:
    ob = MemoryOutbox()
    backend = InMemoryBackend()
    w = OutboxWorker(outbox=ob, backend=backend, poll_interval=0.01)
    w.start()
    await ob.enqueue(_make_message())
    for _ in range(50):
        if await ob.pending_count() == 0:
            break
        await asyncio.sleep(0.02)
    await w.stop()
    assert len(backend.sent) == 1
