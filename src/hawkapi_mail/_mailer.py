"""High-level Mailer + plugin entry point."""

from __future__ import annotations

import contextlib
import weakref
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._backends import Backend, InMemoryBackend, SendResult
from ._message import Attachment, EmailMessage
from ._outbox import Outbox, OutboxWorker, RetryPolicy
from ._templates import TemplateRenderer


@dataclass
class Mailer:
    backend: Backend
    default_sender: str = ""
    templates: TemplateRenderer | None = None
    outbox: Outbox | None = None
    worker: OutboxWorker | None = None
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    async def send(
        self,
        message: EmailMessage,
        *,
        deferred: bool = False,
    ) -> SendResult | int:
        """Send ``message``. When ``deferred`` is True and an outbox is attached,
        enqueue the message instead and return the outbox entry id."""
        if not message.sender and self.default_sender:
            message.sender = self.default_sender
        if deferred:
            if self.outbox is None:
                raise RuntimeError("deferred=True but no outbox configured")
            return await self.outbox.enqueue(message)
        return await self.backend.send(message)

    async def send_template(
        self,
        template: str,
        *,
        context: dict[str, Any] | None = None,
        subject: str,
        sender: str = "",
        to: str | Iterable[str] = (),
        cc: str | Iterable[str] = (),
        bcc: str | Iterable[str] = (),
        reply_to: str | Iterable[str] = (),
        text_template: str | None = None,
        attachments: Iterable[Attachment] = (),
        tags: Iterable[str] = (),
        metadata: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        deferred: bool = False,
    ) -> SendResult | int:
        if self.templates is None:
            raise RuntimeError("send_template called but no TemplateRenderer is configured")
        ctx = dict(context or {})
        html = await self.templates.render_async(template, **ctx)
        text = await self.templates.render_async(text_template, **ctx) if text_template else ""
        msg = EmailMessage.build(
            subject=subject,
            sender=sender or self.default_sender,
            to=to,
            cc=cc,
            bcc=bcc,
            reply_to=reply_to,
            text=text,
            html=html,
            attachments=attachments,
            tags=tags,
            metadata=metadata,
            headers=headers,
        )
        return await self.send(msg, deferred=deferred)

    async def attach_file(
        self,
        message: EmailMessage,
        path: str | Path,
        *,
        filename: str | None = None,
        mime_type: str | None = None,
        inline: bool = False,
    ) -> Attachment:
        return message.add_attachment(path, filename=filename, mime_type=mime_type, inline=inline)

    async def shutdown(self) -> None:
        if self.worker is not None:
            await self.worker.stop()
        await self.backend.close()
        if self.outbox is not None:
            await self.outbox.close()


# ---------------------------------------------------------------------------
# Plugin registry + DI helpers
# ---------------------------------------------------------------------------


class _StateNamespace:
    mail: Any


# WeakKeyDictionary keyed by the app object itself avoids the id() ABA hazard
# (two different apps re-using the same id() slot after one is GC'd).
_ACTIVE_MAILERS: weakref.WeakKeyDictionary[Any, Mailer] = weakref.WeakKeyDictionary()
_LAST_MAILER: list[Mailer | None] = [None]


def init_mail(
    app: Any,
    *,
    backend: Backend | None = None,
    default_sender: str = "",
    templates: TemplateRenderer | None = None,
    outbox: Outbox | None = None,
    retry: RetryPolicy | None = None,
    start_worker: bool = False,
) -> Mailer:
    """Attach a Mailer to ``app.state.mail`` and register it for DI lookup.

    When ``outbox`` is provided and ``start_worker=True`` the OutboxWorker is
    started during the HawkAPI startup phase via :pyfunc:`app.on_startup`.
    """
    if backend is None:
        backend = InMemoryBackend()
    mailer = Mailer(
        backend=backend,
        default_sender=default_sender,
        templates=templates,
        outbox=outbox,
        retry=retry or RetryPolicy(),
    )
    if outbox is not None:
        mailer.worker = OutboxWorker(outbox=outbox, backend=backend, retry=mailer.retry)
    if getattr(app, "state", None) is None:
        app.state = _StateNamespace()
    app.state.mail = mailer
    # Unhashable app object — fall back to state attachment + last-mailer slot.
    with contextlib.suppress(TypeError):
        _ACTIVE_MAILERS[app] = mailer
    _LAST_MAILER[0] = mailer

    if start_worker and mailer.worker is not None and hasattr(app, "on_startup"):
        worker = mailer.worker

        async def _start() -> None:
            worker.start()

        async def _stop() -> None:
            await worker.stop()

        app.on_startup(_start)
        if hasattr(app, "on_shutdown"):
            app.on_shutdown(_stop)
    return mailer


def resolve_mailer(app: Any) -> Mailer | None:
    if app is None:
        return _LAST_MAILER[0]
    try:
        mailer = _ACTIVE_MAILERS.get(app)
    except TypeError:
        mailer = None
    if mailer is not None:
        return mailer
    state = getattr(app, "state", None)
    if state is not None and hasattr(state, "mail"):
        return state.mail  # type: ignore[no-any-return]
    return _LAST_MAILER[0]


__all__ = ["Mailer", "init_mail", "resolve_mailer"]
