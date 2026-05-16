"""High-level Mailer + plugin DI integration."""

from __future__ import annotations

from typing import Any

import pytest
from hawkapi import Depends, HawkAPI, Request
from hawkapi.testing import TestClient

from hawkapi_mail import (
    EmailMessage,
    InMemoryBackend,
    Mailer,
    MemoryOutbox,
    TemplateRenderer,
    get_mailer,
    init_mail,
)


async def test_mailer_uses_default_sender() -> None:
    backend = InMemoryBackend()
    mailer = Mailer(backend=backend, default_sender="me@x.com")
    msg = EmailMessage.build(subject="t", to="x@y.z", text="hi")
    await mailer.send(msg)
    assert backend.sent[0].sender == "me@x.com"


async def test_mailer_send_template_renders_html() -> None:
    backend = InMemoryBackend()
    templates = TemplateRenderer(
        templates={
            "welcome.html": "<p>Hi {{ name }}</p>",
            "welcome.txt": "Hi {{ name }}",
        }
    )
    mailer = Mailer(backend=backend, default_sender="me@x.com", templates=templates)
    await mailer.send_template(
        "welcome.html",
        text_template="welcome.txt",
        context={"name": "Bob"},
        subject="hello",
        to="bob@example.com",
    )
    assert backend.sent[0].html_body == "<p>Hi Bob</p>"
    assert backend.sent[0].text_body == "Hi Bob"


async def test_mailer_deferred_enqueues_in_outbox() -> None:
    backend = InMemoryBackend()
    outbox = MemoryOutbox()
    mailer = Mailer(backend=backend, outbox=outbox)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z")
    entry_id = await mailer.send(msg, deferred=True)
    assert isinstance(entry_id, int)
    assert entry_id > 0
    assert await outbox.pending_count() == 1
    assert backend.sent == []  # nothing sent yet


async def test_mailer_deferred_without_outbox_raises() -> None:
    backend = InMemoryBackend()
    mailer = Mailer(backend=backend)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z")
    with pytest.raises(RuntimeError, match="no outbox"):
        await mailer.send(msg, deferred=True)


async def test_send_template_without_renderer_raises() -> None:
    backend = InMemoryBackend()
    mailer = Mailer(backend=backend)
    with pytest.raises(RuntimeError, match="no TemplateRenderer"):
        await mailer.send_template("x.html", subject="t", to="x@y.z")


def test_init_mail_attaches_to_app_state() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    backend = InMemoryBackend()
    mailer = init_mail(app, backend=backend, default_sender="me@x.com")
    assert app.state.mail is mailer
    assert mailer.default_sender == "me@x.com"


def test_get_mailer_dep_returns_mailer() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    init_mail(app, backend=InMemoryBackend(), default_sender="me@x.com")

    @app.post("/notify")
    async def notify(request: Request, m: Mailer = Depends(get_mailer)) -> dict[str, Any]:
        await m.send(EmailMessage.build(subject="t", to="x@y.z", text="hi"))
        sent = m.backend.sent if hasattr(m.backend, "sent") else []  # type: ignore[attr-defined]
        return {"count": len(sent)}

    client = TestClient(app)
    r = client.post("/notify")
    assert r.status_code in (200, 201)
    assert r.json() == {"count": 1}


def test_get_mailer_dep_500_when_not_configured() -> None:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)

    @app.post("/notify")
    async def notify(m: Mailer = Depends(get_mailer)) -> dict[str, Any]:
        return {"ok": True}

    # Need to clear last-mailer fallback so the dep cannot succeed.
    import hawkapi_mail._mailer as _m

    saved = _m._LAST_MAILER[0]
    _m._LAST_MAILER[0] = None
    _m._ACTIVE_MAILERS.pop(id(app), None)
    try:
        client = TestClient(app)
        r = client.post("/notify")
        assert r.status_code == 500
    finally:
        _m._LAST_MAILER[0] = saved
