"""Backends — SMTP transport mocked via aiosmtplib monkeypatch, HTTP via httpx MockTransport."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from hawkapi_mail import (
    EmailMessage,
    InMemoryBackend,
    MailgunBackend,
    MailgunConfig,
    ResendBackend,
    ResendConfig,
    SendError,
    SendGridBackend,
    SendGridConfig,
    SMTPBackend,
    SMTPConfig,
)


async def test_memory_backend_captures_message() -> None:
    backend = InMemoryBackend()
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", text="hi")
    result = await backend.send(msg)
    assert result.provider == "memory"
    assert len(backend.sent) == 1
    assert backend.sent[0].subject == "t"


async def test_memory_backend_clear() -> None:
    backend = InMemoryBackend()
    await backend.send(EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z"))
    backend.clear()
    assert backend.sent == []


async def test_smtp_backend_requires_sender() -> None:
    backend = SMTPBackend(config=SMTPConfig())
    msg = EmailMessage.build(subject="t", to="x@y.z", text="hi")
    with pytest.raises(SendError, match="sender"):
        await backend.send(msg)


async def test_smtp_backend_invokes_aiosmtplib(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}

    async def fake_send(message: Any, **kw: Any) -> tuple[dict[str, Any], str]:
        calls["message"] = message
        calls.update(kw)
        return ({}, "OK")

    monkeypatch.setattr("aiosmtplib.send", fake_send)
    backend = SMTPBackend(config=SMTPConfig(host="smtp.example", port=587, start_tls=True))
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", text="hi")
    res = await backend.send(msg)
    assert res.provider == "smtp"
    assert calls["hostname"] == "smtp.example"
    assert calls["port"] == 587
    assert calls["start_tls"] is True
    assert calls["recipients"] == ["x@y.z"]


async def test_smtp_backend_wraps_smtp_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    import aiosmtplib

    async def boom(*args: Any, **kw: Any) -> None:
        raise aiosmtplib.SMTPException("nope")

    monkeypatch.setattr("aiosmtplib.send", boom)
    backend = SMTPBackend(config=SMTPConfig())
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", text="hi")
    with pytest.raises(SendError, match="nope"):
        await backend.send(msg)


# ---------------------------------------------------------------------------
# HTTP backends via httpx.MockTransport
# ---------------------------------------------------------------------------


def _mock_client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_sendgrid_backend_posts_v3_endpoint() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.read()
        return httpx.Response(202, headers={"x-message-id": "sg-123"})

    backend = SendGridBackend(config=SendGridConfig(api_key="k"))
    backend._client = _mock_client(handler)
    msg = EmailMessage.build(
        subject="t", sender="a@b.c", to="x@y.z", text="hi", html="<b>hi</b>", tags=["welcome"]
    )
    res = await backend.send(msg)
    assert res.provider == "sendgrid"
    assert res.provider_message_id == "sg-123"
    assert "/v3/mail/send" in captured["url"]
    assert b"welcome" in captured["body"]


async def test_sendgrid_backend_raises_on_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    backend = SendGridBackend(config=SendGridConfig(api_key="k"))
    backend._client = _mock_client(handler)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", text="hi")
    with pytest.raises(SendError, match="400"):
        await backend.send(msg)


async def test_mailgun_backend_posts_domain_endpoint() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"id": "<mg-id@x>"})

    backend = MailgunBackend(config=MailgunConfig(api_key="key", domain="mg.example"))
    backend._client = _mock_client(handler)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", text="hi", tags=["nl"])
    res = await backend.send(msg)
    assert res.provider == "mailgun"
    assert res.provider_message_id == "<mg-id@x>"
    assert "/mg.example/messages" in captured["url"]
    assert captured["auth"].startswith("Basic ")


async def test_mailgun_backend_raises_on_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    backend = MailgunBackend(config=MailgunConfig(api_key="bad", domain="mg.example"))
    backend._client = _mock_client(handler)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", text="hi")
    with pytest.raises(SendError, match="401"):
        await backend.send(msg)


async def test_resend_backend_posts_emails_endpoint() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"id": "re-123"})

    backend = ResendBackend(config=ResendConfig(api_key="re-k"))
    backend._client = _mock_client(handler)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", html="<b>hi</b>")
    res = await backend.send(msg)
    assert res.provider == "resend"
    assert res.provider_message_id == "re-123"
    assert captured["url"].endswith("/emails")
    assert captured["auth"] == "Bearer re-k"


async def test_resend_backend_raises_on_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, text="invalid")

    backend = ResendBackend(config=ResendConfig(api_key="k"))
    backend._client = _mock_client(handler)
    msg = EmailMessage.build(subject="t", sender="a@b.c", to="x@y.z", html="<b>hi</b>")
    with pytest.raises(SendError, match="422"):
        await backend.send(msg)


async def test_http_backend_close_releases_client() -> None:
    backend = SendGridBackend(config=SendGridConfig(api_key="k"))
    _ = backend._get_client(30.0)
    assert backend._client is not None
    await backend.close()
    assert backend._client is None
