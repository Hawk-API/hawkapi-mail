"""Email backends — SMTP, SES, SendGrid, Mailgun, Resend, in-memory."""

from __future__ import annotations

import base64
import logging
import ssl
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import aiosmtplib
import httpx

from ._message import EmailMessage

logger = logging.getLogger("hawkapi_mail.backends")

if TYPE_CHECKING:  # pragma: no cover
    pass


class SendError(Exception):
    """Raised when a backend cannot deliver a message."""


@dataclass(slots=True)
class SendResult:
    message_id: str
    provider: str
    provider_message_id: str = ""
    raw_response: Any = None


class Backend(Protocol):
    name: str

    async def send(self, message: EmailMessage) -> SendResult: ...
    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SMTPConfig:
    host: str = "localhost"
    port: int = 25
    username: str = ""
    password: str = field(default="", repr=False)
    use_tls: bool = False  # implicit TLS / SMTPS (port 465)
    start_tls: bool = False  # STARTTLS (port 587)
    timeout: float = 30.0
    validate_certs: bool = True
    """Disable TLS certificate verification. Test-only — unsafe in production."""


@dataclass
class SMTPBackend:
    config: SMTPConfig
    name: str = "smtp"

    async def send(self, message: EmailMessage) -> SendResult:
        message.validate()
        if not message.sender:
            raise SendError("sender required for SMTP")
        ctx = ssl.create_default_context()
        if not self.config.validate_certs:
            warnings.warn(
                "SMTP TLS certificate verification disabled (validate_certs=False) "
                "— unsafe outside tests",
                stacklevel=2,
            )
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            await aiosmtplib.send(
                message.to_mime(),
                sender=message.sender,
                recipients=message.all_recipients(),
                hostname=self.config.host,
                port=self.config.port,
                username=self.config.username or None,
                password=self.config.password or None,
                use_tls=self.config.use_tls,
                start_tls=self.config.start_tls,
                timeout=self.config.timeout,
                tls_context=ctx,
            )
        except aiosmtplib.SMTPException as exc:
            logger.debug("SMTP send failure: %s", exc)
            raise SendError("SMTP send failed") from exc
        return SendResult(message_id=message.message_id, provider="smtp")

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Shared HTTP helper
# ---------------------------------------------------------------------------


@dataclass
class _HTTPMixin:
    _client: httpx.AsyncClient | None = field(default=None, init=False)

    def _get_client(self, timeout: float) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=timeout)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
# AWS SES (raw send via boto3)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SESConfig:
    region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = field(default="", repr=False)
    configuration_set: str = ""


@dataclass
class SESBackend:
    config: SESConfig
    name: str = "ses"
    _client: Any = field(default=None, init=False)

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover
                raise SendError("boto3 not installed; pip install 'hawkapi-mail[ses]'") from exc
            kw: dict[str, Any] = {"region_name": self.config.region}
            if self.config.aws_access_key_id:
                kw["aws_access_key_id"] = self.config.aws_access_key_id
            if self.config.aws_secret_access_key:
                kw["aws_secret_access_key"] = self.config.aws_secret_access_key
            self._client = boto3.client("ses", **kw)
        return self._client

    async def send(self, message: EmailMessage) -> SendResult:
        message.validate()
        client = self._get_client()
        raw = message.to_mime()
        kw: dict[str, Any] = {
            "Source": message.sender,
            "Destinations": message.all_recipients(),
            "RawMessage": {"Data": raw},
        }
        if self.config.configuration_set:
            kw["ConfigurationSetName"] = self.config.configuration_set
        try:
            resp = client.send_raw_email(**kw)
        except Exception as exc:  # pragma: no cover - network
            logger.debug("SES send failure: %s", exc)
            raise SendError("SES send failed") from exc
        return SendResult(
            message_id=message.message_id,
            provider="ses",
            provider_message_id=resp.get("MessageId", ""),
            raw_response=resp,
        )

    async def close(self) -> None:
        self._client = None


# ---------------------------------------------------------------------------
# SendGrid (HTTP API v3)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SendGridConfig:
    api_key: str = field(repr=False)
    base_url: str = "https://api.sendgrid.com"
    timeout: float = 30.0


@dataclass
class SendGridBackend(_HTTPMixin):
    config: SendGridConfig = field(default_factory=lambda: SendGridConfig(api_key=""))
    name: str = "sendgrid"

    async def send(self, message: EmailMessage) -> SendResult:
        message.validate()
        payload = _sendgrid_payload(message)
        client = self._get_client(self.config.timeout)
        resp = await client.post(
            f"{self.config.base_url}/v3/mail/send",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            json=payload,
        )
        if resp.status_code >= 300:
            logger.debug("SendGrid %s response body: %s", resp.status_code, resp.text[:500])
            raise SendError(f"SendGrid send failed (status={resp.status_code})")
        provider_id = resp.headers.get("x-message-id", "")
        return SendResult(
            message_id=message.message_id,
            provider="sendgrid",
            provider_message_id=provider_id,
            raw_response={"status_code": resp.status_code, "message_id": provider_id},
        )


def _sendgrid_payload(message: EmailMessage) -> dict[str, Any]:
    personalizations: dict[str, Any] = {"to": [{"email": e} for e in message.to]}
    if message.cc:
        personalizations["cc"] = [{"email": e} for e in message.cc]
    if message.bcc:
        personalizations["bcc"] = [{"email": e} for e in message.bcc]
    content: list[dict[str, str]] = []
    if message.text_body:
        content.append({"type": "text/plain", "value": message.text_body})
    if message.html_body:
        content.append({"type": "text/html", "value": message.html_body})
    if not content:
        content.append({"type": "text/plain", "value": ""})
    body: dict[str, Any] = {
        "personalizations": [personalizations],
        "from": {"email": message.sender},
        "subject": message.subject,
        "content": content,
    }
    if message.reply_to:
        body["reply_to"] = {"email": message.reply_to[0]}
    if message.attachments:
        body["attachments"] = [
            {
                "content": base64.b64encode(a.content).decode("ascii"),
                "filename": a.filename,
                "type": a.mime_type,
                "disposition": "inline" if a.inline else "attachment",
                **({"content_id": a.content_id.strip("<>")} if a.inline and a.content_id else {}),
            }
            for a in message.attachments
        ]
    if message.tags:
        body["categories"] = list(message.tags)
    if message.metadata:
        body["custom_args"] = dict(message.metadata)
    if message.headers:
        body["headers"] = dict(message.headers)
    return body


# ---------------------------------------------------------------------------
# Mailgun (HTTP API v3)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MailgunConfig:
    api_key: str = field(repr=False)
    domain: str
    base_url: str = "https://api.mailgun.net"
    timeout: float = 30.0


@dataclass
class MailgunBackend(_HTTPMixin):
    config: MailgunConfig = field(default_factory=lambda: MailgunConfig(api_key="", domain=""))
    name: str = "mailgun"

    async def send(self, message: EmailMessage) -> SendResult:
        message.validate()
        data: list[tuple[str, str]] = [
            ("from", message.sender),
            ("subject", message.subject),
        ]
        for r in message.to:
            data.append(("to", r))
        for r in message.cc:
            data.append(("cc", r))
        for r in message.bcc:
            data.append(("bcc", r))
        if message.text_body:
            data.append(("text", message.text_body))
        if message.html_body:
            data.append(("html", message.html_body))
        if message.reply_to:
            data.append(("h:Reply-To", ", ".join(message.reply_to)))
        for k, v in message.headers.items():
            data.append((f"h:{k}", v))
        for tag in message.tags:
            data.append(("o:tag", tag))
        for k, v in message.metadata.items():
            data.append((f"v:{k}", v))
        files: list[tuple[str, tuple[str, bytes, str]]] = []
        for a in message.attachments:
            field_name = "inline" if a.inline else "attachment"
            files.append((field_name, (a.filename, a.content, a.mime_type)))
        client = self._get_client(self.config.timeout)
        if files:
            resp = await client.post(
                f"{self.config.base_url}/v3/{self.config.domain}/messages",
                auth=("api", self.config.api_key),
                data=data,  # type: ignore[arg-type]
                files=files,
            )
        else:
            from urllib.parse import urlencode

            body = urlencode(data).encode("utf-8")
            resp = await client.post(
                f"{self.config.base_url}/v3/{self.config.domain}/messages",
                auth=("api", self.config.api_key),
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code >= 300:
            logger.debug("Mailgun %s response body: %s", resp.status_code, resp.text[:500])
            raise SendError(f"Mailgun send failed (status={resp.status_code})")
        body = resp.json()
        return SendResult(
            message_id=message.message_id,
            provider="mailgun",
            provider_message_id=body.get("id", ""),
            raw_response=body,
        )


# ---------------------------------------------------------------------------
# Resend (HTTP API)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ResendConfig:
    api_key: str = field(repr=False)
    base_url: str = "https://api.resend.com"
    timeout: float = 30.0


@dataclass
class ResendBackend(_HTTPMixin):
    config: ResendConfig = field(default_factory=lambda: ResendConfig(api_key=""))
    name: str = "resend"

    async def send(self, message: EmailMessage) -> SendResult:
        message.validate()
        body: dict[str, Any] = {
            "from": message.sender,
            "to": message.to,
            "subject": message.subject,
        }
        if message.cc:
            body["cc"] = message.cc
        if message.bcc:
            body["bcc"] = message.bcc
        if message.reply_to:
            body["reply_to"] = message.reply_to
        if message.html_body:
            body["html"] = message.html_body
        if message.text_body:
            body["text"] = message.text_body
        if message.tags:
            body["tags"] = [{"name": "tag", "value": t} for t in message.tags]
        if message.headers:
            body["headers"] = dict(message.headers)
        if message.attachments:
            body["attachments"] = [
                {
                    "filename": a.filename,
                    "content": base64.b64encode(a.content).decode("ascii"),
                    "content_type": a.mime_type,
                }
                for a in message.attachments
            ]
        client = self._get_client(self.config.timeout)
        resp = await client.post(
            f"{self.config.base_url}/emails",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            json=body,
        )
        if resp.status_code >= 300:
            logger.debug("Resend %s response body: %s", resp.status_code, resp.text[:500])
            raise SendError(f"Resend send failed (status={resp.status_code})")
        data = resp.json()
        return SendResult(
            message_id=message.message_id,
            provider="resend",
            provider_message_id=data.get("id", ""),
            raw_response=data,
        )


# ---------------------------------------------------------------------------
# In-memory (test outbox)
# ---------------------------------------------------------------------------


@dataclass
class InMemoryBackend:
    """Backend that captures messages instead of sending them — perfect for tests."""

    name: str = "memory"
    sent: list[EmailMessage] = field(default_factory=list)

    async def send(self, message: EmailMessage) -> SendResult:
        self.sent.append(message)
        return SendResult(message_id=message.message_id, provider="memory")

    async def close(self) -> None:
        return None

    def clear(self) -> None:
        self.sent.clear()


__all__ = [
    "Backend",
    "InMemoryBackend",
    "MailgunBackend",
    "MailgunConfig",
    "ResendBackend",
    "ResendConfig",
    "SESBackend",
    "SESConfig",
    "SMTPBackend",
    "SMTPConfig",
    "SendError",
    "SendGridBackend",
    "SendGridConfig",
    "SendResult",
]
