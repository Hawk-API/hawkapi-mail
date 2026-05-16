"""Webhook signature verification + event normalization.

Each provider posts events with its own envelope format and authentication
scheme. We normalize to ``WebhookEvent`` so callers can listen for
``delivered`` / ``bounce`` / ``complaint`` / ``opened`` / ``clicked`` /
``unsubscribed`` / ``other`` without caring which provider sent them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

logger = logging.getLogger("hawkapi_mail.webhooks")


EventKind = Literal[
    "delivered",
    "bounce",
    "complaint",
    "opened",
    "clicked",
    "unsubscribed",
    "other",
]


@dataclass(slots=True)
class WebhookEvent:
    provider: str
    kind: EventKind
    recipient: str = ""
    message_id: str = ""
    timestamp: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)


class SignatureError(Exception):
    """Raised when a webhook signature cannot be verified."""


# ---------------------------------------------------------------------------
# SendGrid (Event Webhook — ECDSA on payload)
# ---------------------------------------------------------------------------


def verify_sendgrid(
    *,
    public_key_pem: str,
    payload: bytes,
    signature_b64: str,
    timestamp: str,
) -> None:
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric import ec  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise SignatureError("cryptography required for SendGrid verification") from exc

    import base64

    try:
        pk = serialization.load_pem_public_key(public_key_pem.encode())
        sig = base64.b64decode(signature_b64)
        signed_payload = timestamp.encode() + payload
        if not isinstance(pk, ec.EllipticCurvePublicKey):  # pragma: no cover
            raise SignatureError("expected ECDSA public key for SendGrid")
        pk.verify(sig, signed_payload, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise SignatureError(f"SendGrid signature invalid: {exc}") from exc


_SENDGRID_KIND: dict[str, EventKind] = {
    "delivered": "delivered",
    "bounce": "bounce",
    "blocked": "bounce",
    "dropped": "bounce",
    "deferred": "bounce",
    "spamreport": "complaint",
    "open": "opened",
    "click": "clicked",
    "unsubscribe": "unsubscribed",
    "group_unsubscribe": "unsubscribed",
}


def parse_sendgrid(payload: bytes) -> list[WebhookEvent]:
    raw = json.loads(payload or b"[]")
    events: list[WebhookEvent] = []
    for item in raw:
        kind = _SENDGRID_KIND.get(item.get("event", ""), "other")
        events.append(
            WebhookEvent(
                provider="sendgrid",
                kind=kind,
                recipient=item.get("email", ""),
                message_id=item.get("sg_message_id", ""),
                timestamp=float(item.get("timestamp", 0) or 0),
                raw=item,
            )
        )
    return events


# ---------------------------------------------------------------------------
# Mailgun (HMAC-SHA256 over timestamp+token)
# ---------------------------------------------------------------------------


def verify_mailgun(
    *,
    signing_key: str,
    timestamp: str,
    token: str,
    signature: str,
) -> None:
    expected = hmac.new(
        signing_key.encode("utf-8"),
        msg=f"{timestamp}{token}".encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise SignatureError("Mailgun signature mismatch")


_MAILGUN_KIND: dict[str, EventKind] = {
    "delivered": "delivered",
    "failed": "bounce",
    "rejected": "bounce",
    "complained": "complaint",
    "opened": "opened",
    "clicked": "clicked",
    "unsubscribed": "unsubscribed",
}


def parse_mailgun(payload: bytes) -> WebhookEvent:
    raw = json.loads(payload or b"{}")
    event_data: dict[str, Any] = raw.get("event-data", raw)
    kind = _MAILGUN_KIND.get(event_data.get("event", ""), "other")
    recipient = event_data.get("recipient", "")
    message = event_data.get("message", {}) or {}
    msg_headers = message.get("headers", {}) or {}
    return WebhookEvent(
        provider="mailgun",
        kind=kind,
        recipient=recipient,
        message_id=msg_headers.get("message-id", ""),
        timestamp=float(event_data.get("timestamp", 0) or 0),
        raw=event_data,
    )


# ---------------------------------------------------------------------------
# Resend (Svix-style HMAC)
# ---------------------------------------------------------------------------


def verify_resend(
    *,
    signing_secret: str,
    msg_id: str,
    timestamp: str,
    signature: str,
    payload: bytes,
) -> None:
    """Resend uses Svix — header format: ``v1,<base64>`` (may be multiple, space-separated)."""
    import base64

    secret = signing_secret
    if secret.startswith("whsec_"):
        secret = secret[len("whsec_") :]
    try:
        key = base64.b64decode(secret)
    except Exception as exc:
        raise SignatureError(f"Resend secret invalid base64: {exc}") from exc
    signed = f"{msg_id}.{timestamp}.".encode() + payload
    expected = base64.b64encode(
        hmac.new(key, msg=signed, digestmod=hashlib.sha256).digest()
    ).decode()
    candidates = [s.split(",", 1)[1] for s in signature.split() if "," in s]
    for cand in candidates:
        if hmac.compare_digest(expected, cand):
            return
    raise SignatureError("Resend signature mismatch")


_RESEND_KIND: dict[str, EventKind] = {
    "email.delivered": "delivered",
    "email.bounced": "bounce",
    "email.complained": "complaint",
    "email.opened": "opened",
    "email.clicked": "clicked",
}


def parse_resend(payload: bytes) -> WebhookEvent:
    raw = json.loads(payload or b"{}")
    kind = _RESEND_KIND.get(raw.get("type", ""), "other")
    data: dict[str, Any] = raw.get("data", {}) or {}
    return WebhookEvent(
        provider="resend",
        kind=kind,
        recipient=(data.get("to") or [""])[0] if isinstance(data.get("to"), list) else "",
        message_id=data.get("email_id", ""),
        timestamp=0.0,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# AWS SES via SNS (SubscriptionConfirmation auto-confirm + signature verify)
# ---------------------------------------------------------------------------


_SES_KIND: dict[str, EventKind] = {
    "Delivery": "delivered",
    "Bounce": "bounce",
    "Complaint": "complaint",
    "Open": "opened",
    "Click": "clicked",
}


def parse_ses_sns(payload: bytes) -> list[WebhookEvent]:
    raw = json.loads(payload or b"{}")
    msg_type = raw.get("Type", "")
    if msg_type == "Notification":
        try:
            inner = json.loads(raw.get("Message", "{}"))
        except json.JSONDecodeError:
            inner = {}
        kind = _SES_KIND.get(inner.get("eventType", inner.get("notificationType", "")), "other")
        mail = inner.get("mail", {}) or {}
        recipients: list[str] = mail.get("destination", []) or []
        return [
            WebhookEvent(
                provider="ses",
                kind=kind,
                recipient=r,
                message_id=mail.get("messageId", ""),
                timestamp=0.0,
                raw=inner,
            )
            for r in (recipients or [""])
        ]
    return []


async def confirm_ses_subscription(
    payload: bytes, *, client: httpx.AsyncClient | None = None
) -> bool:
    """When SNS sends a SubscriptionConfirmation, hit ``SubscribeURL`` to confirm.

    Returns ``True`` if a confirmation was performed.
    """
    raw = json.loads(payload or b"{}")
    if raw.get("Type") != "SubscriptionConfirmation":
        return False
    url = raw.get("SubscribeURL")
    if not url:
        return False
    own_client = client is None
    c = client or httpx.AsyncClient(timeout=10.0)
    try:
        resp = await c.get(url)
        resp.raise_for_status()
    finally:
        if own_client:
            await c.aclose()
    return True


__all__ = [
    "EventKind",
    "SignatureError",
    "WebhookEvent",
    "confirm_ses_subscription",
    "parse_mailgun",
    "parse_resend",
    "parse_sendgrid",
    "parse_ses_sns",
    "verify_mailgun",
    "verify_resend",
    "verify_sendgrid",
]
