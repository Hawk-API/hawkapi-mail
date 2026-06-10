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
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("hawkapi_mail.webhooks")

_SNS_URL_RE = re.compile(r"^https://sns\.[a-z0-9-]+\.amazonaws\.com/")
_SNS_HOST_RE = re.compile(r"^sns\.[a-z0-9-]+\.amazonaws\.com$")


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
        from cryptography.hazmat.primitives import (  # type: ignore[import-not-found]
            hashes,
            serialization,
        )
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
    max_age_seconds: int = 900,
) -> None:
    try:
        ts_int = int(timestamp)
    except (ValueError, TypeError) as exc:
        raise SignatureError("invalid timestamp") from exc
    if abs(time.time() - ts_int) > max_age_seconds:
        raise SignatureError("timestamp out of window")
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
    max_age_seconds: int = 300,
) -> None:
    """Resend uses Svix — header format: ``v1,<base64>`` (may be multiple, space-separated)."""
    import base64

    try:
        ts_int = int(timestamp)
    except (ValueError, TypeError) as exc:
        raise SignatureError("invalid timestamp") from exc
    if abs(time.time() - ts_int) > max_age_seconds:
        raise SignatureError("timestamp out of window")

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


# Field order of the canonical "string to sign" differs by message type.
# See https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
_SNS_SIGN_FIELDS_NOTIFICATION = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
_SNS_SIGN_FIELDS_SUBSCRIPTION = (
    "Message",
    "MessageId",
    "SubscribeURL",
    "Timestamp",
    "Token",
    "TopicArn",
    "Type",
)


def _sns_string_to_sign(raw: dict[str, Any]) -> bytes:
    """Build the canonical bytes AWS signed, per the SNS message-verification spec.

    ``Subject`` is included only when present (and only for ``Notification``).
    """
    msg_type = raw.get("Type", "")
    if msg_type == "Notification":
        fields = _SNS_SIGN_FIELDS_NOTIFICATION
    elif msg_type in ("SubscriptionConfirmation", "UnsubscribeConfirmation"):
        fields = _SNS_SIGN_FIELDS_SUBSCRIPTION
    else:
        raise SignatureError(f"unsupported SNS message type: {msg_type!r}")
    parts: list[str] = []
    for key in fields:
        if key == "Subject" and "Subject" not in raw:
            continue
        if key not in raw:
            raise SignatureError(f"SNS message missing signed field {key!r}")
        parts.append(f"{key}\n{raw[key]}\n")
    return "".join(parts).encode("utf-8")


async def verify_sns_message(payload: bytes, *, client: httpx.AsyncClient | None = None) -> None:
    """Verify an SNS message's RSA signature against its signing certificate.

    Validates ``SigningCertURL`` is HTTPS on an ``sns.<region>.amazonaws.com``
    host, fetches the certificate (no redirects), rebuilds the canonical
    string-to-sign, and verifies ``Signature`` with the cert's public key using
    SHA1 for ``SignatureVersion`` ``"1"`` and SHA256 for ``"2"``. Raises
    :class:`SignatureError` on any failure (CWE-345).
    """
    try:
        from cryptography import x509  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives import hashes  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric import (  # type: ignore[import-not-found]
            padding,
            rsa,
        )
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise SignatureError(
            "cryptography is required for SNS signature verification (install hawkapi-mail[ses])"
        ) from exc

    import base64

    raw = json.loads(payload or b"{}")

    sig_version = str(raw.get("SignatureVersion", ""))
    if sig_version == "1":
        # SHA1 is mandated by the AWS SNS SignatureVersion 1 spec, not a choice.
        algorithm = hashes.SHA1()  # noqa: S303
    elif sig_version == "2":
        algorithm = hashes.SHA256()
    else:
        raise SignatureError(f"unsupported SNS SignatureVersion: {sig_version!r}")

    cert_url = raw.get("SigningCertURL", "")
    if not cert_url:
        raise SignatureError("SNS message missing SigningCertURL")
    parsed = urlparse(cert_url)
    if parsed.scheme != "https" or not _SNS_HOST_RE.match(parsed.netloc):
        raise SignatureError(f"untrusted SigningCertURL host: {parsed.netloc!r}")

    signature_b64 = raw.get("Signature", "")
    if not signature_b64:
        raise SignatureError("SNS message missing Signature")
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as exc:
        raise SignatureError(f"SNS Signature not valid base64: {exc}") from exc

    string_to_sign = _sns_string_to_sign(raw)

    own_client = client is None
    c = client or httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    try:
        resp = await c.get(cert_url, follow_redirects=False)
    finally:
        if own_client:
            await c.aclose()
    if resp.status_code != 200:
        raise SignatureError(f"fetching SigningCertURL returned {resp.status_code}")

    try:
        cert = x509.load_pem_x509_certificate(resp.content)
        public_key = cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise SignatureError("SNS signing certificate is not RSA")
        public_key.verify(signature, string_to_sign, padding.PKCS1v15(), algorithm)
    except SignatureError:
        raise
    except Exception as exc:
        raise SignatureError(f"SNS signature verification failed: {exc}") from exc


async def confirm_ses_subscription(
    payload: bytes,
    *,
    client: httpx.AsyncClient | None = None,
    verify_signature: bool = True,
) -> bool:
    """When SNS sends a SubscriptionConfirmation, hit ``SubscribeURL`` to confirm.

    Returns ``True`` if a confirmation was performed.

    The SNS message's RSA signature is verified against its signing certificate
    (see :func:`verify_sns_message`) before any network request to
    ``SubscribeURL`` is made. The ``SubscribeURL`` host is additionally
    allowlisted to the AWS SNS domain and redirects are disabled
    (``follow_redirects=False``). Set ``verify_signature=False`` only if the
    caller has already verified the signature upstream.
    """
    raw = json.loads(payload or b"{}")
    if raw.get("Type") != "SubscriptionConfirmation":
        return False
    url = raw.get("SubscribeURL")
    if not url:
        return False
    if not _SNS_URL_RE.match(url):
        logger.warning("Rejecting suspicious SubscribeURL: %s", url[:200])
        return False
    if verify_signature:
        await verify_sns_message(payload, client=client)
    own_client = client is None
    c = client or httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    try:
        resp = await c.get(url, follow_redirects=False)
        if resp.status_code != 200:
            logger.warning(
                "SNS SubscribeURL returned non-200 (%d); refusing to follow", resp.status_code
            )
            return False
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
    "verify_sns_message",
]
