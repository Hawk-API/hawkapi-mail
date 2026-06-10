"""Webhook signature verification + event parsing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import httpx
import pytest

from hawkapi_mail import (
    SignatureError,
    confirm_ses_subscription,
    parse_mailgun,
    parse_resend,
    parse_sendgrid,
    parse_ses_sns,
    verify_mailgun,
    verify_resend,
    verify_sns_message,
)

# ---------------------------------------------------------------------------
# Mailgun
# ---------------------------------------------------------------------------


def test_verify_mailgun_accepts_correct_signature() -> None:
    key = "secret"
    timestamp = str(int(time.time()))
    token = "tok-abc"
    sig = hmac.new(
        key.encode(), msg=f"{timestamp}{token}".encode(), digestmod=hashlib.sha256
    ).hexdigest()
    verify_mailgun(signing_key=key, timestamp=timestamp, token=token, signature=sig)


def test_verify_mailgun_rejects_bad_signature() -> None:
    timestamp = str(int(time.time()))
    with pytest.raises(SignatureError):
        verify_mailgun(signing_key="secret", timestamp=timestamp, token="tok", signature="bad")


def test_verify_mailgun_rejects_old_timestamp() -> None:
    key = "secret"
    old = str(int(time.time()) - 3600)
    token = "tok-abc"
    sig = hmac.new(key.encode(), msg=f"{old}{token}".encode(), digestmod=hashlib.sha256).hexdigest()
    with pytest.raises(SignatureError):
        verify_mailgun(signing_key=key, timestamp=old, token=token, signature=sig)


def test_verify_mailgun_rejects_non_numeric_timestamp() -> None:
    with pytest.raises(SignatureError):
        verify_mailgun(signing_key="secret", timestamp="not-a-ts", token="tok", signature="x")


def test_parse_mailgun_delivered() -> None:
    body = {
        "event-data": {
            "event": "delivered",
            "recipient": "x@y.z",
            "message": {"headers": {"message-id": "<m-1@x>"}},
            "timestamp": 1700000000,
        }
    }
    e = parse_mailgun(json.dumps(body).encode())
    assert e.provider == "mailgun"
    assert e.kind == "delivered"
    assert e.recipient == "x@y.z"
    assert e.message_id == "<m-1@x>"


def test_parse_mailgun_bounce_aliases_failed() -> None:
    e = parse_mailgun(
        json.dumps(
            {"event-data": {"event": "failed", "recipient": "x@y.z", "message": {"headers": {}}}}
        ).encode()
    )
    assert e.kind == "bounce"


# ---------------------------------------------------------------------------
# SendGrid
# ---------------------------------------------------------------------------


def test_parse_sendgrid_batch() -> None:
    events = parse_sendgrid(
        json.dumps(
            [
                {"event": "delivered", "email": "a@b.c", "sg_message_id": "m1", "timestamp": 1},
                {"event": "spamreport", "email": "x@y.z", "sg_message_id": "m2", "timestamp": 2},
                {"event": "click", "email": "u@v.w", "sg_message_id": "m3", "timestamp": 3},
            ]
        ).encode()
    )
    assert [e.kind for e in events] == ["delivered", "complaint", "clicked"]
    assert events[0].recipient == "a@b.c"


def test_parse_sendgrid_unknown_event_falls_back_to_other() -> None:
    events = parse_sendgrid(json.dumps([{"event": "weird"}]).encode())
    assert events[0].kind == "other"


# ---------------------------------------------------------------------------
# Resend (Svix HMAC)
# ---------------------------------------------------------------------------


def test_verify_resend_accepts_correct_signature() -> None:
    secret = base64.b64encode(b"my-secret-bytes").decode()
    msg_id = "msg_123"
    timestamp = str(int(time.time()))
    payload = b'{"type":"email.delivered"}'
    raw_secret = base64.b64decode(secret)
    sig = base64.b64encode(
        hmac.new(
            raw_secret, msg=f"{msg_id}.{timestamp}.".encode() + payload, digestmod=hashlib.sha256
        ).digest()
    ).decode()
    verify_resend(
        signing_secret=secret,
        msg_id=msg_id,
        timestamp=timestamp,
        signature=f"v1,{sig}",
        payload=payload,
    )


def test_verify_resend_rejects_bad_signature() -> None:
    secret = base64.b64encode(b"my-secret-bytes").decode()
    timestamp = str(int(time.time()))
    with pytest.raises(SignatureError):
        verify_resend(
            signing_secret=secret,
            msg_id="m",
            timestamp=timestamp,
            signature="v1,YmFkc2ln",
            payload=b"{}",
        )


def test_verify_resend_rejects_old_timestamp() -> None:
    secret = base64.b64encode(b"my-secret-bytes").decode()
    old = str(int(time.time()) - 3600)
    payload = b'{"type":"email.delivered"}'
    raw_secret = base64.b64decode(secret)
    sig = base64.b64encode(
        hmac.new(
            raw_secret, msg=f"msg_1.{old}.".encode() + payload, digestmod=hashlib.sha256
        ).digest()
    ).decode()
    with pytest.raises(SignatureError):
        verify_resend(
            signing_secret=secret,
            msg_id="msg_1",
            timestamp=old,
            signature=f"v1,{sig}",
            payload=payload,
        )


def test_parse_resend_email_delivered() -> None:
    body = {"type": "email.delivered", "data": {"email_id": "re-1", "to": ["x@y.z"]}}
    e = parse_resend(json.dumps(body).encode())
    assert e.kind == "delivered"
    assert e.message_id == "re-1"
    assert e.recipient == "x@y.z"


# ---------------------------------------------------------------------------
# SES via SNS
# ---------------------------------------------------------------------------


def test_parse_ses_sns_bounce() -> None:
    inner = {
        "eventType": "Bounce",
        "mail": {"messageId": "ses-1", "destination": ["x@y.z", "u@v.w"]},
    }
    body = {"Type": "Notification", "Message": json.dumps(inner)}
    events = parse_ses_sns(json.dumps(body).encode())
    assert len(events) == 2
    assert all(e.kind == "bounce" for e in events)
    assert events[0].message_id == "ses-1"


def test_parse_ses_sns_ignores_non_notification() -> None:
    body = {"Type": "SubscriptionConfirmation"}
    events = parse_ses_sns(json.dumps(body).encode())
    assert events == []


# ---------------------------------------------------------------------------
# confirm_ses_subscription — SSRF guard
# ---------------------------------------------------------------------------


async def test_confirm_ses_subscription_rejects_non_aws_url() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        body = json.dumps(
            {"Type": "SubscriptionConfirmation", "SubscribeURL": "http://evil.com/confirm"}
        ).encode()
        result = await confirm_ses_subscription(body, client=client, verify_signature=False)
    assert result is False
    assert calls == []


async def test_confirm_ses_subscription_rejects_lookalike_domain() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        body = json.dumps(
            {
                "Type": "SubscriptionConfirmation",
                "SubscribeURL": "https://sns.us-east-1.amazonaws.com.evil.com/x",
            }
        ).encode()
        result = await confirm_ses_subscription(body, client=client, verify_signature=False)
    assert result is False
    assert calls == []


async def test_confirm_ses_subscription_accepts_aws_url() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        body = json.dumps(
            {
                "Type": "SubscriptionConfirmation",
                "SubscribeURL": (
                    "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
                ),
            }
        ).encode()
        result = await confirm_ses_subscription(body, client=client, verify_signature=False)
    assert result is True
    assert len(calls) == 1
    assert "sns.us-east-1.amazonaws.com" in str(calls[0].url)


async def test_confirm_ses_subscription_rejects_non_200() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://evil.com"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        body = json.dumps(
            {
                "Type": "SubscriptionConfirmation",
                "SubscribeURL": "https://sns.us-east-1.amazonaws.com/x",
            }
        ).encode()
        result = await confirm_ses_subscription(body, client=client, verify_signature=False)
    assert result is False


# ---------------------------------------------------------------------------
# verify_sns_message — RSA signature against signing certificate (CWE-345)
# ---------------------------------------------------------------------------

pytest.importorskip("cryptography")

CERT_URL = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem"


def _make_signed_sns(message_type: str = "Notification") -> tuple[dict, bytes]:
    """Build a self-signed cert and a v1 (SHA1) signed SNS payload."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    if message_type == "Notification":
        msg = {
            "Type": "Notification",
            "MessageId": "id-1",
            "TopicArn": "arn:aws:sns:us-east-1:123:topic",
            "Message": '{"eventType":"Delivery"}',
            "Timestamp": "2026-06-10T00:00:00.000Z",
            "SignatureVersion": "1",
            "SigningCertURL": CERT_URL,
        }
        fields = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
    else:
        msg = {
            "Type": "SubscriptionConfirmation",
            "MessageId": "id-1",
            "TopicArn": "arn:aws:sns:us-east-1:123:topic",
            "Message": "You have chosen to subscribe",
            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription",
            "Token": "tok",
            "Timestamp": "2026-06-10T00:00:00.000Z",
            "SignatureVersion": "1",
            "SigningCertURL": CERT_URL,
        }
        fields = ("Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type")

    string_to_sign = "".join(
        f"{k}\n{msg[k]}\n" for k in fields if k != "Subject" or k in msg
    ).encode()
    signature = key.sign(string_to_sign, padding.PKCS1v15(), hashes.SHA1())
    msg["Signature"] = base64.b64encode(signature).decode()
    return msg, cert_pem


def _cert_client(cert_pem: bytes) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=cert_pem)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_verify_sns_message_accepts_valid_signature() -> None:
    msg, cert_pem = _make_signed_sns("Notification")
    async with _cert_client(cert_pem) as client:
        await verify_sns_message(json.dumps(msg).encode(), client=client)


async def test_verify_sns_message_accepts_subscription_confirmation() -> None:
    msg, cert_pem = _make_signed_sns("SubscriptionConfirmation")
    async with _cert_client(cert_pem) as client:
        await verify_sns_message(json.dumps(msg).encode(), client=client)


async def test_verify_sns_message_rejects_tampered_message() -> None:
    msg, cert_pem = _make_signed_sns("Notification")
    msg["Message"] = '{"eventType":"Bounce"}'  # tamper after signing
    async with _cert_client(cert_pem) as client:
        with pytest.raises(SignatureError):
            await verify_sns_message(json.dumps(msg).encode(), client=client)


async def test_verify_sns_message_rejects_untrusted_cert_url() -> None:
    msg, cert_pem = _make_signed_sns("Notification")
    msg["SigningCertURL"] = "https://evil.com/cert.pem"
    async with _cert_client(cert_pem) as client:
        with pytest.raises(SignatureError, match="untrusted"):
            await verify_sns_message(json.dumps(msg).encode(), client=client)


async def test_verify_sns_message_rejects_http_cert_url() -> None:
    msg, cert_pem = _make_signed_sns("Notification")
    msg["SigningCertURL"] = "http://sns.us-east-1.amazonaws.com/cert.pem"
    async with _cert_client(cert_pem) as client:
        with pytest.raises(SignatureError):
            await verify_sns_message(json.dumps(msg).encode(), client=client)


async def test_verify_sns_message_rejects_unknown_signature_version() -> None:
    msg, cert_pem = _make_signed_sns("Notification")
    msg["SignatureVersion"] = "9"
    async with _cert_client(cert_pem) as client:
        with pytest.raises(SignatureError):
            await verify_sns_message(json.dumps(msg).encode(), client=client)


async def test_verify_sns_message_missing_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("no cryptography")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SignatureError, match="cryptography"):
        await verify_sns_message(b"{}")


async def test_confirm_ses_subscription_verifies_signature() -> None:
    msg, cert_pem = _make_signed_sns("SubscriptionConfirmation")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if str(request.url) == CERT_URL:
            return httpx.Response(200, content=cert_pem)
        return httpx.Response(200, text="ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await confirm_ses_subscription(json.dumps(msg).encode(), client=client)
    assert result is True
    # cert fetch + subscribe confirm
    assert len(calls) == 2


async def test_confirm_ses_subscription_rejects_forged_signature() -> None:
    msg, cert_pem = _make_signed_sns("SubscriptionConfirmation")
    msg["Token"] = "forged"  # tamper after signing

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=cert_pem)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SignatureError):
            await confirm_ses_subscription(json.dumps(msg).encode(), client=client)
