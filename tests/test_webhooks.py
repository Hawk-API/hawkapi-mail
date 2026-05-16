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
        result = await confirm_ses_subscription(body, client=client)
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
        result = await confirm_ses_subscription(body, client=client)
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
        result = await confirm_ses_subscription(body, client=client)
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
        result = await confirm_ses_subscription(body, client=client)
    assert result is False
