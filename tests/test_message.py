"""EmailMessage builder + MIME rendering."""

from __future__ import annotations

import pytest

from hawkapi_mail import Attachment, EmailMessage, format_address, new_message_id


def test_build_with_string_recipient() -> None:
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to="x@y.z", text="hello")
    assert msg.to == ["x@y.z"]
    assert msg.text_body == "hello"


def test_build_with_iterable_recipients() -> None:
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to=["x@y.z", "u@v.w"], cc="cc@a.b")
    assert msg.to == ["x@y.z", "u@v.w"]
    assert msg.cc == ["cc@a.b"]


def test_all_recipients_combines_to_cc_bcc() -> None:
    msg = EmailMessage.build(
        subject="hi", sender="a@b.c", to="x@y.z", cc="cc@a.b", bcc=["b1@x.y", "b2@x.y"]
    )
    assert msg.all_recipients() == ["x@y.z", "cc@a.b", "b1@x.y", "b2@x.y"]


def test_to_mime_plaintext() -> None:
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to="x@y.z", text="hello world")
    raw = msg.to_mime()
    assert b"Subject: hi" in raw
    assert b"From: a@b.c" in raw
    assert b"To: x@y.z" in raw
    assert b"hello world" in raw


def test_to_mime_multipart_with_html() -> None:
    msg = EmailMessage.build(
        subject="hi", sender="a@b.c", to="x@y.z", text="plain", html="<b>html</b>"
    )
    raw = msg.to_mime()
    assert b"multipart/alternative" in raw
    assert b"plain" in raw
    assert b"<b>html</b>" in raw


def test_to_mime_html_only() -> None:
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to="x@y.z", html="<i>only</i>")
    raw = msg.to_mime()
    assert b"text/html" in raw
    assert b"<i>only</i>" in raw


def test_to_mime_with_attachment() -> None:
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to="x@y.z", text="hi")
    msg.attachments.append(
        Attachment(filename="hello.txt", content=b"hello-content", mime_type="text/plain")
    )
    raw = msg.to_mime()
    assert b"hello.txt" in raw
    assert b"hello-content" in raw or b"aGVsbG8tY29udGVudA" in raw  # base64


def test_add_attachment_from_path(tmp_path: object) -> None:
    from pathlib import Path

    p = Path(tmp_path) / "data.bin"  # type: ignore[arg-type]
    p.write_bytes(b"\x00\x01\x02")
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to="x@y.z")
    att = msg.add_attachment(p)
    assert att.filename == "data.bin"
    assert att.content == b"\x00\x01\x02"


def test_format_address() -> None:
    s = format_address("Alice", "alice@x.com")
    assert "Alice" in s
    assert "alice@x.com" in s


def test_new_message_id_unique() -> None:
    assert new_message_id() != new_message_id()


def test_headers_and_reply_to_in_mime() -> None:
    msg = EmailMessage.build(
        subject="hi",
        sender="a@b.c",
        to="x@y.z",
        text="t",
        reply_to=["r@x.y"],
        headers={"X-Custom": "v"},
    )
    raw = msg.to_mime()
    assert b"Reply-To: r@x.y" in raw
    assert b"X-Custom: v" in raw


@pytest.mark.parametrize(
    "to_value,expected",
    [
        ("", []),
        ([], []),
        (("a@b.c",), ["a@b.c"]),
    ],
)
def test_build_normalizes_empty_recipients(to_value: object, expected: list[str]) -> None:
    msg = EmailMessage.build(subject="hi", sender="a@b.c", to=to_value)  # type: ignore[arg-type]
    assert msg.to == expected
