"""Email message builder."""

from __future__ import annotations

import mimetypes
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import EmailMessage as _StdlibMessage
from email.utils import formataddr, make_msgid
from pathlib import Path
from typing import Any

_CRLF_RE = re.compile(r"[\r\n\x00]")


def _check_header(name: str, value: str) -> None:
    """Reject CR/LF/NUL in header names or values (CWE-74)."""
    if _CRLF_RE.search(name) or _CRLF_RE.search(value):
        raise ValueError(f"header injection attempt: name={name[:32]!r} value={value[:32]!r}")


@dataclass(slots=True)
class Attachment:
    filename: str
    content: bytes
    mime_type: str = "application/octet-stream"
    inline: bool = False
    content_id: str | None = None


@dataclass(slots=True)
class EmailMessage:
    """High-level email message — backend-agnostic."""

    subject: str
    sender: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    message_id: str = field(default_factory=lambda: make_msgid(domain="hawkapi-mail"))

    @classmethod
    def build(
        cls,
        *,
        subject: str,
        sender: str = "",
        to: str | Iterable[str] = (),
        cc: str | Iterable[str] = (),
        bcc: str | Iterable[str] = (),
        reply_to: str | Iterable[str] = (),
        text: str = "",
        html: str = "",
        attachments: Iterable[Attachment] = (),
        headers: dict[str, str] | None = None,
        tags: Iterable[str] = (),
        metadata: dict[str, str] | None = None,
    ) -> EmailMessage:
        return cls(
            subject=subject,
            sender=sender,
            to=_to_list(to),
            cc=_to_list(cc),
            bcc=_to_list(bcc),
            reply_to=_to_list(reply_to),
            text_body=text,
            html_body=html,
            attachments=list(attachments),
            headers=dict(headers or {}),
            tags=list(tags),
            metadata=dict(metadata or {}),
        )

    def add_attachment(
        self,
        path: str | Path,
        *,
        filename: str | None = None,
        mime_type: str | None = None,
        inline: bool = False,
    ) -> Attachment:
        p = Path(path)
        data = p.read_bytes()
        mt = mime_type or mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        cid = make_msgid(domain="hawkapi-mail") if inline else None
        att = Attachment(
            filename=filename or p.name,
            content=data,
            mime_type=mt,
            inline=inline,
            content_id=cid,
        )
        self.attachments.append(att)
        return att

    def all_recipients(self) -> list[str]:
        return [*self.to, *self.cc, *self.bcc]

    def validate(self) -> None:
        """Reject CR/LF/NUL in any header-bound field (CWE-74).

        Called by every backend (SMTP/SES via to_mime, and the HTTP backends
        directly) so subject/sender/recipients and custom headers cannot be
        used for header injection regardless of provider.
        """
        _check_header("Subject", self.subject)
        if self.sender:
            _check_header("From", self.sender)
        for addr in self.to:
            _check_header("To", addr)
        for addr in self.cc:
            _check_header("Cc", addr)
        for addr in self.bcc:
            _check_header("Bcc", addr)
        for addr in self.reply_to:
            _check_header("Reply-To", addr)
        for k, v in self.headers.items():
            _check_header(k, v)

    def to_mime(self) -> bytes:
        """Render to RFC822 bytes (used by SMTP + raw-mode SES)."""
        # Validate every header name/value for CR/LF/NUL before stdlib accepts it.
        self.validate()

        msg = _StdlibMessage()
        msg["Subject"] = self.subject
        if self.sender:
            msg["From"] = self.sender
        if self.to:
            msg["To"] = ", ".join(self.to)
        if self.cc:
            msg["Cc"] = ", ".join(self.cc)
        if self.reply_to:
            msg["Reply-To"] = ", ".join(self.reply_to)
        msg["Message-ID"] = self.message_id
        for k, v in self.headers.items():
            msg[k] = v
        if self.text_body and self.html_body:
            msg.set_content(self.text_body)
            msg.add_alternative(self.html_body, subtype="html")
        elif self.html_body:
            msg.set_content(self.html_body, subtype="html")
        else:
            msg.set_content(self.text_body or "")
        for att in self.attachments:
            maintype, _, subtype = att.mime_type.partition("/")
            disposition = "inline" if att.inline else "attachment"
            extra: dict[str, Any] = {"filename": att.filename, "disposition": disposition}
            if att.inline and att.content_id:
                extra["cid"] = att.content_id.strip("<>")
            msg.add_attachment(
                att.content,
                maintype=maintype or "application",
                subtype=subtype or "octet-stream",
                **extra,
            )
        return bytes(msg)


def _to_list(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    return list(value)


def format_address(name: str, email: str) -> str:
    return formataddr((name, email))


def new_message_id(domain: str | None = None) -> str:
    return make_msgid(domain=domain or "hawkapi-mail")


__all__ = [
    "Attachment",
    "EmailMessage",
    "format_address",
    "new_message_id",
]
