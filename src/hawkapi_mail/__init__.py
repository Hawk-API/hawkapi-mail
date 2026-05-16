"""hawkapi-mail — email plugin for HawkAPI.

Backends: SMTP, AWS SES, SendGrid, Mailgun, Resend, in-memory.
Extras: Jinja2 templates, persistent outbox + retry worker, webhook handlers.
"""

from __future__ import annotations

from ._backends import (
    Backend,
    InMemoryBackend,
    MailgunBackend,
    MailgunConfig,
    ResendBackend,
    ResendConfig,
    SendError,
    SendGridBackend,
    SendGridConfig,
    SendResult,
    SESBackend,
    SESConfig,
    SMTPBackend,
    SMTPConfig,
)
from ._deps import get_mailer
from ._mailer import Mailer, init_mail, resolve_mailer
from ._message import Attachment, EmailMessage, format_address, new_message_id
from ._outbox import (
    MemoryOutbox,
    Outbox,
    OutboxEntry,
    OutboxWorker,
    RetryPolicy,
    SQLiteOutbox,
)
from ._templates import TemplateRenderer
from ._webhooks import (
    EventKind,
    SignatureError,
    WebhookEvent,
    confirm_ses_subscription,
    parse_mailgun,
    parse_resend,
    parse_sendgrid,
    parse_ses_sns,
    verify_mailgun,
    verify_resend,
    verify_sendgrid,
)

__version__ = "0.2.0"

__all__ = [
    "Attachment",
    "Backend",
    "EmailMessage",
    "EventKind",
    "InMemoryBackend",
    "Mailer",
    "MailgunBackend",
    "MailgunConfig",
    "MemoryOutbox",
    "Outbox",
    "OutboxEntry",
    "OutboxWorker",
    "ResendBackend",
    "ResendConfig",
    "RetryPolicy",
    "SESBackend",
    "SESConfig",
    "SMTPBackend",
    "SMTPConfig",
    "SQLiteOutbox",
    "SendError",
    "SendGridBackend",
    "SendGridConfig",
    "SendResult",
    "SignatureError",
    "TemplateRenderer",
    "WebhookEvent",
    "__version__",
    "confirm_ses_subscription",
    "format_address",
    "get_mailer",
    "init_mail",
    "new_message_id",
    "parse_mailgun",
    "parse_resend",
    "parse_sendgrid",
    "parse_ses_sns",
    "resolve_mailer",
    "verify_mailgun",
    "verify_resend",
    "verify_sendgrid",
]
