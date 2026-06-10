# hawkapi-mail

Email plugin for [HawkAPI](https://github.com/Hawk-API/HawkAPI). SMTP, AWS SES, SendGrid, Mailgun, Resend, Jinja2 templates, persistent outbox with retry, and webhook handlers for delivery/bounce/complaint events.

## Install

```bash
pip install hawkapi-mail            # SMTP + SendGrid + Mailgun + Resend + outbox
pip install 'hawkapi-mail[ses]'     # adds AWS SES backend + SNS signature verification
```

The `[ses]` extra pulls in `cryptography`, which is required both for the SES backend (boto3) and for verifying SNS webhook signatures (see [Webhooks](#webhooks)).

## Quickstart

```python
from hawkapi import Depends, HawkAPI
from hawkapi_mail import (
    EmailMessage,
    Mailer,
    SMTPBackend,
    SMTPConfig,
    get_mailer,
    init_mail,
)

app = HawkAPI()
init_mail(
    app,
    backend=SMTPBackend(SMTPConfig(host="smtp.example.com", port=587, start_tls=True,
                                    username="api", password="secret")),
    default_sender="hello@example.com",
)


@app.post("/welcome")
async def welcome(email: str, mail: Mailer = Depends(get_mailer)):
    msg = EmailMessage.build(
        subject="Welcome!", to=email, text="Glad you joined.",
        html="<h1>Glad you joined.</h1>",
    )
    await mail.send(msg)
    return {"ok": True}
```

## Backends

```python
from hawkapi_mail import (
    InMemoryBackend,                                # tests
    SMTPBackend, SMTPConfig,                        # SMTP / SMTPS / STARTTLS
    SESBackend, SESConfig,                          # AWS SES (extras: [ses])
    SendGridBackend, SendGridConfig,                # SendGrid v3 API
    MailgunBackend, MailgunConfig,                  # Mailgun v3 API
    ResendBackend, ResendConfig,                    # Resend HTTP API
)

sendgrid = SendGridBackend(SendGridConfig(api_key="SG.xxx"))
mailgun  = MailgunBackend(MailgunConfig(api_key="key-xxx", domain="mg.example.com"))
resend   = ResendBackend(ResendConfig(api_key="re_xxx"))
ses      = SESBackend(SESConfig(region="eu-west-1"))   # uses boto3 / IAM
```

All backends share one async `send(message) -> SendResult` interface; swap them freely.

Every backend validates the message (subject, sender, recipients, and custom headers) before sending and rejects CR/LF/NUL — so the HTTP backends (SendGrid/Mailgun/Resend) get the same header-injection protection as the SMTP/SES path.

`SMTPConfig.validate_certs` defaults to `True` and should stay `True` in production. Setting it to `False` disables TLS certificate verification and emits a `UserWarning` — use it only against a local/test SMTP server with a self-signed certificate.

## Templates

```python
from hawkapi_mail import TemplateRenderer

templates = TemplateRenderer(directory="emails/")           # or package=..., or templates={...}
init_mail(app, backend=..., templates=templates, default_sender="hello@example.com")

await mail.send_template(
    "welcome.html",
    text_template="welcome.txt",
    context={"name": "Alice"},
    subject="Welcome",
    to="alice@example.com",
)
```

Jinja2 with async rendering + HTML autoescape on by default. Templates render in a Jinja2 `SandboxedEnvironment`, which blocks access to unsafe attributes and builtins. This means `render_string(source, **context)` is safe against template-injection (SSTI/RCE) escalation even when the rendering *context* is attacker-controlled. The template *source* itself is still trusted code, so passing user-supplied template source is discouraged; keep templates under your control (files, package, or a fixed `templates={...}` mapping).

## Persistent outbox

```python
from hawkapi_mail import SQLiteOutbox, RetryPolicy

outbox = SQLiteOutbox(path="mail.db")
init_mail(
    app,
    backend=sendgrid,
    outbox=outbox,
    retry=RetryPolicy(max_attempts=5, base_seconds=5, max_seconds=3600),
    start_worker=True,     # drains the outbox in the background
)

# Enqueue instead of sending right away:
entry_id = await mail.send(message, deferred=True)
```

The worker pulls due entries, calls the backend, and on `SendError` schedules an exponential-backoff retry. After `max_attempts` the entry is dropped (logged at error level). For tests, swap in `MemoryOutbox()`.

## Webhooks

```python
from hawkapi_mail import (
    verify_sendgrid, parse_sendgrid,
    verify_mailgun,  parse_mailgun,
    verify_resend,   parse_resend,
    parse_ses_sns,   confirm_ses_subscription,
)


@app.post("/webhooks/mailgun")
async def mailgun_hook(request):
    form = await request.form()
    verify_mailgun(
        signing_key="…",
        timestamp=form["timestamp"], token=form["token"], signature=form["signature"],
    )
    event = parse_mailgun(await request.body())
    # event.kind ∈ delivered | bounce | complaint | opened | clicked | unsubscribed | other
    return {"ok": True}


@app.post("/webhooks/ses")
async def ses_hook(request):
    body = await request.body()
    if await confirm_ses_subscription(body):       # SNS SubscriptionConfirmation
        return {"confirmed": True}
    for event in parse_ses_sns(body):
        ...
    return {"ok": True}
```

All providers normalize to a single `WebhookEvent(provider, kind, recipient, message_id, timestamp, raw)`.

For SES, `confirm_ses_subscription(body)` verifies the SNS message's RSA signature against its AWS signing certificate before hitting `SubscribeURL` (the `SigningCertURL`/`SubscribeURL` hosts are allowlisted to `sns.<region>.amazonaws.com` and redirects are disabled). Pass `verify_signature=False` only if you already verified upstream. You can also verify any SNS message directly with `verify_sns_message(body)`, which raises `SignatureError` on failure. Signature verification needs `cryptography`, installed via the `[ses]` extra (`pip install 'hawkapi-mail[ses]'`).

## Testing

```python
from hawkapi_mail import InMemoryBackend, init_mail

backend = InMemoryBackend()
init_mail(app, backend=backend, default_sender="me@x.com")

# After exercising the app:
assert len(backend.sent) == 1
assert backend.sent[0].subject == "Welcome"
backend.clear()
```

## Development

```bash
git clone https://github.com/Hawk-API/hawkapi-mail.git
cd hawkapi-mail
uv sync --extra dev
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run pyright src/
```

## License

MIT.
