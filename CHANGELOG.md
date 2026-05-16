# Changelog

## 0.1.0 — 2026-05-16

Initial release.

- SMTP backend via aiosmtplib (TLS / STARTTLS / SSL).
- AWS SES backend (raw send via boto3, extras: `[ses]`).
- SendGrid v3, Mailgun v3, Resend HTTP backends.
- In-memory backend for tests.
- `EmailMessage` builder — text + HTML + attachments, to/cc/bcc/reply-to, tags, metadata.
- Jinja2 `TemplateRenderer` with async rendering + HTML autoescape.
- Persistent outbox (`MemoryOutbox`, `SQLiteOutbox`) with retry worker + exponential backoff.
- Webhook helpers: signature verification (Mailgun, Resend/Svix, SendGrid ECDSA) and event parsing (Mailgun, SendGrid, Resend, SES via SNS) normalized to `WebhookEvent`.
- `init_mail(app, ...)` + `Depends(get_mailer)`.
