# Changelog

## 0.3.0 — 2026-06-10

Security hardening.

- Jinja2 templating now uses a sandboxed environment, preventing SSTI/RCE via `render_string` (CWE-94/1336).
- All HTTP backends (SendGrid/Mailgun/Resend) validate subject/sender/recipients and custom headers for CRLF/NUL before sending (CWE-93), matching the SMTP/SES path.
- SNS subscription/notification handling now verifies the message RSA signature against the AWS signing certificate (CWE-345).
- Secret config fields (passwords, API keys, AWS secret) are excluded from dataclass `repr` (CWE-532).
- `validate_certs=False` now emits a warning before disabling TLS verification.
- Provider error response bodies are truncated in debug logs; SendGrid no longer stores full response headers (CWE-532).

## 0.2.0 — 2026-05-16

Security + reliability hardening.

- Reject CR/LF/NUL in any MIME header name or value (CWE-74 header injection).
- Mailgun and Resend webhook verifiers now require a fresh timestamp (default 900s / 300s) before HMAC compare (CWE-294 replay).
- `confirm_ses_subscription` allowlists `https://sns.<region>.amazonaws.com/` and disables redirects (CWE-918 SSRF).
- Backend errors no longer leak SMTP / HTTP response bodies; status code only.
- Outbox dead-letters entries after `max_attempts` instead of silently deleting them; new `mark_dead` + `status='dead'` column.
- `_send_one` now catches non-`SendError` exceptions instead of leaving entries stuck.
- `RetryPolicy.delay_for` adds +/-20% jitter.
- `init_mail` keys the registry by `WeakKeyDictionary[app]` to avoid `id()` ABA after GC; startup hook is now `async def`.

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
