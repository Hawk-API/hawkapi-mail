"""DI helpers for handlers."""

from __future__ import annotations

from hawkapi import HTTPException, Request

from ._mailer import Mailer, resolve_mailer


def get_mailer(request: Request) -> Mailer:
    mailer = resolve_mailer(request.scope.get("app"))
    if mailer is None:
        raise HTTPException(500, detail="Mailer not configured — call init_mail(app, ...) first")
    return mailer


__all__ = ["get_mailer"]
