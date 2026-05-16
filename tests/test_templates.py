"""Jinja2 template rendering."""

from __future__ import annotations

import pytest

from hawkapi_mail import TemplateRenderer


def test_render_string() -> None:
    r = TemplateRenderer()
    assert r.render_string("Hi {{ name }}!", name="Alice") == "Hi Alice!"


def test_render_from_dict_loader() -> None:
    r = TemplateRenderer(templates={"welcome.html": "<p>Hi {{ name }}</p>"})
    assert r.render("welcome.html", name="Bob") == "<p>Hi Bob</p>"


async def test_render_async() -> None:
    r = TemplateRenderer(templates={"a.html": "Hello {{ x }}"})
    assert await r.render_async("a.html", x="y") == "Hello y"


def test_render_from_filesystem(tmp_path: object) -> None:
    from pathlib import Path

    p = Path(tmp_path)  # type: ignore[arg-type]
    (p / "msg.html").write_text("<h1>{{ title }}</h1>", encoding="utf-8")
    r = TemplateRenderer(directory=p)
    assert r.render("msg.html", title="Hello") == "<h1>Hello</h1>"


def test_autoescape_html() -> None:
    r = TemplateRenderer(templates={"x.html": "{{ raw }}"})
    out = r.render("x.html", raw="<script>")
    assert "&lt;script&gt;" in out


def test_missing_template_raises() -> None:
    from jinja2 import TemplateNotFound

    r = TemplateRenderer()
    with pytest.raises(TemplateNotFound):
        r.render("missing.html")
