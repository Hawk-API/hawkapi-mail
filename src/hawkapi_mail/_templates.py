"""Jinja2 template rendering helpers."""

from __future__ import annotations

from pathlib import Path

from jinja2 import (
    BaseLoader,
    ChoiceLoader,
    DictLoader,
    FileSystemLoader,
    PackageLoader,
    select_autoescape,
)
from jinja2.sandbox import SandboxedEnvironment


class TemplateRenderer:
    def __init__(
        self,
        *,
        directory: str | Path | None = None,
        package: str | None = None,
        package_path: str = "templates",
        templates: dict[str, str] | None = None,
        autoescape: bool = True,
    ) -> None:
        loaders: list[BaseLoader] = []
        if directory is not None:
            loaders.append(FileSystemLoader(str(directory)))
        if package is not None:
            loaders.append(PackageLoader(package, package_path))
        if templates:
            loaders.append(DictLoader(templates))
        if not loaders:
            loaders.append(DictLoader({}))
        loader = loaders[0] if len(loaders) == 1 else ChoiceLoader(loaders)
        ae = select_autoescape(["html", "xml"]) if autoescape else False
        # SandboxedEnvironment blocks access to unsafe attributes/builtins so that
        # user-controllable sources passed to render_string() cannot escalate to RCE.
        self.env = SandboxedEnvironment(loader=loader, autoescape=ae, enable_async=True)

    def render(self, template: str, /, **context: object) -> str:
        tpl = self.env.get_template(template)
        return tpl.render(**context)

    async def render_async(self, template: str, /, **context: object) -> str:
        tpl = self.env.get_template(template)
        return await tpl.render_async(**context)

    def render_string(self, source: str, /, **context: object) -> str:
        tpl = self.env.from_string(source)
        return tpl.render(**context)


__all__ = ["TemplateRenderer"]
