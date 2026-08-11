"""Report rendering."""

from __future__ import annotations

from jinja2 import Template

TEMPLATE = Template(
    "Report for {{ tenant }}\n"
    "{% for row in rows %}{{ row.sku }}: {{ row.quantity }}\n{% endfor %}"
)


def render(tenant: str, rows: list[dict]) -> str:
    return TEMPLATE.render(tenant=tenant, rows=rows)
