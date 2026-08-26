"""Graphviz DOT export for knowledge graph data.

Converts graph node/edge lists to Graphviz DOT format for visualization.
SVG rendering is optional — requires the ``graphviz`` Python package
(``pip install graphviz``) AND the ``dot`` system binary. Falls back to
DOT text when graphviz is not installed.

No hard dependency — the import is guarded so sentinel_x works without it.
"""

from __future__ import annotations

import html
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_ENTITY_COLORS: dict[str, str] = {
    "user": "#4a90d9",
    "host": "#7b68ee",
    "ip": "#e67e22",
    "ioc": "#e74c3c",
    "process": "#27ae60",
    "domain": "#9b59b6",
    "hash": "#f39c12",
    "url": "#1abc9c",
}

_DEFAULT_COLOR = "#95a5a6"
_MALICIOUS_BORDER = "#e74c3c"


def nodes_to_dot(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    title: str = "SENTINEL-X Knowledge Graph",
    rankdir: str = "LR",
) -> str:
    """Render nodes and edges as a Graphviz DOT string."""
    lines = [
        "digraph G {",
        f'  labelloc="t"; label="{html.escape(title)}";',
        f"  rankdir={rankdir};",
        "  node [shape=box style=filled fontname=Helvetica fontsize=10];",
        "  edge [fontname=Helvetica fontsize=9 color=#666666];",
        "",
    ]

    for node in nodes:
        nid = html.escape(str(node.get("id", "")))
        name = html.escape(str(node.get("name", node.get("id", ""))))
        ntype = str(node.get("type", "")).lower()
        color = _ENTITY_COLORS.get(ntype, _DEFAULT_COLOR)
        border = _MALICIOUS_BORDER if node.get("malicious") else "#cccccc"
        lines.append(
            f'  "{nid}" [label="{name}" fillcolor={color} '
            f'color="{border}" penwidth=2];'
        )

    lines.append("")

    for edge in edges:
        src = html.escape(str(edge.get("source", "")))
        dst = html.escape(str(edge.get("target", "")))
        rel = html.escape(str(edge.get("relation", "")))
        weight = edge.get("weight", 1.0)
        penwidth = max(1.0, min(float(weight) * 2, 6.0))
        lines.append(
            f'  "{src}" -> "{dst}" [label="{rel}" penwidth={penwidth:.1f}];'
        )

    lines.append("}")
    return "\n".join(lines)


def render_svg(dot_source: str) -> bytes | None:
    """Render DOT source to SVG bytes via ``dot`` binary.

    Returns SVG bytes on success, or ``None`` if graphviz is not available.
    """
    try:
        dot_path = subprocess.run(  # noqa: S603
            ["dot", "-V"],  # noqa: S607
            capture_output=True,
            timeout=5,
        )
        if dot_path.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    with tempfile.NamedTemporaryFile(suffix=".dot", mode="w", delete=False) as f:
        f.write(dot_source)
        dot_file = f.name

    try:
        result = subprocess.run(  # noqa: S603
            ["dot", "-Tsvg", dot_file],  # noqa: S607
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout
    finally:
        Path(dot_file).unlink(missing_ok=True)

    return None
