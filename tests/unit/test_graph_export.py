"""Tests for graph DOT export."""

from __future__ import annotations

from sentinel_x.graph.export import nodes_to_dot, render_svg

_SAMPLE_NODES = [
    {"id": "user:alice", "type": "user", "name": "alice", "malicious": False},
    {"id": "host:WS-118", "type": "host", "name": "WS-118", "malicious": False},
    {"id": "ioc:10.0.0.5", "type": "ioc", "name": "10.0.0.5", "malicious": True},
]

_SAMPLE_EDGES = [
    {"source": "user:alice", "target": "host:WS-118", "relation": "logged_in", "weight": 1.0},
    {"source": "host:WS-118", "target": "ioc:10.0.0.5", "relation": "connected_to", "weight": 2.5},
]


def test_dot_output_is_valid_structure() -> None:
    dot = nodes_to_dot(_SAMPLE_NODES, _SAMPLE_EDGES)
    assert dot.startswith("digraph G {")
    assert "}" in dot
    assert '"user:alice"' in dot
    assert '"ioc:10.0.0.5"' in dot


def test_dot_edges_present() -> None:
    dot = nodes_to_dot(_SAMPLE_NODES, _SAMPLE_EDGES)
    assert '"user:alice" -> "host:WS-118"' in dot
    assert '"host:WS-118" -> "ioc:10.0.0.5"' in dot
    assert 'label="logged_in"' in dot


def test_dot_malicious_border() -> None:
    dot = nodes_to_dot(_SAMPLE_NODES, _SAMPLE_EDGES)
    assert '"#e74c3c"' in dot  # red border for malicious


def test_dot_empty_graph() -> None:
    dot = nodes_to_dot([], [])
    assert "digraph G {" in dot
    assert dot.strip().endswith("}")


def test_dot_custom_title() -> None:
    dot = nodes_to_dot(_SAMPLE_NODES, _SAMPLE_EDGES, title="My Graph")
    assert 'label="My Graph"' in dot


def test_render_svg_returns_none_without_dot() -> None:
    # On a system without graphviz installed, render_svg should return None
    result = render_svg("digraph G { a -> b; }")
    # We don't assert None because CI might have graphviz installed
    # Just verify it doesn't crash
    assert result is None or isinstance(result, bytes)
