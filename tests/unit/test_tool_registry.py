"""Tests for the structured tool registry."""

from __future__ import annotations

import pytest

from sentinel_x.agents.tools.tool_registry import ToolRegistry


def _dummy_add(a: int, b: int = 0) -> int:
    return a + b


def _dummy_greet(name: str) -> str:
    return f"hello {name}"


def _register_dummy(registry: ToolRegistry) -> None:
    registry.register(
        name="add",
        description="Add two numbers",
        parameters={"a": "int", "b": "int=0"},
        fn=_dummy_add,
    )
    registry.register(
        name="greet",
        description="Greet someone",
        parameters={"name": "str"},
        fn=_dummy_greet,
    )


def test_register_and_retrieve() -> None:
    r = ToolRegistry()
    _register_dummy(r)
    assert "add" in r
    assert "greet" in r
    assert len(r) == 2
    assert r.get("add") is not None
    assert r.get("nonexistent") is None


def test_execute_succeeds() -> None:
    r = ToolRegistry()
    _register_dummy(r)
    assert r.execute("add", {"a": 3, "b": 5}) == 8
    assert r.execute("add", {"a": 7}) == 7  # b defaults to 0
    assert r.execute("greet", {"name": "alice"}) == "hello alice"


def test_validate_catches_missing_required() -> None:
    r = ToolRegistry()
    _register_dummy(r)
    err = r.validate_call("add", {})
    assert err is not None
    assert "missing required" in err


def test_validate_catches_unknown_args() -> None:
    r = ToolRegistry()
    _register_dummy(r)
    err = r.validate_call("add", {"a": 1, "x": 99})
    assert err is not None
    assert "unknown" in err


def test_validate_rejects_unknown_tool() -> None:
    r = ToolRegistry()
    assert r.validate_call("nope", {}) is not None


def test_execute_rejects_bad_args() -> None:
    r = ToolRegistry()
    _register_dummy(r)
    with pytest.raises(ValueError, match="missing required"):
        r.execute("add", {})


def test_execute_rejects_unknown_tool() -> None:
    r = ToolRegistry()
    with pytest.raises(KeyError):
        r.execute("nope", {})


def test_param_mismatch_at_register_raises() -> None:
    r = ToolRegistry()
    with pytest.raises(ValueError, match="declared params"):
        r.register(
            name="bad",
            description="mismatched",
            parameters={"x": "int"},  # declared
            fn=_dummy_add,  # actual fn has (a, b)
        )


def test_to_prompt_docs() -> None:
    r = ToolRegistry()
    _register_dummy(r)
    docs = r.to_prompt_docs()
    assert "add(a" in docs
    assert "greet(name" in docs
    assert "Add two numbers" in docs
