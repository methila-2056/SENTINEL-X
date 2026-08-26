"""Tests for the sentinel_x CLI dispatcher (__main__.py)."""

from __future__ import annotations

from unittest.mock import patch

from sentinel_x.__main__ import COMMANDS, main


def test_help_exits_cleanly(capsys: object) -> None:
    with patch("sys.argv", ["sentinel-x", "--help"]):
        assert main() == 0


def test_no_args_returns_nonzero() -> None:
    with patch("sys.argv", ["sentinel-x"]):
        assert main() == 1


def test_unknown_command_returns_one(capsys: object) -> None:
    with patch("sys.argv", ["sentinel-x", "nonexistent"]):
        assert main() == 1


def test_all_commands_importable() -> None:
    from importlib import import_module

    for _name, path in COMMANDS.items():
        mod = import_module(path)
        assert callable(getattr(mod, "main", None)), f"{path}.main not callable"
