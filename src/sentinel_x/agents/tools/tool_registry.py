"""Structured agent tool registry with validation and test harness.

Replaces the ad-hoc `build_default_tools()` dict with a declarative
registry: tools register themselves via `@tool` or `register()`, their
signatures are validated at registration time, and the whole toolbox
can be exercised in-memory without LLM or database calls.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sentinel_x.common.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    """Declarative tool definition — immutable after registration."""

    name: str
    description: str
    parameters: dict[str, str]  # param_name -> "type" or "type=default"
    fn: Callable[..., Any]
    max_results: int = 10

    def validate_args(self, args: dict[str, Any]) -> str | None:
        """Return an error message if *args* is invalid, else None."""
        sig = inspect.signature(self.fn)
        required = {
            name
            for name, p in sig.parameters.items()
            if p.default is inspect.Parameter.empty
        }
        provided = set(args.keys())
        missing = required - provided
        if missing:
            return f"missing required args: {', '.join(sorted(missing))}"
        unknown = provided - set(sig.parameters)
        if unknown:
            return f"unknown args: {', '.join(sorted(unknown))}"
        return None

    def to_prompt_doc(self) -> str:
        params = ", ".join(f"{k}:{v}" for k, v in self.parameters.items())
        return f"- {self.name}({params}): {self.description}"


class ToolRegistry:
    """Mutable registry that validates and stores tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict[str, str],
        fn: Callable[..., Any],
        *,
        max_results: int = 10,
    ) -> ToolSpec:
        spec = ToolSpec(
            name=name,
            description=description,
            parameters=parameters,
            fn=fn,
            max_results=max_results,
        )
        # Validate that fn signature matches declared parameters
        sig = inspect.signature(fn)
        declared = set(parameters.keys())
        actual = set(sig.parameters.keys())
        if declared != actual:
            raise ValueError(
                f"Tool {name}: declared params {declared} != actual fn params {actual}"
            )
        self._tools[name] = spec
        logger.debug("tool_registered", name=name)
        return spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def to_prompt_docs(self) -> str:
        return "\n".join(t.to_prompt_doc() for t in self._tools.values())

    def validate_call(self, name: str, args: dict[str, Any]) -> str | None:
        spec = self.get(name)
        if spec is None:
            return f"unknown tool: {name}"
        return spec.validate_args(args)

    def execute(self, name: str, args: dict[str, Any]) -> Any:
        spec = self.get(name)
        if spec is None:
            raise KeyError(f"unknown tool: {name}")
        err = spec.validate_args(args)
        if err:
            raise ValueError(err)
        return spec.fn(**args)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools


def build_registry() -> ToolRegistry:
    """Construct a ToolRegistry and register all default investigation tools.

    Imported lazily to avoid circular imports with DB/LLM modules.
    """
    from sentinel_x.agents.tools.registry import build_default_tools

    registry = ToolRegistry()
    for _name, tool in build_default_tools().items():
        registry.register(
            name=tool.name,
            description=tool.description,
            parameters=tool.parameters,
            fn=tool.fn,
            max_results=tool.max_results,
        )
    return registry
