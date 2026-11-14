"""CEL applicability expressions (`when:` in rule frontmatter), evaluated over a `ctx` map.
https://github.com/google/cel-spec"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import celpy

from governance.context_model import ContextModel, ServiceContext


class CelError(Exception):
    pass


@lru_cache(maxsize=512)
def _program(expression: str) -> Any:
    env = celpy.Environment()
    try:
        return env.program(env.compile(expression))
    except Exception as exc:  # celpy raises several parser exception types
        raise CelError(f"cannot compile {expression!r}: {exc}") from exc


def compile_check(expression: str) -> None:
    _program(expression)


def evaluate(expression: str, activation: dict[str, Any]) -> bool:
    program = _program(expression)
    try:
        result = program.evaluate({"ctx": celpy.json_to_cel(activation)})
    except Exception as exc:  # CELEvalError and conversion errors
        raise CelError(f"cannot evaluate {expression!r}: {exc}") from exc
    if not isinstance(result, celpy.celtypes.BoolType):
        raise CelError(f"{expression!r} returned {type(result).__name__}, not bool")
    return bool(result)


def build_activation(
    model: ContextModel,
    service: ServiceContext,
    *,
    environment: str,
    languages: list[str],
    frameworks: list[str],
    platforms: list[str],
    tasks: list[str],
    profiles: list[str],
) -> dict[str, Any]:
    activation: dict[str, Any] = {
        "environment": environment,
        "languages": languages,
        "frameworks": frameworks,
        "platforms": platforms,
        "tasks": tasks,
        "profiles": profiles,
        "component": service.component or "",
    }
    for dim, attr in service.attributes.items():
        activation[dim] = attr.value
        if dim in model.ordered:
            activation[f"{dim}_rank"] = model.rank(dim, attr.value)
    return activation


def sample_activation(model: ContextModel) -> dict[str, Any]:
    """A fully populated activation used by the registry linter to catch unknown fields."""
    activation: dict[str, Any] = {
        "environment": "production",
        "languages": [],
        "frameworks": [],
        "platforms": [],
        "tasks": [],
        "profiles": [],
        "component": "",
    }
    for dim, values in model.ordered.items():
        activation[dim] = values[-1]
        activation[f"{dim}_rank"] = len(values) - 1
    for dim, values in model.sets.items():
        activation[dim] = list(values)
    return activation
