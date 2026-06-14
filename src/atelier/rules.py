import fnmatch
import tomllib
from pathlib import Path
from typing import Any

from atelier.types import (
    DEFAULT_INCLUDE,
    DEFAULT_SYSTEMS,
    NIXOS_CACHE,
    PER_SYSTEM_SETS,
    Rules,
)

_GLOB_CHARS = frozenset("*?[]")


def _build(data: dict[str, Any]) -> Rules:
    """Build ``Rules`` from parsed toml, falling back to defaults for omitted keys.

    The official cache is always folded into ``substituters`` (a set, so a user
    who also lists it does not duplicate it), so cache-status checks work even
    when the rule file names no cache of its own.
    """
    return Rules(
        systems=tuple(data.get("systems", DEFAULT_SYSTEMS)),
        include=tuple(data.get("include", DEFAULT_INCLUDE)),
        exclude=tuple(data.get("exclude", ())),
        substituters=frozenset(data.get("substituters", ())) | {NIXOS_CACHE},
        trusted_public_keys=frozenset(data.get("trusted-public-keys", ())),
    )


def load(path: Path) -> Rules:
    """Read a rule file, falling back to defaults for any omitted key."""
    return _build(tomllib.loads(path.read_text()))


def defaults() -> Rules:
    """The rules used when no rule file exists, every key at its built-in default.

    Identical to loading an empty rule file, so a missing ``atelier.toml`` and an
    empty one evaluate the same flake.
    """
    return _build({})


def matches(pattern: str, path: str) -> bool:
    """Match a dotted glob against a flake attribute path.

    Matching is segment wise with an equal segment count, so a bare ``*`` spans
    exactly one segment and a nested scope needs its own segment. Thus
    ``legacyPackages.*.*`` matches ``legacyPackages.x86_64-linux.caddy`` but not
    ``legacyPackages.x86_64-linux.ocamlPackages.dune``, which needs the explicit
    ``legacyPackages.*.ocamlPackages.*``.
    """
    pat = pattern.split(".")
    seg = path.split(".")
    if len(pat) != len(seg):
        return False
    return all(fnmatch.fnmatchcase(s, p) for p, s in zip(pat, seg, strict=True))


def included(path: str, rules: Rules) -> bool:
    """True when `path` matches any include glob."""
    return any(matches(pattern, path) for pattern in rules.include)


def excluded(path: str, rules: Rules) -> bool:
    """True when `path` matches any exclude glob."""
    return any(matches(pattern, path) for pattern in rules.exclude)


def prunable_excludes(rules: Rules) -> dict[str, dict[str, list[str]]]:
    """Exact leaf names droppable before evaluation, grouped by set then system.

    Handles ``<set>.<sys>.<leaf>`` excludes where ``<sys>`` is ``*`` (all systems)
    or a literal system, and ``<leaf>`` is literal (no glob metacharacters). The
    select expression ``removeAttrs`` them so nix-eval-jobs never forces, fetches,
    or builds an excluded attribute. Broader globs stay post-eval filters.

    Shape: ``{set: {("*" | system): [leaf, ...]}}``.
    """
    out: dict[str, dict[str, list[str]]] = {}
    for pattern in rules.exclude:
        parts = pattern.split(".")
        if len(parts) != 3 or parts[0] not in PER_SYSTEM_SETS:
            continue
        system, leaf = parts[1], parts[2]
        if _GLOB_CHARS & set(leaf):
            continue
        if system != "*" and _GLOB_CHARS & set(system):
            continue
        out.setdefault(parts[0], {}).setdefault(system, []).append(leaf)
    return {
        output: {system: sorted(set(leaves)) for system, leaves in by_system.items()}
        for output, by_system in out.items()
    }
