"""Tests for API role-gating dependencies."""

from __future__ import annotations

from sentinel_x.api.deps import KNOWN_ROLES, AuthUser, require_roles


def test_known_roles_are_fixed() -> None:
    assert set(KNOWN_ROLES) == {"admin", "analyst", "viewer"}


def test_require_roles_allows_matching_role() -> None:
    checker = require_roles("admin", "analyst")
    user = AuthUser(username="alice", role="analyst")
    # require_roles returns a Depends; call the inner checker directly
    result = checker(user=user)
    assert result == user


def test_require_roles_rejects_wrong_role() -> None:
    from fastapi import HTTPException

    checker = require_roles("admin")
    user = AuthUser(username="bob", role="viewer")
    try:
        checker(user=user)
        raise AssertionError("should have raised")
    except HTTPException as exc:
        assert exc.status_code == 403
