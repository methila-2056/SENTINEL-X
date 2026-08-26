"""Tests for the OpenAPI export script."""

from __future__ import annotations

from sentinel_x.api.app import create_app


def test_openapi_spec_has_required_fields() -> None:
    app = create_app()
    spec = app.openapi()
    assert "openapi" in spec
    assert "info" in spec
    assert "paths" in spec
    assert spec["info"]["title"] == "SENTINEL-X API"


def test_openapi_spec_covers_all_routers() -> None:
    app = create_app()
    spec = app.openapi()
    paths = set(spec["paths"].keys())
    expected_prefixes = [
        "/api/incidents",
        "/api/events",
        "/api/auth",
        "/api/investigations",
        "/api/knowledge",
        "/api/admin",
        "/api/ml",
        "/api/graph",
    ]
    for prefix in expected_prefixes:
        assert any(p.startswith(prefix) for p in paths), f"No paths starting with {prefix}"


def test_openapi_spec_includes_auth_security() -> None:
    app = create_app()
    spec = app.openapi()
    # Should have security scheme for bearer auth
    components = spec.get("components", {}).get("securitySchemes", {})
    assert len(components) > 0 or "security" in spec
