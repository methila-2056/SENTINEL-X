"""Export the OpenAPI specification from the FastAPI application.

Usage:
    sentinelx-openapi > openapi.json
    sentinelx-openapi --format yaml > openapi.yaml
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Export SENTINEL-X OpenAPI spec")
    parser.add_argument(
        "--format", choices=["json", "yaml"], default="json", help="Output format (default: json)"
    )
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    from sentinel_x.api.app import create_app

    app = create_app()
    spec = app.openapi()

    # Inject version from pyproject.toml
    pyproject = Path("pyproject.toml")
    if pyproject.exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        spec["info"]["version"] = data.get("project", {}).get("version", spec["info"]["version"])

    if args.format == "yaml":
        try:
            import yaml

            output = yaml.dump(spec, default_flow_style=False, sort_keys=False)
        except ImportError:
            print("PyYAML not installed; falling back to JSON", file=sys.stderr)
            output = json.dumps(spec, indent=2, default=str)
    else:
        output = json.dumps(spec, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output)
