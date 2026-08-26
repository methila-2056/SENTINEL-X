"""Sentinel-X CLI dispatcher.

Usage:
    python -m sentinel_x <command> [options]

Commands:
    seed                  Seed database with events + incidents + knowledge graph
    init-db               Bootstrap schema on a fresh PostgreSQL
    create-user           Create or update an API user account
    download-cicids       Download CIC-IDS2017 raw CSVs
    download-knowledge    Download MITRE ATT&CK + SigmaHQ sources
    generate-synth        Generate synthetic security telemetry
"""

import sys
from importlib import import_module

COMMANDS = {
    "seed":             "sentinel_x.scripts.seed_pipeline",
    "init-db":          "sentinel_x.scripts.init_db",
    "create-user":      "sentinel_x.scripts.create_user",
    "download-cicids":  "sentinel_x.scripts.download_cicids",
    "download-knowledge": "sentinel_x.scripts.download_knowledge",
    "generate-synth":   "sentinel_x.scripts.generate_synthetic",
}

USAGE = """\
Usage: python -m sentinel_x <command> [options]

Commands:
  seed                   Seed database with events + incidents + knowledge graph
  init-db                Bootstrap schema on a fresh PostgreSQL
  create-user            Create or update an API user account
  download-cicids        Download CIC-IDS2017 raw CSVs
  download-knowledge     Download MITRE ATT&CK + SigmaHQ sources
  generate-synth         Generate synthetic security telemetry
"""


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(USAGE)
        return 0 if sys.argv[1:] else 1

    name = sys.argv[1]
    if name not in COMMANDS:
        print(f"Unknown command: {name!r}\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 1

    sys.argv = [sys.argv[0], *sys.argv[2:]]
    mod = import_module(COMMANDS[name])
    return mod.main()


if __name__ == "__main__":
    raise SystemExit(main())
