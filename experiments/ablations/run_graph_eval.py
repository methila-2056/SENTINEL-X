"""Graph-traversal evaluation: does multi-hop reasoning surface IOC paths?

For every ground-truth incident host, checks whether the knowledge graph
contains a path (<= max hops) from that host to a known-malicious IOC node,
and compares against a benign-host control sample. Reports hit-rate
separation between attack and benign groups.

Usage:
    python experiments/ablations/run_graph_eval.py [--hops 4]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.graph.traversal.walk import neighborhood, paths_to_iocs  # noqa: E402

BENIGN_SAMPLE = 30


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hops", type=int, default=4)
    parser.add_argument(
        "--ground-truth", default=str(ROOT / "data/processed/synthetic/incidents_ground_truth.json")
    )
    args = parser.parse_args()
    configure_logging()

    with open(args.ground_truth, encoding="utf-8") as fh:
        incidents = json.load(fh)

    # Attack group: hosts named in ground truth incidents
    attack_hosts = sorted({h for inc in incidents for h in inc.get("compromised_hosts", [])})

    # Control group: hosts present in graph but not in any incident
    from sqlalchemy import select

    from sentinel_x.common.db import get_sync_session
    from sentinel_x.data.db.models import EntityRow

    with get_sync_session() as session:
        all_hosts = session.scalars(
            select(EntityRow.name).where(EntityRow.entity_type == "host").limit(500)
        ).all()
    attack_set = set(attack_hosts)
    benign_hosts = [h for h in all_hosts if h not in attack_set][:BENIGN_SAMPLE]

    def ioc_reachable(host: str) -> bool:
        if not paths_to_iocs(f"host:{host}", max_hops=args.hops, limit=1):
            return False
        nbhd = neighborhood(f"host:{host}", max_hops=args.hops)
        return any(n.get("entity_type") == "ioc" or n.get("is_malicious") for n in nbhd.nodes)

    attack_hits = [ioc_reachable(h) for h in attack_hosts]
    benign_hits = [ioc_reachable(h) for h in benign_hosts]

    def rate(hits: list[bool]) -> float:
        return round(sum(hits) / len(hits), 4) if hits else 0.0

    summary = {
        "max_hops": args.hops,
        "attack_hosts": len(attack_hosts),
        "benign_hosts": len(benign_hosts),
        "attack_ioc_path_rate": rate(attack_hits),
        "benign_ioc_path_rate": rate(benign_hits),
        "separation": round(rate(attack_hits) - rate(benign_hits), 4),
    }

    out_dir = ROOT / "experiments/ablations"
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Graph traversal: IOC path discovery",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Max hops | {args.hops} |",
        f"| Attack hosts evaluated | {summary['attack_hosts']} |",
        f"| Benign controls | {summary['benign_hosts']} |",
        f"| Attack hosts with IOC path | {summary['attack_ioc_path_rate']:.1%} |",
        f"| Benign hosts with IOC path | {summary['benign_ioc_path_rate']:.1%} |",
        f"| Separation (attack - benign) | {summary['separation']:+.1%} |",
    ]
    (out_dir / "graph_eval.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(out_dir / "graph_eval.json", "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
