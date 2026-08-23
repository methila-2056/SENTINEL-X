"""Knowledge source parsers producing normalized document dicts."""

import json
from pathlib import Path

import structlog
import yaml

logger = structlog.get_logger(__name__)

DocumentDict = dict  # {source, document_type, external_id, title, content, metadata}


def parse_mitre_stix(stix_path: Path) -> list[DocumentDict]:
    """Extract attack-patterns (techniques), mitigations and relationships from the ATT&CK STIX bundle."""
    with open(stix_path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    objects = bundle.get("objects", [])

    docs: list[DocumentDict] = []
    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            if obj.get("revoked"):
                continue
            external_refs = obj.get("external_references", [])
            technique_id = next(
                (
                    ref.get("external_id")
                    for ref in external_refs
                    if ref.get("source_name") == "mitre-attack"
                ),
                None,
            )
            kill_chain = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            platforms = obj.get("x_mitre_platforms", [])
            detection = obj.get("x_mitre_detection", "")
            description = obj.get("description", "")
            content = (
                f"MITRE ATT&CK technique {technique_id or 'unknown'}: {obj.get('name', '')}. "
                f"Description: {description} "
                f"Detection guidance: {detection}"
            ).strip()
            if not description:
                continue
            docs.append(
                {
                    "source": "mitre_attack",
                    "document_type": "technique",
                    "external_id": technique_id,
                    "title": f"{technique_id or 'T????'}: {obj.get('name', '')}",
                    "content": content,
                    "metadata": {
                        "technique_id": technique_id,
                        "tactics": kill_chain,
                        "platforms": platforms,
                        "stix_id": obj.get("id"),
                    },
                }
            )
        elif obj_type == "relationship":
            # Keep only mitigates relationships for mitigation context
            if obj.get("relationship_type") != "mitigates":
                continue
        elif obj_type == "course-of-action":
            docs.append(
                {
                    "source": "mitre_attack",
                    "document_type": "mitigation",
                    "external_id": obj.get("external_references", [{}])[0].get("external_id"),
                    "title": obj.get("name", "Mitigation"),
                    "content": f"Mitigation: {obj.get('name', '')}. {obj.get('description', '')}".strip(),
                    "metadata": {"stix_id": obj.get("id")},
                }
            )
    logger.info("mitre_parsed", documents=len(docs))
    return docs


SIGMA_SECTIONS = ("title", "description", "logsource", "detection")


def parse_sigma_rule(path: Path) -> DocumentDict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
    except Exception:  # noqa: BLE001 - skip malformed rules
        return None
    if not isinstance(rule, dict) or rule.get("title") is None:
        return None
    title = str(rule.get("title"))
    description = str(rule.get("description") or "")
    logsource = rule.get("logsource") or {}
    detection = rule.get("detection") or {}
    tags = rule.get("tags") or []
    level = rule.get("level")

    selection_lines = []
    for key, value in detection.items():
        if key == "condition":
            selection_lines.append(f"condition: {value}")
        else:
            selection_lines.append(f"{key}: {json.dumps(value, default=str)[:400]}")

    content = (
        f"Sigma detection rule '{title}'. {description} "
        f"Log source: category={logsource.get('category')}, product={logsource.get('product')}, "
        f"service={logsource.get('service')}. "
        f"Detection logic: {'; '.join(selection_lines)[:1200]}"
    )
    return {
        "source": "sigma",
        "document_type": "detection_rule",
        "external_id": rule.get("id"),
        "title": title,
        "content": content,
        "metadata": {
            "tags": [str(t) for t in tags][:20],
            "level": level,
            "product": logsource.get("product"),
            "category": logsource.get("category"),
        },
    }


def load_sigma_rules(rules_dir: Path, limit: int | None = 3000) -> list[DocumentDict]:
    docs: list[DocumentDict] = []
    paths = sorted(Path(rules_dir).rglob("*.yml"))
    for path in paths[:limit] if limit else paths:
        parsed = parse_sigma_rule(path)
        if parsed:
            docs.append(parsed)
    logger.info("sigma_parsed", documents=len(docs))
    return docs


def load_playbooks(playbook_dir: Path) -> list[DocumentDict]:
    docs: list[DocumentDict] = []
    for path in sorted(Path(playbook_dir).glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = text.splitlines()[0].lstrip("# ").strip() if text.splitlines() else path.stem
        docs.append(
            {
                "source": "playbook",
                "document_type": "playbook",
                "external_id": path.stem,
                "title": title,
                "content": text,
                "metadata": {"filename": path.name},
            }
        )
    logger.info("playbooks_parsed", documents=len(docs))
    return docs
