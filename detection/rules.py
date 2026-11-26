"""Loading detection rules from detection/rules/<name>/ folders."""
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent / "rules"
RULE_TYPES = {"event", "threshold", "new_value", "flowlog_threshold"}


@dataclass
class Rule:
    folder: str
    id: str
    name: str
    severity: str
    type: str
    source: str            # cloudtrail | flowlogs
    description: str
    mitre: dict
    frequency: str
    response: str = ""
    pattern: dict = field(default_factory=dict)
    threshold: dict = field(default_factory=dict)
    new_value: dict = field(default_factory=dict)
    flowlog_match: dict = field(default_factory=dict)
    filter_pattern: str = ""   # CloudWatch metric filter syntax (Terraform)
    query: str = ""            # CloudWatch Logs Insights query (hunting)


def load_rules(rules_dir: Path = RULES_DIR) -> list:
    rules = []
    for meta_path in sorted(rules_dir.glob("*/rule.yaml")):
        folder = meta_path.parent
        meta = yaml.safe_load(meta_path.read_text())
        if meta.get("type") not in RULE_TYPES:
            raise ValueError(f"{meta_path}: type must be one of {sorted(RULE_TYPES)}")
        pattern_file = folder / "pattern.json"
        rules.append(Rule(
            folder=folder.name,
            id=meta["id"], name=meta["name"], severity=meta["severity"], type=meta["type"],
            source=meta.get("source", "cloudtrail"), description=meta["description"].strip(),
            mitre=meta["mitre"], frequency=meta.get("frequency", ""),
            response=meta.get("response", "").strip(),
            pattern=json.loads(pattern_file.read_text()) if pattern_file.exists() else {},
            threshold=meta.get("threshold", {}), new_value=meta.get("new_value", {}),
            flowlog_match=meta.get("flowlog_match", {}),
            filter_pattern=_read(folder / "filter.txt"), query=_read(folder / "query.sql"),
        ))
    return sorted(rules, key=lambda r: r.id)


def _read(path: Path) -> str:
    return path.read_text().strip() if path.exists() else ""
