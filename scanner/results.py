"""Saving and loading scan results (one timestamped JSON file per scan in results/)."""
import json
from datetime import datetime, timezone

from common import config
from scanner.models import Finding

SCAN_GLOB = "scan-*.json"


def save_scan(meta: dict, findings) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = config.RESULTS_DIR / f"scan-{stamp}.json"
    payload = {**meta, "scan_id": stamp, "findings": [f.to_dict() for f in findings]}
    path.write_text(json.dumps(payload, indent=2))
    return str(path)


def list_scans():
    """All scan files, oldest first (the timestamp in the name sorts correctly)."""
    return sorted(config.RESULTS_DIR.glob(SCAN_GLOB))


def load_scan(path) -> dict:
    data = json.loads(open(path).read())
    data["findings"] = [Finding.from_dict(f) for f in data["findings"]]
    return data
