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


def comparable_scans():
    """Scans from the same mode and account as the newest scan, oldest first.

    Drift and trends only make sense within one environment: never compare an
    emulator scan with a real-account scan, or two different accounts."""
    paths = list_scans()
    if not paths:
        return []
    def env(path):
        data = json.loads(open(path).read())
        return data.get("mode"), data.get("account_id")
    target = env(paths[-1])
    return [p for p in paths if env(p) == target]


def load_scan(path) -> dict:
    data = json.loads(open(path).read())
    data["findings"] = [Finding.from_dict(f) for f in data["findings"]]
    return data
