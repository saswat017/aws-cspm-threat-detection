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


def comparable_scans(mode=None):
    """Scans of one environment (mode + account), oldest first.

    Drift and trends only make sense within one environment: never compare an
    emulator scan with a real-account scan, or two different accounts.
    By default the environment is the current CSPM_MODE and the account of the
    newest scan in that mode."""
    mode = mode or config.MODE
    def env(path):
        data = json.loads(open(path).read())
        return data.get("mode"), data.get("account_id")
    in_mode = [(p, env(p)) for p in list_scans() if env(p)[0] == mode]
    if not in_mode:
        return []
    target = in_mode[-1][1]
    return [p for p, e in in_mode if e == target]
