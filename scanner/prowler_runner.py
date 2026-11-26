"""Optional: run Prowler (open-source CSPM tool) with the CIS AWS benchmark.

Prowler only runs in live mode (real AWS). Its JSON-OCSF output is converted
into the same Finding format as the custom checks, so both appear in one
report and one score.
"""
import json
import shutil
import subprocess
from pathlib import Path

from common import config
from scanner.models import Finding

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "informational": "low"}
STATUS_MAP = {"PASS": "PASS", "FAIL": "FAIL", "MANUAL": "ERROR", "MUTED": "PASS"}


def prowler_available() -> bool:
    return shutil.which("prowler") is not None


def run_prowler(profile: str, region: str, compliance: str = "cis_3.0_aws") -> Path:
    """Run Prowler and return the path of its JSON-OCSF output file."""
    out_dir = config.RESULTS_DIR / "prowler"
    out_dir.mkdir(exist_ok=True)
    cmd = ["prowler", "aws", "--profile", profile, "--filter-region", region,
           "--compliance", compliance, "--output-formats", "json-ocsf",
           "--output-directory", str(out_dir), "--output-filename", "prowler-latest",
           "--no-banner"]
    # Prowler exits with code 3 when it finds failed checks; that is not an error.
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 3):
        raise RuntimeError(f"Prowler failed ({proc.returncode}): {proc.stderr[-500:]}")
    files = sorted(out_dir.glob("prowler-latest*.json"))
    if not files:
        raise RuntimeError("Prowler produced no JSON output")
    return files[-1]


def normalize_ocsf(path: Path) -> list:
    """Convert Prowler JSON-OCSF records into Finding objects."""
    records = json.loads(Path(path).read_text())
    findings = []
    for r in records:
        info = r.get("finding_info", {})
        resources = r.get("resources") or [{}]
        res = resources[0]
        compliance = (r.get("unmapped") or {}).get("compliance") or {}
        cis = next((f"{k} {', '.join(v)}" for k, v in compliance.items() if k.startswith("CIS")), "n/a")
        findings.append(Finding(
            check_id=(r.get("metadata") or {}).get("event_code") or info.get("uid", "prowler"),
            title=info.get("title", ""),
            severity=SEVERITY_MAP.get(str(r.get("severity", "low")).lower(), "low"),
            status=STATUS_MAP.get(str(r.get("status_code", "")).upper(), "ERROR"),
            resource_id=res.get("uid") or res.get("name") or "n/a",
            resource_type=res.get("type", ""),
            region=res.get("region") or (r.get("cloud") or {}).get("region", ""),
            service=(res.get("group") or {}).get("name", ""),
            cis_ref=cis,
            description=info.get("desc", ""),
            recommendation=(r.get("remediation") or {}).get("desc", ""),
            evidence=r.get("status_detail", ""),
            source="prowler",
        ))
    return findings
