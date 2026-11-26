"""The normalized finding format shared by custom checks and Prowler."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SEVERITIES = ["critical", "high", "medium", "low"]

# PASS  = the resource meets the rule
# FAIL  = the resource breaks the rule (a finding)
# ERROR = could not check it (for example AccessDenied); never counted as a pass
STATUSES = ["PASS", "FAIL", "ERROR"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    check_id: str          # e.g. "S3-001" or a Prowler check name
    title: str
    severity: str          # critical | high | medium | low
    status: str            # PASS | FAIL | ERROR
    resource_id: str
    resource_type: str
    region: str
    service: str           # s3, ec2, iam, ...
    cis_ref: str           # CIS AWS Foundations reference, or "n/a (...)"
    description: str
    recommendation: str    # text only: the scanner never changes anything
    evidence: str = ""     # what was observed, in plain words
    source: str = "custom"  # custom | prowler
    timestamp: str = field(default_factory=utc_now)

    @property
    def key(self) -> str:
        """Identity used by `scanner diff` to match a finding across scans."""
        return f"{self.check_id}|{self.resource_id}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**known)
