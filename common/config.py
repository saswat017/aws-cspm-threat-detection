"""Central settings, read from environment variables (and an optional .env file).

CSPM_MODE decides where every module talks to:
  demo  -> the local AWS emulator (moto). No AWS account needed.
  live  -> real AWS, using the named profile in AWS_PROFILE.
"""
import os
from pathlib import Path

try:  # python-dotenv is optional; without it, plain environment variables work
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

ROOT = Path(__file__).resolve().parent.parent
if load_dotenv:
    load_dotenv(ROOT / ".env")

MODE = os.getenv("CSPM_MODE", "demo").strip().lower()
if MODE not in ("demo", "live"):
    raise SystemExit(f"CSPM_MODE must be 'demo' or 'live', not {MODE!r}")

REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", "cspm-lab")
EMULATOR_ENDPOINT = os.getenv("EMULATOR_ENDPOINT", "http://127.0.0.1:5001")

# Scanner policy: more admins than this is a finding (IAM-004).
ADMIN_THRESHOLD = int(os.getenv("ADMIN_THRESHOLD", "2"))
# Scanner policy: access keys older than this many days are a finding (IAM-006).
ACCESS_KEY_MAX_AGE_DAYS = int(os.getenv("ACCESS_KEY_MAX_AGE_DAYS", "90"))

# Names created by terraform/monitoring.
PROJECT = os.getenv("CSPM_PROJECT", "cspm-lab")
CLOUDTRAIL_LOG_GROUP = "/cspm/cloudtrail"
FLOW_LOG_GROUP = "/cspm/vpc-flow-logs"
ALERTS_LOG_GROUP = "/security/alerts"
ALERTS_TOPIC_NAME = f"{PROJECT}-security-alerts"

RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)
