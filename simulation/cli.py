"""Command line for attack simulation.

    python -m simulation list                     list scenarios
    python -m simulation run <name>|all           perform a scenario (logs the time to simulation/log.json)
    python -m simulation revert <name>|all        undo it
    python -m simulation mttd                     Mean Time To Detect per scenario

Live mode changes REAL AWS resources, so it asks for confirmation (or --yes).
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from botocore.exceptions import ClientError

from common.aws import AwsContext
from detection.engine import read_alerts
from simulation.scenarios import SCENARIOS

LOG_FILE = Path(__file__).resolve().parent / "log.json"


def now():
    return datetime.now(timezone.utc)


def read_log():
    return json.loads(LOG_FILE.read_text()) if LOG_FILE.exists() else []


def append_log(entry):
    log = read_log()
    log.append(entry)
    LOG_FILE.write_text(json.dumps(log, indent=2))


def last_saved_state(name):
    for entry in reversed(read_log()):
        if entry["scenario"] == name and entry["action"] == "run":
            return entry.get("details", {})
    return {}


def confirm_live(aws, args, what):
    if aws.mode == "live" and not args.yes:
        answer = input(f"LIVE MODE: this will {what} in REAL AWS account {aws.account_id}. Type 'yes': ")
        if answer.strip().lower() != "yes":
            sys.exit("Cancelled.")


def selected(name):
    if name == "all":
        return list(SCENARIOS)
    if name not in SCENARIOS:
        sys.exit(f"Unknown scenario {name!r}. Try: python -m simulation list")
    return [name]


def cmd_list(_args):
    for s in SCENARIOS.values():
        flag = " (demo only)" if s.demo_only else ""
        print(f"{s.name:20} expects {', '.join(s.expected_rules):18} {s.title}{flag}")


def run_one(aws, name) -> dict:
    """Run one scenario and log it. Used by the CLI and the dashboard."""
    cls = SCENARIOS[name]
    if cls.demo_only and aws.mode != "demo":
        return {"scenario": name, "skipped": "demo only"}
    started = now()
    try:
        details = cls(aws).run()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if "Duplicate" in code or "AlreadyExists" in code:
            raise SystemExit(f"{name} is already active. Revert it first: python -m simulation revert {name}")
        raise
    entry = {"scenario": name, "action": "run", "mode": aws.mode,
             "started_at": started.isoformat(timespec="seconds"),
             "finished_at": now().isoformat(timespec="seconds"),
             "expected_rules": cls.expected_rules, "details": details}
    append_log(entry)
    return entry


def revert_one(aws, name) -> dict:
    """Undo one scenario (manual cleanup by the defender) and log it."""
    cls = SCENARIOS[name]
    if cls.demo_only and aws.mode != "demo":
        return {"scenario": name, "skipped": "demo only"}
    scenario = cls(aws)
    scenario.source_ip = scenario.operator_ip   # cleanup is done by the defender
    details = scenario.revert(last_saved_state(name))
    entry = {"scenario": name, "action": "revert", "mode": aws.mode,
             "started_at": now().isoformat(timespec="seconds"), "details": details}
    append_log(entry)
    return entry


def cmd_run(args):
    aws = AwsContext()
    names = selected(args.scenario)
    confirm_live(aws, args, f"run {', '.join(names)}")
    for name in names:
        entry = run_one(aws, name)
        if "skipped" in entry:
            print(f"skip {name}: demo only")
        else:
            print(f"RUN    {name:20} at {entry['started_at']}  expects {', '.join(entry['expected_rules'])}")


def cmd_revert(args):
    aws = AwsContext()
    names = list(reversed(selected(args.scenario)))   # undo in reverse order
    confirm_live(aws, args, f"revert {', '.join(names)}")
    for name in names:
        entry = revert_one(aws, name)
        if "skipped" not in entry:
            print(f"REVERT {name:20} {entry['details'].get('note', 'done')}")


def compute_mttd():
    """For each simulated run and each expected rule: first alert after the action."""
    alerts = read_alerts()
    rows = []
    for entry in read_log():
        if entry["action"] != "run":
            continue
        start = datetime.fromisoformat(entry["started_at"])
        for rule_id in entry["expected_rules"]:
            hits = [datetime.fromisoformat(a["detected_at"]) for a in alerts
                    if a["rule_id"] == rule_id and datetime.fromisoformat(a["detected_at"]) >= start]
            first = min(hits) if hits else None
            rows.append({"scenario": entry["scenario"], "started_at": entry["started_at"],
                         "rule_id": rule_id, "mode": entry["mode"],
                         "detected_at": first.isoformat(timespec="seconds") if first else None,
                         "mttd_seconds": round((first - start).total_seconds()) if first else None})
    return rows


def cmd_mttd(_args):
    rows = compute_mttd()
    if not rows:
        sys.exit("No simulations logged yet. Run: python -m simulation run all")
    print(f"{'scenario':20} {'rule':8} {'started (UTC)':26} {'detected':8} MTTD")
    for r in rows:
        mttd = f"{r['mttd_seconds']}s" if r["mttd_seconds"] is not None else "-"
        print(f"{r['scenario']:20} {r['rule_id']:8} {r['started_at']:26} "
              f"{'yes' if r['detected_at'] else 'MISSED':8} {mttd}")
    found = [r["mttd_seconds"] for r in rows if r["mttd_seconds"] is not None]
    print(f"\nDetected {len(found)}/{len(rows)}"
          + (f", mean time to detect {sum(found) / len(found):.0f}s" if found else ""))


def main():
    parser = argparse.ArgumentParser(prog="python -m simulation", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    for cmd, func in (("run", cmd_run), ("revert", cmd_revert)):
        p = sub.add_parser(cmd)
        p.add_argument("scenario", help="scenario name or 'all'")
        p.add_argument("--yes", action="store_true", help="skip the live-mode confirmation")
        p.set_defaults(func=func)
    sub.add_parser("mttd").set_defaults(func=cmd_mttd)
    args = parser.parse_args()
    args.func(args)
