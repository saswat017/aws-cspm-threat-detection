"""Command line for the posture scanner.

    python -m scanner scan [--no-prowler]   run all checks, save results/scan-<time>.json
    python -m scanner diff                  compare the last two scans (drift detection)
    python -m scanner report                build an HTML assessment report (Module 6)
    python -m scanner checks                list every custom check
"""
import argparse
import sys
from collections import Counter

from common import config
from common.aws import AwsContext
from scanner import results
from scanner.checks import ALL_CHECKS
from scanner.diff import diff_scans
from scanner.models import utc_now
from scanner.scoring import summarize

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_scan(aws, use_prowler=True, quiet=False):
    """Run every check and Prowler (live mode only). Returns (path, meta, findings)."""
    started = utc_now()
    findings = []
    for check_cls in ALL_CHECKS:
        out = check_cls(aws).run()
        findings.extend(out)
        if not quiet:
            c = Counter(f.status for f in out)
            print(f"  {check_cls.id:8} {check_cls.title[:60]:60} "
                  f"pass {c['PASS']:2}  fail {c['FAIL']:2}  error {c['ERROR']:2}")

    prowler_note = "skipped"
    if use_prowler and aws.mode == "live":
        from scanner import prowler_runner
        if prowler_runner.prowler_available():
            if not quiet:
                print("  Running Prowler (CIS benchmark), this takes a few minutes...")
            out = prowler_runner.normalize_ocsf(prowler_runner.run_prowler(config.AWS_PROFILE, aws.region))
            findings.extend(out)
            prowler_note = f"{len(out)} results"
        else:
            prowler_note = "not installed"
    elif aws.mode == "demo":
        prowler_note = "skipped (demo mode: Prowler needs real AWS)"

    meta = {"mode": aws.mode, "account_id": aws.account_id, "region": aws.region,
            "started_at": started, "finished_at": utc_now(), "prowler": prowler_note,
            "summary": summarize(findings)}
    path = results.save_scan(meta, findings)
    return path, meta, findings


def cmd_scan(args):
    aws = AwsContext()
    banner = ("DEMO MODE: local AWS emulator, not a real AWS account"
              if aws.mode == "demo" else f"LIVE MODE: real AWS, profile {config.AWS_PROFILE}")
    print(f"[{banner}]  account {aws.account_id}  region {aws.region}\n")
    path, meta, findings = run_scan(aws, use_prowler=not args.no_prowler)
    s = meta["summary"]
    print(f"\nPosture score: {s['score']}/100   "
          f"({s['passed']} pass, {s['failed']} fail, {s['errors']} error, coverage {s['coverage_pct']}%)")
    print("Failed by severity: " + ", ".join(f"{k} {v}" for k, v in s["failed_by_severity"].items()))
    print(f"Prowler: {meta['prowler']}")
    fails = sorted((f for f in findings if f.status == "FAIL"), key=lambda f: SEV_ORDER[f.severity])
    if fails:
        print("\nTop findings:")
        for f in fails[:15]:
            print(f"  [{f.severity.upper():8}] {f.check_id:8} {f.resource_id[:40]:40} {f.evidence[:60]}")
    print(f"\nSaved: {path}")


def cmd_diff(_args):
    scans = results.list_scans()
    if len(scans) < 2:
        sys.exit("Need at least two scans. Run `python -m scanner scan` twice.")
    d = diff_scans(results.load_scan(scans[-2]), results.load_scan(scans[-1]))
    print(f"Drift between scan {d['old_scan']} and {d['new_scan']}")
    print(f"Score change: {d['score_change']:+}   unchanged findings: {d['unchanged']}\n")
    print(f"NEW findings ({len(d['new'])}):")
    for f in d["new"]:
        print(f"  + [{f.severity.upper():8}] {f.check_id:8} {f.resource_id[:40]:40} {f.evidence[:60]}")
    print(f"\nRESOLVED findings ({len(d['resolved'])}):")
    for f in d["resolved"]:
        print(f"  - [{f.severity.upper():8}] {f.check_id:8} {f.resource_id[:40]}")


def cmd_checks(_args):
    for c in ALL_CHECKS:
        print(f"{c.id:8} {c.severity:9} {c.cis_ref:32} {c.title}")


def cmd_report(_args):
    try:
        from scanner.report import build_report
    except ImportError:
        sys.exit("The HTML report is part of Module 6 (dashboard and reports), not built yet.")
    print(f"Report written: {build_report()}")


def main():
    parser = argparse.ArgumentParser(prog="python -m scanner", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run every check and save the results")
    scan.add_argument("--no-prowler", action="store_true", help="skip Prowler in live mode")
    scan.set_defaults(func=cmd_scan)
    sub.add_parser("diff", help="new/resolved findings between the last two scans").set_defaults(func=cmd_diff)
    sub.add_parser("checks", help="list the custom checks").set_defaults(func=cmd_checks)
    sub.add_parser("report", help="HTML assessment report").set_defaults(func=cmd_report)
    args = parser.parse_args()
    args.func(args)
