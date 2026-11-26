"""Command line for threat detection.

    python -m detection rules              list the detection rules
    python -m detection run                check new log events once
    python -m detection watch [-i 10]      keep checking every N seconds (Ctrl+C to stop)
    python -m detection alerts             show fired alerts
    python -m detection mitre-doc          (re)write docs/mitre-mapping.md from the rule files
"""
import argparse
import time

from common import config
from common.aws import AwsContext
from detection.engine import DetectionEngine, read_alerts
from detection.rules import load_rules


def print_alert(a):
    print(f"  ALERT [{a['severity'].upper():8}] {a['rule_id']} {a['rule_name']}\n"
          f"        {a['summary']}\n"
          f"        MITRE {a['mitre_technique']} | event {a['event_time']} | detected {a['detected_at']}")


def cmd_rules(_args):
    for r in load_rules():
        print(f"{r.id:8} {r.severity:9} {r.type:18} {r.mitre['technique_id']:10} {r.name}")


def cmd_run(args):
    aws = AwsContext()
    engine = DetectionEngine(aws, notify=not args.no_notify)
    alerts = engine.run_once()
    print(f"[{aws.mode.upper()} MODE] checked new events: {len(alerts)} alert(s)")
    for a in alerts:
        print_alert(a)


def cmd_watch(args):
    aws = AwsContext()
    engine = DetectionEngine(aws, notify=not args.no_notify)
    print(f"[{aws.mode.upper()} MODE] watching {config.CLOUDTRAIL_LOG_GROUP} and "
          f"{config.FLOW_LOG_GROUP} every {args.interval}s (Ctrl+C to stop)")
    try:
        while True:
            for a in engine.run_once():
                print_alert(a)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopped")


def cmd_alerts(args):
    alerts = read_alerts()[-args.last:]
    print(f"{len(alerts)} alert(s)")
    for a in alerts:
        print_alert(a)


def cmd_mitre_doc(_args):
    rules = load_rules()
    lines = ["# Detection rules mapped to MITRE ATT&CK (Cloud)", "",
             "Generated from `detection/rules/*/rule.yaml` by `python -m detection mitre-doc`.", "",
             "| Rule | Name | Severity | Type | MITRE technique | Tactic | Frequency |",
             "|---|---|---|---|---|---|---|"]
    for r in rules:
        url = "https://attack.mitre.org/techniques/" + r.mitre["technique_id"].replace(".", "/")
        lines.append(f"| {r.id} | {r.name} | {r.severity} | {r.type} | "
                     f"[{r.mitre['technique_id']}]({url}) {r.mitre['technique']} | "
                     f"{r.mitre['tactic']} | {r.frequency} |")
    path = config.ROOT / "docs" / "mitre-mapping.md"
    path.write_text("\n".join(lines) + "\n")
    print(f"Written {path}")


def main():
    parser = argparse.ArgumentParser(prog="python -m detection", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("rules", help="list detection rules").set_defaults(func=cmd_rules)
    run = sub.add_parser("run", help="evaluate new events once")
    run.add_argument("--no-notify", action="store_true", help="do not publish to SNS/log group")
    run.set_defaults(func=cmd_run)
    watch = sub.add_parser("watch", help="evaluate continuously")
    watch.add_argument("-i", "--interval", type=int, default=10)
    watch.add_argument("--no-notify", action="store_true")
    watch.set_defaults(func=cmd_watch)
    alerts = sub.add_parser("alerts", help="show fired alerts")
    alerts.add_argument("--last", type=int, default=20)
    alerts.set_defaults(func=cmd_alerts)
    sub.add_parser("mitre-doc", help="write docs/mitre-mapping.md").set_defaults(func=cmd_mitre_doc)
    args = parser.parse_args()
    args.func(args)
