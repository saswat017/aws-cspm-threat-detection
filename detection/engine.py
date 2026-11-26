"""Detection engine: reads new log events and evaluates every rule against them.

Data flow (same in demo and live mode):

    CloudTrail  -> CloudWatch Logs /cspm/cloudtrail     --+
    Flow Logs   -> CloudWatch Logs /cspm/vpc-flow-logs  --+--> engine --> alert
                                                                          |-> /security/alerts log group
                                                                          |-> SNS topic (email)
                                                                          '-> results/alerts.jsonl

Rule types:
  event              one matching event = one alert (e.g. AdministratorAccess attached)
  threshold          N matching events from the same group key within W minutes
  new_value          first time a field value is seen (e.g. a new source IP)
  flowlog_threshold  like threshold, but over VPC Flow Log records

On real AWS the event and threshold rules are ALSO deployed natively as
EventBridge rules and CloudWatch alarms by terraform/monitoring/detections.tf.
The engine state (checkpoints, windows, learned values) is kept in
results/detection_state.json so each run only looks at new events.
"""
import json
import time
import uuid
from datetime import datetime, timezone

from common import config
from detection.matcher import get_path, matches, to_eventbridge
from detection.rules import load_rules

STATE_FILE = config.RESULTS_DIR / "detection_state.json"
ALERTS_FILE = config.RESULTS_DIR / "alerts.jsonl"
FLOW_FIELDS = ["version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport",
               "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log_status"]
MAX_REMEMBERED_IDS = 5000


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="seconds")


def _event_key(group, event) -> str:
    """Identity of a log event. Includes the timestamp because an emulator restart
    can reuse event IDs."""
    return f"{group}|{event['timestamp']}|{event['eventId']}"


def parse_flow_record(message: str):
    parts = message.split()
    return dict(zip(FLOW_FIELDS, parts)) if len(parts) == len(FLOW_FIELDS) else None


class DetectionEngine:
    def __init__(self, aws, rules=None, notify=True):
        self.aws = aws
        self.logs = aws.client("logs")
        self.rules = rules if rules is not None else load_rules()
        self.notify = notify
        self.state = self._load_state()

    # ------------------------------------------------------------- state --
    def _load_state(self):
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        return {"checkpoints": {}, "seen_ids": [], "windows": {}, "cooldowns": {}, "baselines": {}}

    def _save_state(self):
        self.state["seen_ids"] = self.state["seen_ids"][-MAX_REMEMBERED_IDS:]
        STATE_FILE.write_text(json.dumps(self.state, indent=1))

    # ----------------------------------------------------------- reading --
    def _new_log_events(self, group: str):
        """All log events in `group` since the last checkpoint, oldest first."""
        start = self.state["checkpoints"].get(group, 0)
        seen = set(self.state["seen_ids"])
        events, kwargs = [], {"logGroupName": group, "startTime": start}
        try:
            while True:
                page = self.logs.filter_log_events(**kwargs)
                events += [e for e in page.get("events", []) if _event_key(group, e) not in seen]
                if not page.get("nextToken"):
                    break
                kwargs["nextToken"] = page["nextToken"]
        except self.logs.exceptions.ResourceNotFoundException:
            return []
        events.sort(key=lambda e: e["timestamp"])
        if events:
            self.state["checkpoints"][group] = events[-1]["timestamp"]
            self.state["seen_ids"] += [_event_key(group, e) for e in events]
        return events

    # ---------------------------------------------------------- evaluate --
    def run_once(self) -> list:
        """Process new events once. Returns the alerts that fired."""
        alerts = []
        for log_event in self._new_log_events(config.CLOUDTRAIL_LOG_GROUP):
            try:
                record = json.loads(log_event["message"])
            except json.JSONDecodeError:
                continue
            event = to_eventbridge(record)
            for rule in self.rules:
                if rule.source == "cloudtrail" and matches(rule.pattern, event):
                    alert = self._evaluate(rule, event, log_event["timestamp"])
                    if alert:
                        alerts.append(alert)

        flow_rules = [r for r in self.rules if r.source == "flowlogs"]
        for log_event in self._new_log_events(config.FLOW_LOG_GROUP):
            record = parse_flow_record(log_event["message"])
            if not record:
                continue
            for rule in flow_rules:
                if all(record.get(k) == str(v) for k, v in rule.flowlog_match.items()):
                    alert = self._evaluate(rule, {"detail": record, "flow": record}, log_event["timestamp"])
                    if alert:
                        alerts.append(alert)

        for alert in alerts:
            self._deliver(alert)
        self._save_state()
        return alerts

    def _evaluate(self, rule, event, ts_ms):
        if rule.type == "event":
            return self._make_alert(rule, event, ts_ms, count=1)

        if rule.type in ("threshold", "flowlog_threshold"):
            group_value = get_path(event, rule.threshold["group_by"]) if rule.type == "threshold" \
                else event["flow"].get(rule.threshold["group_by"])
            key = f"{rule.id}|{group_value}"
            window_ms = rule.threshold["window_minutes"] * 60_000
            times = [t for t in self.state["windows"].get(key, []) if t > ts_ms - window_ms]
            times.append(ts_ms)
            self.state["windows"][key] = times
            if len(times) >= rule.threshold["count"] and self.state["cooldowns"].get(key, 0) < ts_ms:
                # Fire once per window, not once per event above the threshold.
                self.state["cooldowns"][key] = ts_ms + window_ms
                return self._make_alert(rule, event, ts_ms, count=len(times), group=group_value)
            return None

        if rule.type == "new_value":
            value = get_path(event, rule.new_value["field"])
            known = self.state["baselines"].setdefault(rule.id, [])
            if value is None or value in known:
                return None
            known.append(value)
            if len(known) == 1:
                return None          # the very first value is learned as normal
            return self._make_alert(rule, event, ts_ms, count=1, group=value)
        return None

    # ------------------------------------------------------------ alerts --
    def _make_alert(self, rule, event, ts_ms, count, group=None):
        d = event.get("detail", {})
        if "flow" in event:
            actor, ip = "n/a (network traffic)", d.get("srcaddr")
            summary = f"{count} connection attempts to port {d.get('dstport')} from {d.get('srcaddr')}"
            resource = d.get("dstaddr")
        else:
            ident = d.get("userIdentity", {})
            actor = ident.get("arn") or ident.get("type", "unknown")
            ip = d.get("sourceIPAddress")
            resource = _resource_of(d)
            summary = f"{d.get('eventName')} by {actor} from {ip}"
            if count > 1:
                summary = f"{count}x {summary} within {rule.threshold.get('window_minutes')} min"
        return {
            "alert_id": str(uuid.uuid4()),
            "rule_id": rule.id, "rule_name": rule.name, "severity": rule.severity,
            "mitre_technique": rule.mitre.get("technique_id"), "mitre_tactic": rule.mitre.get("tactic"),
            "event_time": d.get("eventTime") or iso(ts_ms),
            "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": summary, "actor": actor, "source_ip": ip, "resource": resource,
            "group": group, "count": count, "event_id": d.get("eventID"),
            "mode": self.aws.mode, "response": rule.response,
        }

    def _deliver(self, alert):
        with open(ALERTS_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
        if not self.notify:
            return
        try:  # 1) the alerts log group (also where native AWS alerts land)
            stream = "detection-engine"
            try:
                self.logs.create_log_stream(logGroupName=config.ALERTS_LOG_GROUP, logStreamName=stream)
            except self.logs.exceptions.ResourceAlreadyExistsException:
                pass
            self.logs.put_log_events(logGroupName=config.ALERTS_LOG_GROUP, logStreamName=stream,
                                     logEvents=[{"timestamp": int(time.time() * 1000),
                                                 "message": json.dumps(alert)}])
        except Exception as e:
            print(f"  (could not write to {config.ALERTS_LOG_GROUP}: {e})")
        try:  # 2) SNS topic -> email
            sns = self.aws.client("sns")
            topics = [t["TopicArn"] for t in sns.list_topics()["Topics"]
                      if t["TopicArn"].endswith(":" + config.ALERTS_TOPIC_NAME)]
            if topics:
                sns.publish(TopicArn=topics[0],
                            Subject=f"[{alert['severity'].upper()}] {alert['rule_name']}"[:100],
                            Message=json.dumps(alert, indent=2))
        except Exception as e:
            print(f"  (could not publish to SNS: {e})")


def _resource_of(detail: dict) -> str:
    rp = detail.get("requestParameters") or {}
    for key in ("groupId", "bucketName", "userName", "name", "policyArn", "secretId", "keyId"):
        if rp.get(key):
            return str(rp[key])
    return detail.get("eventSource", "")


def read_alerts() -> list:
    if not ALERTS_FILE.exists():
        return []
    return [json.loads(line) for line in ALERTS_FILE.read_text().splitlines() if line.strip()]
