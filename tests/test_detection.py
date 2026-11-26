"""Detection tests: the pattern matcher, and the engine end to end on mock CloudWatch Logs."""
import json
import time

import pytest

from common import config
from detection import engine as engine_mod
from detection.matcher import matches, to_eventbridge
from detection.rules import load_rules

RULES = {r.folder: r for r in load_rules()}


def ct(event_name, source="iam", **extra):
    record = {"eventSource": f"{source}.amazonaws.com", "eventName": event_name,
              "eventType": "AwsApiCall", "readOnly": False, "sourceIPAddress": "198.51.100.23",
              "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/x"}}
    record.update(extra)
    return to_eventbridge(record)


def test_all_rules_load_with_mitre_ids():
    assert len(RULES) == 11
    assert all(r.mitre["technique_id"].startswith("T") for r in RULES.values())


def test_operators():
    assert matches({"a": [{"prefix": "Del"}]}, {"a": "DeleteUser"})
    assert not matches({"a": [{"prefix": "Del"}]}, {"a": "CreateUser"})
    assert matches({"a": [{"anything-but": "x"}]}, {"a": "y"})
    assert matches({"a": [{"exists": False}]}, {"b": 1})
    assert matches({"a": ["v"]}, {"a": ["q", "v"]})                       # arrays: any element
    assert matches({"$or": [{"a": [1]}, {"b": [2]}]}, {"b": 2})


def test_sg_rule_matches_world_ipv4_but_not_private():
    rule = RULES["sg_open_to_internet"]
    def sg(cidr):
        return ct("AuthorizeSecurityGroupIngress", "ec2", requestParameters={"groupId": "sg-1",
                  "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                                               "ipRanges": {"items": [{"cidrIp": cidr}]}}]}})
    assert matches(rule.pattern, sg("0.0.0.0/0"))
    assert not matches(rule.pattern, sg("10.0.0.0/16"))


def test_admin_attach_only_for_admin_policy():
    rule = RULES["iam_admin_policy_attached"]
    assert matches(rule.pattern, ct("AttachUserPolicy", requestParameters={
        "userName": "u", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    assert not matches(rule.pattern, ct("AttachUserPolicy", requestParameters={
        "userName": "u", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))


def test_console_login_without_mfa():
    rule = RULES["console_login_without_mfa"]
    login = {"eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
             "eventType": "AwsConsoleSignIn", "userIdentity": {"type": "IAMUser"},
             "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}}
    assert matches(rule.pattern, to_eventbridge(login))
    login["additionalEventData"]["MFAUsed"] = "Yes"
    assert not matches(rule.pattern, to_eventbridge(login))


@pytest.fixture
def engine(aws, tmp_path, monkeypatch):
    monkeypatch.setattr(engine_mod, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(engine_mod, "ALERTS_FILE", tmp_path / "alerts.jsonl")
    logs = aws.client("logs")
    for group in (config.CLOUDTRAIL_LOG_GROUP, config.FLOW_LOG_GROUP, config.ALERTS_LOG_GROUP):
        logs.create_log_group(logGroupName=group)
    logs.create_log_stream(logGroupName=config.CLOUDTRAIL_LOG_GROUP, logStreamName="s")
    logs.create_log_stream(logGroupName=config.FLOW_LOG_GROUP, logStreamName="eni-1-all")

    def write(records):
        ts = int(time.time() * 1000)
        logs.put_log_events(logGroupName=config.CLOUDTRAIL_LOG_GROUP, logStreamName="s",
                            logEvents=[{"timestamp": ts, "message": json.dumps(r["detail"])} for r in records])

    def write_flows(lines):
        ts = int(time.time() * 1000)
        logs.put_log_events(logGroupName=config.FLOW_LOG_GROUP, logStreamName="eni-1-all",
                            logEvents=[{"timestamp": ts, "message": m} for m in lines])

    eng = engine_mod.DetectionEngine(aws)
    eng.write, eng.write_flows = write, write_flows
    return eng


def test_engine_event_rule_fires_once(engine):
    engine.write([ct("CreateUser", requestParameters={"userName": "evil"})])
    alerts = engine.run_once()
    assert [a["rule_id"] for a in alerts] == ["DET-004"]
    assert engine.run_once() == []          # already processed: no duplicate alert


def test_engine_threshold_rule(engine):
    login = {"eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
             "eventType": "AwsConsoleSignIn", "sourceIPAddress": "203.0.113.7",
             "userIdentity": {"type": "IAMUser"}, "responseElements": {"ConsoleLogin": "Failure"}}
    engine.write([to_eventbridge(login)] * 2)
    assert engine.run_once() == []          # 2 failures: below threshold of 3
    engine.write([to_eventbridge(login)] * 2)
    assert [a["rule_id"] for a in engine.run_once()] == ["DET-007"]


def test_engine_new_value_rule(engine):
    def read(ip):
        return ct("GetParameter", "ssm", readOnly=True, sourceIPAddress=ip, requestParameters={"name": "/p"})
    engine.write([read("10.20.1.10")])
    assert engine.run_once() == []          # first IP is learned as normal
    engine.write([read("198.51.100.23")])
    assert [a["rule_id"] for a in engine.run_once()] == ["DET-009"]


def test_engine_flowlog_bruteforce(engine):
    lines = [f"2 123 eni-1 203.0.113.9 10.20.1.10 {40000 + i} 22 6 1 60 0 1 REJECT OK" for i in range(25)]
    engine.write_flows(lines)
    alerts = engine.run_once()
    assert [a["rule_id"] for a in alerts] == ["DET-011"]
    assert alerts[0]["source_ip"] == "203.0.113.9"
