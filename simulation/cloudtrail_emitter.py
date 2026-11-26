"""Writes CloudTrail-format records into CloudWatch Logs (DEMO MODE ONLY).

Why this exists: on real AWS, CloudTrail records every API call by itself and
delivers it to the /cspm/cloudtrail log group. The local emulator does not do
that, so in demo mode the simulator writes the same JSON record that CloudTrail
would have written for each action it performs, into the same log group.

Every emitted record is marked as simulated (userAgent contains
"cspm-simulation" and it carries "cspmSimulated": true), so it can never be
mistaken for real CloudTrail evidence.
"""
import json
import time
import uuid
from datetime import datetime, timezone

from common import config

ATTACKER_IP = "198.51.100.23"      # documentation-only IP range (RFC 5737)
BRUTEFORCE_IP = "203.0.113.77"     # documentation-only IP range (RFC 5737)
OPERATOR_IP = "192.0.2.10"         # the defender doing manual cleanup (RFC 5737)


class CloudTrailEmitter:
    def __init__(self, aws):
        if aws.mode != "demo":
            raise RuntimeError("Simulated CloudTrail records may only be written in demo mode.")
        self.aws = aws
        self.logs = aws.client("logs")
        self.account = aws.account_id
        self.stream = f"{self.account}_CloudTrail_{aws.region}"
        self._ensure_stream(config.CLOUDTRAIL_LOG_GROUP, self.stream)

    def _ensure_stream(self, group, stream):
        try:
            self.logs.create_log_stream(logGroupName=group, logStreamName=stream)
        except self.logs.exceptions.ResourceAlreadyExistsException:
            pass

    # --- identities -----------------------------------------------------------
    def iam_user(self, name, access_key="AKIASIMULATED0000001"):
        return {"type": "IAMUser", "principalId": "AIDASIMULATED" + name.upper()[:8],
                "arn": f"arn:aws:iam::{self.account}:user/{name}", "accountId": self.account,
                "userName": name, "accessKeyId": access_key}

    def role_session(self, role, session="i-0simulated"):
        return {"type": "AssumedRole", "principalId": f"AROASIMULATED:{session}",
                "arn": f"arn:aws:sts::{self.account}:assumed-role/{role}/{session}",
                "accountId": self.account,
                "sessionContext": {"sessionIssuer": {"type": "Role", "userName": role,
                                   "arn": f"arn:aws:iam::{self.account}:role/{role}"}}}

    def root(self):
        return {"type": "Root", "principalId": self.account,
                "arn": f"arn:aws:iam::{self.account}:root", "accountId": self.account}

    # --- records --------------------------------------------------------------
    def api_call(self, service, event_name, identity, request=None, response=None,
                 source_ip=ATTACKER_IP, read_only=False, error_code=None):
        record = self._base(identity, source_ip)
        record.update({
            "eventSource": f"{service}.amazonaws.com", "eventName": event_name,
            "requestParameters": request, "responseElements": response,
            "readOnly": read_only, "eventType": "AwsApiCall", "managementEvent": True,
        })
        if error_code:
            record["errorCode"] = error_code
        return self._put([record])[0]

    def console_login(self, identity, success, mfa_used, source_ip=BRUTEFORCE_IP):
        record = self._base(identity, source_ip)
        record.update({
            "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
            "eventType": "AwsConsoleSignIn", "readOnly": False, "managementEvent": True,
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
            "additionalEventData": {"LoginTo": "https://console.aws.amazon.com/console/home",
                                    "MobileVersion": "No", "MFAUsed": "Yes" if mfa_used else "No"},
        })
        if not success:
            record["errorMessage"] = "Failed authentication"
        return self._put([record])[0]

    def flow_records(self, eni, src, dst, dst_port, count, action="REJECT"):
        """Write VPC Flow Log lines (default version-2 format) for `count` attempts."""
        self._ensure_stream(config.FLOW_LOG_GROUP, f"{eni}-all")
        now = int(time.time())
        lines = [f"2 {self.account} {eni} {src} {dst} {40000 + i} {dst_port} 6 1 60 {now} {now + 1} "
                 f"{action} OK" for i in range(count)]
        ts = int(time.time() * 1000)
        self.logs.put_log_events(logGroupName=config.FLOW_LOG_GROUP, logStreamName=f"{eni}-all",
                                 logEvents=[{"timestamp": ts, "message": m} for m in lines])
        return lines

    def _base(self, identity, source_ip):
        return {
            "eventVersion": "1.09", "userIdentity": identity,
            "eventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "awsRegion": self.aws.region, "sourceIPAddress": source_ip,
            "userAgent": "aws-cli/2.0 (cspm-simulation)",
            "requestID": str(uuid.uuid4()), "eventID": str(uuid.uuid4()),
            "recipientAccountId": self.account, "eventCategory": "Management",
            "cspmSimulated": True,
        }

    def _put(self, records):
        ts = int(time.time() * 1000)
        self.logs.put_log_events(
            logGroupName=config.CLOUDTRAIL_LOG_GROUP, logStreamName=self.stream,
            logEvents=[{"timestamp": ts, "message": json.dumps(r)} for r in records])
        return records
