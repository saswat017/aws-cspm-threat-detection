"""Checks that the account's security logging and detection services are switched on."""
from botocore.exceptions import ClientError

from scanner.checks.base import Check


class CloudTrailEnabled(Check):
    id = "SVC-001"
    title = "No multi-region CloudTrail trail is logging"
    severity = "critical"
    service = "cloudtrail"
    cis_ref = "CIS 3.1"
    description = ("CloudTrail is the audit log of every API call. Without it there is no "
                   "evidence of who changed what, and threat detection is blind.")
    recommendation = "Create a multi-region trail with management events and keep logging on."

    def evaluate(self):
        ct = self.aws.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        good = []
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if trail.get("IsMultiRegionTrail") and status.get("IsLogging"):
                good.append(trail["Name"])
        if good:
            yield self.passed("account", "AWS::CloudTrail::Trail", f"Logging: {', '.join(good)}")
        else:
            yield self.failed("account", "AWS::CloudTrail::Trail",
                              f"{len(trails)} trail(s), none multi-region and logging")


class GuardDutyEnabled(Check):
    id = "SVC-002"
    title = "GuardDuty is not enabled"
    severity = "high"
    service = "guardduty"
    cis_ref = "n/a (AWS FSBP GuardDuty.1)"
    description = ("GuardDuty is AWS's managed threat detection (malicious IPs, crypto mining, "
                   "credential misuse). It complements this project's own rules.")
    recommendation = "Enable GuardDuty in every region you use (30-day free trial)."

    def evaluate(self):
        gd = self.aws.client("guardduty")
        detectors = gd.list_detectors()["DetectorIds"]
        enabled = [d for d in detectors if gd.get_detector(DetectorId=d).get("Status") == "ENABLED"]
        if enabled:
            yield self.passed(self.region, "AWS::GuardDuty::Detector", f"Detector {enabled[0]} enabled")
        else:
            yield self.failed(self.region, "AWS::GuardDuty::Detector", "No enabled detector")


class SecurityHubEnabled(Check):
    id = "SVC-003"
    title = "Security Hub is not enabled"
    severity = "medium"
    service = "securityhub"
    cis_ref = "CIS 4.16"
    description = "Security Hub gathers findings and runs the CIS benchmark continuously inside AWS."
    recommendation = "Enable Security Hub and the CIS AWS Foundations standard (needs AWS Config)."

    def evaluate(self):
        try:
            hub = self.aws.client("securityhub").describe_hub()
            yield self.passed(self.region, "AWS::SecurityHub::Hub", f"Enabled: {hub.get('HubArn')}")
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidAccessException", "ResourceNotFoundException"):
                yield self.failed(self.region, "AWS::SecurityHub::Hub", "Not enabled")
            else:
                raise


class VpcFlowLogsEnabled(Check):
    id = "SVC-004"
    title = "VPC has no flow logs"
    severity = "medium"
    service = "ec2"
    cis_ref = "CIS 3.7"
    description = "Flow logs record network connections; without them network attacks leave no trace."
    recommendation = "Enable VPC Flow Logs (at least REJECT traffic) to CloudWatch Logs or S3."

    def evaluate(self):
        ec2 = self.aws.client("ec2")
        logged = {f["ResourceId"] for f in ec2.describe_flow_logs()["FlowLogs"]}
        for vpc in ec2.describe_vpcs()["Vpcs"]:
            vid = vpc["VpcId"] + (" (default)" if vpc.get("IsDefault") else "")
            if vpc["VpcId"] in logged:
                yield self.passed(vid, "AWS::EC2::VPC", "Flow logs enabled")
            else:
                yield self.failed(vid, "AWS::EC2::VPC", "No flow logs")


CHECKS = [CloudTrailEnabled, GuardDutyEnabled, SecurityHubEnabled, VpcFlowLogsEnabled]
