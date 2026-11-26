"""Attack scenarios. Each one performs a careless-admin / attacker action and has
a matching revert() that undoes it by hand (this is manual cleanup by the operator,
not auto-remediation: nothing reverts itself when an alert fires).

In demo mode the scenario also writes the CloudTrail records the action would
have produced (see cloudtrail_emitter.py). In live mode real CloudTrail does that.

Scenarios marked demo_only cannot be done safely or meaningfully on real AWS
from this script (for example root logins or real SSH brute force).
"""
import json

from botocore.exceptions import ClientError

from common import config
from simulation.cloudtrail_emitter import ATTACKER_IP, BRUTEFORCE_IP, OPERATOR_IP, CloudTrailEmitter

ROGUE_USER = "svc-backup-sync"          # looks harmless on purpose
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
STOLEN_IDENTITY = "cspm-admin"         # the scenario assumes this user's key leaked


# ----------------------------------------------------------- lab discovery --
class Lab:
    """Finds the lab resources by name, so it works in both demo and live mode."""

    def __init__(self, aws):
        self.aws = aws
        self.ec2, self.s3, self.iam, self.ssm = (aws.client(s) for s in ("ec2", "s3", "iam", "ssm"))

    def security_group_id(self):
        groups = self.ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [f"{config.PROJECT}-app-sg"]}])["SecurityGroups"]
        if not groups:
            raise SystemExit("Lab security group not found. Is the lab deployed? (python -m lab up)")
        return groups[0]["GroupId"]

    def bucket(self):
        names = [b["Name"] for b in self.s3.list_buckets()["Buckets"]
                 if b["Name"].startswith(f"{config.PROJECT}-data-")]
        if not names:
            raise SystemExit("Lab data bucket not found. Is the lab deployed?")
        return names[0]

    def instance(self):
        res = self.ec2.describe_instances(Filters=[
            {"Name": "tag:Name", "Values": [f"{config.PROJECT}-app-server"]},
            {"Name": "instance-state-name", "Values": ["running", "pending", "stopped"]}])["Reservations"]
        if not res:
            raise SystemExit("Lab instance not found. Is the lab deployed?")
        inst = res[0]["Instances"][0]
        eni = inst["NetworkInterfaces"][0]["NetworkInterfaceId"] if inst.get("NetworkInterfaces") else "eni-0simulated"
        return inst["InstanceId"], inst.get("PrivateIpAddress", "10.20.1.10"), eni

    def parameter(self):
        return f"/{config.PROJECT}/db-password"


# ------------------------------------------------------------------ base --
class Scenario:
    name = ""
    title = ""
    expected_rules = []        # detection rule IDs that should fire
    demo_only = False

    def __init__(self, aws):
        self.aws = aws
        self.lab = Lab(aws)
        self.operator_ip = OPERATOR_IP
        self.ct = CloudTrailEmitter(aws) if aws.mode == "demo" else None
        self.actor = self.ct.iam_user(STOLEN_IDENTITY) if self.ct else None
        self.source_ip = ATTACKER_IP   # set to OPERATOR_IP when reverting

    def emit(self, service, event, request=None, response=None, **kw):
        """Write the matching CloudTrail record (demo mode only)."""
        if self.ct:
            kw.setdefault("source_ip", self.source_ip)
            self.ct.api_call(service, event, kw.pop("identity", self.actor), request, response, **kw)

    def run(self) -> dict:
        raise NotImplementedError

    def revert(self, saved: dict) -> dict:
        raise NotImplementedError


# ------------------------------------------------------------- scenarios --
class OpenSsh(Scenario):
    name = "open_ssh"
    title = "Open SSH (22) on the app security group to 0.0.0.0/0"
    expected_rules = ["DET-001"]

    def _perm(self):
        return [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "temp debug"}]}]

    def _ct_perm(self):
        return {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "groups": {},
                           "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0", "description": "temp debug"}]},
                           "ipv6Ranges": {}, "prefixListIds": {}}]}

    def run(self):
        sg = self.lab.security_group_id()
        self.lab.ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=self._perm())
        self.emit("ec2", "AuthorizeSecurityGroupIngress",
                  {"groupId": sg, "ipPermissions": self._ct_perm()}, {"_return": True})
        return {"security_group": sg}

    def revert(self, saved):
        sg = saved.get("security_group") or self.lab.security_group_id()
        try:
            self.lab.ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=self._perm())
        except ClientError as e:
            if "NotFound" not in e.response["Error"]["Code"]:
                raise
        self.emit("ec2", "RevokeSecurityGroupIngress", {"groupId": sg, "ipPermissions": self._ct_perm()})
        return {"security_group": sg}


class PublicS3(Scenario):
    name = "public_s3"
    title = "Remove Block Public Access and add a public-read bucket policy"
    expected_rules = ["DET-002"]

    def run(self):
        bucket = self.lab.bucket()
        s3 = self.lab.s3
        try:
            original_policy = s3.get_bucket_policy(Bucket=bucket)["Policy"]
        except ClientError:
            original_policy = None
        s3.delete_public_access_block(Bucket=bucket)
        self.emit("s3", "DeleteBucketPublicAccessBlock", {"bucketName": bucket, "publicAccessBlock": ""})
        public = {"Version": "2012-10-17", "Statement": [{
            "Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(public))
        self.emit("s3", "PutBucketPolicy", {"bucketName": bucket, "bucketPolicy": public})
        return {"bucket": bucket, "original_policy": original_policy}

    def revert(self, saved):
        bucket = saved.get("bucket") or self.lab.bucket()
        s3 = self.lab.s3
        if saved.get("original_policy"):
            s3.put_bucket_policy(Bucket=bucket, Policy=saved["original_policy"])
        else:
            s3.delete_bucket_policy(Bucket=bucket)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        self.emit("s3", "PutBucketPolicy", {"bucketName": bucket})
        self.emit("s3", "PutBucketPublicAccessBlock", {"bucketName": bucket})
        return {"bucket": bucket}


class RogueAdmin(Scenario):
    name = "rogue_admin"
    title = f"Create IAM user '{ROGUE_USER}' and attach AdministratorAccess"
    expected_rules = ["DET-004", "DET-003"]

    def run(self):
        iam = self.lab.iam
        iam.create_user(UserName=ROGUE_USER)
        self.emit("iam", "CreateUser", {"userName": ROGUE_USER},
                  {"user": {"userName": ROGUE_USER, "arn": f"arn:aws:iam::{self.aws.account_id}:user/{ROGUE_USER}"}})
        iam.attach_user_policy(UserName=ROGUE_USER, PolicyArn=ADMIN_ARN)
        self.emit("iam", "AttachUserPolicy", {"userName": ROGUE_USER, "policyArn": ADMIN_ARN})
        return {"user": ROGUE_USER}

    def revert(self, saved):
        iam = self.lab.iam
        try:
            for key in iam.list_access_keys(UserName=ROGUE_USER)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=ROGUE_USER, AccessKeyId=key["AccessKeyId"])
            iam.detach_user_policy(UserName=ROGUE_USER, PolicyArn=ADMIN_ARN)
            iam.delete_user(UserName=ROGUE_USER)
        except iam.exceptions.NoSuchEntityException:
            pass
        self.emit("iam", "DeleteUser", {"userName": ROGUE_USER})
        return {"user": ROGUE_USER}


class RogueAccessKey(Scenario):
    name = "rogue_access_key"
    title = f"Create an access key for '{ROGUE_USER}' (persistence)"
    expected_rules = ["DET-004"]

    def run(self):
        iam = self.lab.iam
        try:
            iam.get_user(UserName=ROGUE_USER)
        except iam.exceptions.NoSuchEntityException:
            raise SystemExit(f"Run the rogue_admin scenario first (user {ROGUE_USER} does not exist).")
        key = iam.create_access_key(UserName=ROGUE_USER)["AccessKey"]["AccessKeyId"]
        self.emit("iam", "CreateAccessKey", {"userName": ROGUE_USER},
                  {"accessKey": {"accessKeyId": key, "status": "Active", "userName": ROGUE_USER}})
        return {"user": ROGUE_USER, "access_key_id": key}

    def revert(self, saved):
        iam = self.lab.iam
        if saved.get("access_key_id"):
            try:
                iam.delete_access_key(UserName=ROGUE_USER, AccessKeyId=saved["access_key_id"])
            except iam.exceptions.NoSuchEntityException:
                pass
            self.emit("iam", "DeleteAccessKey", {"userName": ROGUE_USER, "accessKeyId": saved["access_key_id"]})
        return {"user": ROGUE_USER}


class SecretHarvest(Scenario):
    name = "secret_harvest"
    title = "Read the lab secret 12 times from a new IP address (credential harvesting)"
    expected_rules = ["DET-009", "DET-008"]

    def run(self):
        name, ssm = self.lab.parameter(), self.lab.ssm
        _, private_ip, _ = self.lab.instance()
        # Normal behaviour first: the app server reads its secret once from inside the VPC.
        ssm.get_parameter(Name=name, WithDecryption=True)
        self.emit("ssm", "GetParameter", {"name": name, "withDecryption": True}, read_only=True,
                  identity=self.ct.role_session(f"{config.PROJECT}-app-role") if self.ct else None,
                  source_ip=private_ip)
        # Attacker with the stolen key reads it repeatedly from outside.
        for _ in range(12):
            ssm.get_parameter(Name=name, WithDecryption=True)
            self.emit("ssm", "GetParameter", {"name": name, "withDecryption": True},
                      read_only=True, source_ip=ATTACKER_IP)
        return {"parameter": name, "reads": 12}

    def revert(self, saved):
        return {"note": "Nothing to undo (reads change nothing). In real life: rotate the secret."}


class BulkDelete(Scenario):
    name = "bulk_delete"
    title = "Create and then quickly delete 12 SSM parameters (sabotage pattern)"
    expected_rules = ["DET-010"]

    def _names(self):
        return [f"/{config.PROJECT}/sim-temp/item-{i:02d}" for i in range(12)]

    def run(self):
        ssm = self.lab.ssm
        for n in self._names():
            ssm.put_parameter(Name=n, Value="temp", Type="String", Overwrite=True)
        for n in self._names():
            ssm.delete_parameter(Name=n)
            self.emit("ssm", "DeleteParameter", {"name": n})
        return {"deleted": len(self._names())}

    def revert(self, saved):
        ssm = self.lab.ssm
        for n in self._names():  # clean up leftovers if a run was interrupted
            try:
                ssm.delete_parameter(Name=n)
            except ssm.exceptions.ParameterNotFound:
                pass
        return {"note": "Temporary parameters removed"}


class ConsoleBruteForce(Scenario):
    name = "console_bruteforce"
    title = "4 failed console logins, then a successful login without MFA"
    expected_rules = ["DET-007", "DET-006"]
    demo_only = True

    def run(self):
        user = self.ct.iam_user(STOLEN_IDENTITY)
        for _ in range(4):
            self.ct.console_login(user, success=False, mfa_used=False)
        self.ct.console_login(user, success=True, mfa_used=False)
        return {"user": STOLEN_IDENTITY, "source_ip": BRUTEFORCE_IP}

    def revert(self, saved):
        return {"note": "Nothing to undo (log events only). In real life: reset the password, enforce MFA."}


class RootLogin(Scenario):
    name = "root_login"
    title = "Root user signs in to the console"
    expected_rules = ["DET-005"]
    demo_only = True

    def run(self):
        self.ct.console_login(self.ct.root(), success=True, mfa_used=True, source_ip=ATTACKER_IP)
        return {"source_ip": ATTACKER_IP}

    def revert(self, saved):
        return {"note": "Nothing to undo (log event only)."}


class SshBruteForce(Scenario):
    name = "ssh_bruteforce"
    title = "30 SSH connection attempts to the app server from one IP (VPC Flow Logs)"
    expected_rules = ["DET-011"]
    demo_only = True

    def run(self):
        _, private_ip, eni = self.lab.instance()
        self.ct.flow_records(eni, BRUTEFORCE_IP, private_ip, 22, count=30, action="REJECT")
        return {"target": private_ip, "attempts": 30}

    def revert(self, saved):
        return {"note": "Nothing to undo (log records only)."}


SCENARIOS = {s.name: s for s in [OpenSsh, PublicS3, RogueAdmin, RogueAccessKey, SecretHarvest,
                                  BulkDelete, ConsoleBruteForce, RootLogin, SshBruteForce]}
