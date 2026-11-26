from common import config
from scanner.checks.iam import (ADMIN_POLICY_ARN, AdminUsers, ConsoleUserWithoutMfa, RootAccessKeys,
                                RootMfa, TooManyAdmins)
from scanner.checks.kms_secrets import KmsKeyRotation, PlaintextSecretParameter, SecretsManagerRotation
from scanner.checks.services import CloudTrailEnabled, GuardDutyEnabled, VpcFlowLogsEnabled
from tests.conftest import statuses


def test_admin_users_direct_and_group(aws, monkeypatch):
    iam = aws.client("iam")
    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=ADMIN_POLICY_ARN)
    iam.create_user(UserName="bob")
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=ADMIN_POLICY_ARN)
    iam.add_user_to_group(GroupName="admins", UserName="bob")
    iam.create_user(UserName="carol")
    assert statuses(AdminUsers(aws).run()) == {"alice": "FAIL", "bob": "FAIL", "carol": "PASS"}

    monkeypatch.setattr(config, "ADMIN_THRESHOLD", 1)
    assert TooManyAdmins(aws).run()[0].status == "FAIL"
    monkeypatch.setattr(config, "ADMIN_THRESHOLD", 2)
    assert TooManyAdmins(aws).run()[0].status == "PASS"


def test_console_user_without_mfa(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="dev")
    iam.create_login_profile(UserName="dev", Password="Very-Long-Pass-123!")
    iam.create_user(UserName="api-only")          # no console password: not evaluated
    assert statuses(ConsoleUserWithoutMfa(aws).run()) == {"dev": "FAIL"}


def test_root_checks_run(aws):
    assert RootMfa(aws).run()[0].status in ("PASS", "FAIL")
    assert RootAccessKeys(aws).run()[0].status in ("PASS", "FAIL")


def test_kms_rotation(aws):
    kms = aws.client("kms")
    on = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=on)
    off = kms.create_key()["KeyMetadata"]["KeyId"]
    assert statuses(KmsKeyRotation(aws).run()) == {on: "PASS", off: "FAIL"}


def test_secrets(aws):
    aws.client("secretsmanager").create_secret(Name="db-creds", SecretString="x")
    assert statuses(SecretsManagerRotation(aws).run()) == {"db-creds": "FAIL"}
    ssm = aws.client("ssm")
    ssm.put_parameter(Name="/app/db-password", Value="x", Type="String")
    ssm.put_parameter(Name="/app/api-token", Value="x", Type="SecureString")
    ssm.put_parameter(Name="/app/log-level", Value="info", Type="String")   # not secret-like
    assert statuses(PlaintextSecretParameter(aws).run()) == {
        "/app/db-password": "FAIL", "/app/api-token": "PASS"}


def test_cloudtrail_and_guardduty(aws):
    assert CloudTrailEnabled(aws).run()[0].status == "FAIL"
    aws.client("s3").create_bucket(Bucket="trail-bucket")
    ct = aws.client("cloudtrail")
    ct.create_trail(Name="main-trail", S3BucketName="trail-bucket", IsMultiRegionTrail=True)
    ct.start_logging(Name="main-trail")
    assert CloudTrailEnabled(aws).run()[0].status == "PASS"

    assert GuardDutyEnabled(aws).run()[0].status == "FAIL"
    aws.client("guardduty").create_detector(Enable=True)
    assert GuardDutyEnabled(aws).run()[0].status == "PASS"


def test_flow_logs(aws):
    ec2 = aws.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
    out = {f.resource_id.split()[0]: f.status for f in VpcFlowLogsEnabled(aws).run()}
    assert out[vpc] == "FAIL"
