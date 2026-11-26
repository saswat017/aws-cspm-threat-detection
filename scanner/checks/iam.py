"""IAM checks: root account, administrators, MFA and old access keys."""
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from common import config
from scanner.checks.base import Check

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def all_users(iam):
    for page in iam.get_paginator("list_users").paginate():
        yield from page["Users"]


def is_admin(iam, user_name):
    """True if AdministratorAccess is attached to the user directly or via a group."""
    attached = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
    if any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in attached):
        return "attached directly"
    for group in iam.list_groups_for_user(UserName=user_name)["Groups"]:
        g_attached = iam.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]
        if any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in g_attached):
            return f"via group {group['GroupName']}"
    return None


class RootMfa(Check):
    id = "IAM-001"
    title = "Root account does not have MFA enabled"
    severity = "critical"
    service = "iam"
    cis_ref = "CIS 1.5"
    description = "The root user can do anything, including closing the account. A password alone is not enough."
    recommendation = "Enable MFA (authenticator app, passkey or hardware key) on the root user."

    def evaluate(self):
        summary = self.aws.client("iam").get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled") == 1:
            yield self.passed("root", "AWS::IAM::Root", "Root MFA enabled")
        else:
            yield self.failed("root", "AWS::IAM::Root", "Root MFA not enabled")


class RootAccessKeys(Check):
    id = "IAM-002"
    title = "Root account has access keys"
    severity = "critical"
    service = "iam"
    cis_ref = "CIS 1.4"
    description = "Root access keys give unrestricted programmatic access and cannot be limited by any policy."
    recommendation = "Delete the root access keys; use IAM users or roles for programmatic access."

    def evaluate(self):
        summary = self.aws.client("iam").get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0):
            yield self.failed("root", "AWS::IAM::Root", "Root access keys present")
        else:
            yield self.passed("root", "AWS::IAM::Root", "No root access keys")


class AdminUsers(Check):
    id = "IAM-003"
    title = "IAM user has AdministratorAccess"
    severity = "high"
    service = "iam"
    cis_ref = "CIS 1.16 (related)"
    description = ("Users with full admin rights are high-value targets: one leaked password or "
                   "key compromises the whole account.")
    recommendation = ("Grant least-privilege policies instead; keep admin access to as few "
                      "people as possible, ideally through roles assumed with MFA.")

    def evaluate(self):
        iam = self.aws.client("iam")
        for user in all_users(iam):
            how = is_admin(iam, user["UserName"])
            if how:
                yield self.failed(user["UserName"], "AWS::IAM::User", f"AdministratorAccess {how}")
            else:
                yield self.passed(user["UserName"], "AWS::IAM::User", "Not an administrator")


class TooManyAdmins(Check):
    id = "IAM-004"
    title = "More IAM administrators than allowed"
    severity = "medium"
    service = "iam"
    cis_ref = "n/a (custom policy)"
    description = f"Every extra administrator increases risk. Policy: at most ADMIN_THRESHOLD ({config.ADMIN_THRESHOLD})."
    recommendation = "Review the admin list and remove admin rights that are not needed."

    def evaluate(self):
        iam = self.aws.client("iam")
        admins = [u["UserName"] for u in all_users(iam) if is_admin(iam, u["UserName"])]
        evidence = f"{len(admins)} admins (limit {config.ADMIN_THRESHOLD}): {', '.join(admins) or 'none'}"
        if len(admins) > config.ADMIN_THRESHOLD:
            yield self.failed("account", "AWS::IAM::Account", evidence)
        else:
            yield self.passed("account", "AWS::IAM::Account", evidence)


class ConsoleUserWithoutMfa(Check):
    id = "IAM-005"
    title = "IAM user with console password has no MFA"
    severity = "high"
    service = "iam"
    cis_ref = "CIS 1.10"
    description = "A console password without MFA can be phished or guessed."
    recommendation = "Require MFA for every user that has a console password."

    def evaluate(self):
        iam = self.aws.client("iam")
        for user in all_users(iam):
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    continue  # no console password: MFA rule does not apply
                raise
            if iam.list_mfa_devices(UserName=name)["MFADevices"]:
                yield self.passed(name, "AWS::IAM::User", "Console user with MFA")
            else:
                yield self.failed(name, "AWS::IAM::User", "Console password, no MFA device")


class OldAccessKeys(Check):
    id = "IAM-006"
    title = "IAM access key is older than the allowed age"
    severity = "medium"
    service = "iam"
    cis_ref = "CIS 1.14"
    description = f"Long-lived keys are more likely to have leaked. Policy: rotate every {config.ACCESS_KEY_MAX_AGE_DAYS} days."
    recommendation = "Create a new key, switch to it, then deactivate and delete the old key."

    def evaluate(self):
        iam = self.aws.client("iam")
        now = datetime.now(timezone.utc)
        for user in all_users(iam):
            for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                age = (now - key["CreateDate"]).days
                rid = f"{user['UserName']}/{key['AccessKeyId']}"
                if age > config.ACCESS_KEY_MAX_AGE_DAYS:
                    yield self.failed(rid, "AWS::IAM::AccessKey", f"{age} days old")
                else:
                    yield self.passed(rid, "AWS::IAM::AccessKey", f"{age} days old")


CHECKS = [RootMfa, RootAccessKeys, AdminUsers, TooManyAdmins, ConsoleUserWithoutMfa, OldAccessKeys]
