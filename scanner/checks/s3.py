"""S3 checks: public access and encryption of buckets."""
import json

from botocore.exceptions import ClientError

from scanner.checks.base import Check

# ACL grantee URIs that mean "everyone" / "any AWS account".
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
BPA_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]


def list_buckets(aws):
    return [b["Name"] for b in aws.client("s3").list_buckets().get("Buckets", [])]


def get_block_public_access(s3, bucket):
    """Return the bucket's Block Public Access settings ({} if none are set)."""
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


class S3BlockPublicAccess(Check):
    id = "S3-001"
    title = "S3 bucket Block Public Access is not fully enabled"
    severity = "high"
    service = "s3"
    cis_ref = "CIS 2.1.4"
    description = ("Block Public Access is the safety net that stops a bucket from being "
                   "made public by a policy or ACL. All four settings should be on.")
    recommendation = ("Turn on all four Block Public Access settings for the bucket "
                      "(and at account level) unless it must serve public content.")

    def evaluate(self):
        s3 = self.aws.client("s3")
        for bucket in list_buckets(self.aws):
            bpa = get_block_public_access(s3, bucket)
            off = [k for k in BPA_KEYS if not bpa.get(k)]
            if off:
                yield self.failed(bucket, "AWS::S3::Bucket", f"Settings off: {', '.join(off)}")
            else:
                yield self.passed(bucket, "AWS::S3::Bucket", "All four settings on")


class S3PublicPolicyOrAcl(Check):
    id = "S3-002"
    title = "S3 bucket is publicly accessible through its policy or ACL"
    severity = "critical"
    service = "s3"
    cis_ref = "CIS 2.1.4 (related); AWS FSBP S3.2/S3.3"
    description = ("A bucket policy that allows Principal '*' without conditions, or an ACL "
                   "grant to AllUsers/AuthenticatedUsers, lets anyone on the internet read "
                   "or write the data.")
    recommendation = ("Remove the public statement or ACL grant, and enable Block Public "
                      "Access so it cannot happen again.")

    def evaluate(self):
        s3 = self.aws.client("s3")
        for bucket in list_buckets(self.aws):
            bpa = get_block_public_access(s3, bucket)
            reasons = []

            # 1) ACL grants to everyone (ignored by AWS if IgnorePublicAcls is on)
            acl = s3.get_bucket_acl(Bucket=bucket)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if uri in PUBLIC_GRANTEES and not bpa.get("IgnorePublicAcls"):
                    reasons.append(f"ACL grants {grant.get('Permission')} to {uri.rsplit('/', 1)[-1]}")

            # 2) Policy statements open to everyone (blocked if RestrictPublicBuckets is on)
            try:
                policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    raise
                policy = {}
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal")
                is_everyone = principal == "*" or (isinstance(principal, dict)
                                                   and principal.get("AWS") in ("*", ["*"]))
                if (stmt.get("Effect") == "Allow" and is_everyone and not stmt.get("Condition")
                        and not bpa.get("RestrictPublicBuckets")):
                    reasons.append(f"Policy allows {stmt.get('Action')} to everyone")

            if reasons:
                yield self.failed(bucket, "AWS::S3::Bucket", "; ".join(reasons))
            else:
                yield self.passed(bucket, "AWS::S3::Bucket", "No public policy statement or ACL grant")


class S3DefaultEncryption(Check):
    id = "S3-003"
    title = "S3 bucket has no default encryption configured"
    severity = "medium"
    service = "s3"
    cis_ref = "n/a (AWS FSBP S3.4)"
    description = "Without default encryption, new objects may be stored unencrypted at rest."
    recommendation = "Set default encryption to SSE-S3 (free) or SSE-KMS on the bucket."

    def evaluate(self):
        s3 = self.aws.client("s3")
        for bucket in list_buckets(self.aws):
            try:
                rules = s3.get_bucket_encryption(Bucket=bucket)[
                    "ServerSideEncryptionConfiguration"]["Rules"]
                algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                yield self.passed(bucket, "AWS::S3::Bucket", f"Default encryption: {algo}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                    raise
                yield self.failed(bucket, "AWS::S3::Bucket", "No default encryption rule")


CHECKS = [S3BlockPublicAccess, S3PublicPolicyOrAcl, S3DefaultEncryption]
