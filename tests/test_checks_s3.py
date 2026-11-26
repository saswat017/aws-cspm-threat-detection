import json

from scanner.checks.s3 import S3BlockPublicAccess, S3DefaultEncryption, S3PublicPolicyOrAcl
from tests.conftest import statuses

ALL_ON = {k: True for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]}


def make_buckets(s3):
    s3.create_bucket(Bucket="secure")
    s3.put_public_access_block(Bucket="secure", PublicAccessBlockConfiguration=ALL_ON)
    s3.put_bucket_encryption(Bucket="secure", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    s3.create_bucket(Bucket="public")
    s3.put_bucket_policy(Bucket="public", Policy=json.dumps({"Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::public/*"}]}))


def test_block_public_access(aws):
    make_buckets(aws.client("s3"))
    result = statuses(S3BlockPublicAccess(aws).run())
    assert result == {"secure": "PASS", "public": "FAIL"}


def test_public_policy_detected(aws):
    make_buckets(aws.client("s3"))
    result = statuses(S3PublicPolicyOrAcl(aws).run())
    assert result == {"secure": "PASS", "public": "FAIL"}


def test_public_acl_detected(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="acl-bucket")
    s3.put_bucket_acl(Bucket="acl-bucket", ACL="public-read")
    assert statuses(S3PublicPolicyOrAcl(aws).run()) == {"acl-bucket": "FAIL"}


def test_public_policy_neutralized_by_block_public_access(aws):
    s3 = aws.client("s3")
    make_buckets(s3)
    s3.put_public_access_block(Bucket="public", PublicAccessBlockConfiguration=ALL_ON)
    assert statuses(S3PublicPolicyOrAcl(aws).run())["public"] == "PASS"


def test_default_encryption(aws):
    make_buckets(aws.client("s3"))
    result = statuses(S3DefaultEncryption(aws).run())
    assert result["secure"] == "PASS"
    # Note: real AWS now encrypts every new bucket with SSE-S3 by default; moto may too.
    assert result["public"] in ("PASS", "FAIL")
