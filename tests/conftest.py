"""Shared pytest fixtures: every test gets a fresh, empty mock AWS account (moto)."""
import os

import pytest
from moto import mock_aws

from common.aws import AwsContext

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    # Make sure no test can ever reach real AWS.
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def aws():
    # load_aws_managed_policies: make AWS managed policies such as AdministratorAccess exist.
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        yield AwsContext(mode="test", region=REGION)


def statuses(findings):
    """{resource_id: status} helper for readable assertions."""
    return {f.resource_id: f.status for f in findings}
