"""The only place boto3 sessions are created.

Every module asks AwsContext for clients, so switching between the emulator
(demo) and real AWS (live) is a single setting. Credentials are never stored
in code: live mode uses the named CLI profile, demo mode uses dummy keys that
the emulator accepts.
"""
import ipaddress
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import EndpointConnectionError

from common import config

_BOTO_CONFIG = Config(connect_timeout=5, read_timeout=30,
                      retries={"max_attempts": 3, "mode": "standard"})


def is_emulator_address(endpoint: str) -> bool:
    """Demo mode may only use this computer or a private network address
    (e.g. a second laptop on the same Wi-Fi). Those can never be real AWS."""
    host = urlparse(endpoint).hostname or ""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # host names are not allowed: they could point anywhere
    return ip.is_loopback or ip.is_private


class AwsContext:
    """Creates boto3 clients for one mode/region and remembers the account ID."""

    def __init__(self, mode=None, region=None, profile=None, endpoint=None):
        self.mode = mode or config.MODE
        self.region = region or config.REGION
        self._account_id = None

        if self.mode == "demo":
            endpoint = endpoint or config.EMULATOR_ENDPOINT
            # Safety: demo mode may only talk to this computer or a private-network machine.
            if not is_emulator_address(endpoint):
                raise ValueError("Demo mode only allows an emulator on this computer or on a "
                                 "private network address (e.g. 192.168.1.23).")
            self.endpoint = endpoint
            self.session = boto3.session.Session(
                aws_access_key_id="testing",       # dummy values, not secrets
                aws_secret_access_key="testing",
                region_name=self.region)
        elif self.mode == "live":
            self.endpoint = None
            self.session = boto3.session.Session(
                profile_name=profile or config.AWS_PROFILE, region_name=self.region)
        elif self.mode == "test":
            # Unit tests: moto's in-process mock intercepts normal AWS calls.
            self.endpoint = None
            self.session = boto3.session.Session(region_name=self.region)
        else:
            raise ValueError(f"Unknown mode {self.mode!r}")

    def client(self, service, region=None):
        return self.session.client(service, region_name=region or self.region,
                                   endpoint_url=self.endpoint, config=_BOTO_CONFIG)

    @property
    def account_id(self):
        if self._account_id is None:
            try:
                self._account_id = self.client("sts").get_caller_identity()["Account"]
            except EndpointConnectionError:
                if self.mode == "demo":
                    raise SystemExit(f"The AWS emulator is not running at {self.endpoint}. "
                                     "Start it with: python -m lab up")
                raise
        return self._account_id

    def describe(self):
        return {"mode": self.mode, "region": self.region,
                "account_id": self.account_id, "endpoint": self.endpoint}
