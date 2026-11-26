"""EC2 checks: public IPs, disk encryption and the instance metadata service."""
from scanner.checks.base import Check


def all_instances(aws):
    """Running and stopped instances (terminated ones no longer matter)."""
    pages = aws.client("ec2").get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}])
    for page in pages:
        for reservation in page["Reservations"]:
            yield from reservation["Instances"]


def name_of(instance):
    for tag in instance.get("Tags", []):
        if tag["Key"] == "Name":
            return f"{instance['InstanceId']} ({tag['Value']})"
    return instance["InstanceId"]


class PublicIpAttached(Check):
    id = "EC2-001"
    title = "EC2 instance has a public IP address"
    severity = "medium"
    service = "ec2"
    cis_ref = "n/a (AWS FSBP EC2.9)"
    description = ("An instance with a public IP is directly reachable from the internet; "
                   "one security group mistake exposes it.")
    recommendation = ("Remove the public IP; place the instance behind a load balancer, or "
                      "use SSM Session Manager for admin access.")

    def evaluate(self):
        for inst in all_instances(self.aws):
            ip = inst.get("PublicIpAddress")
            if ip:
                yield self.failed(name_of(inst), "AWS::EC2::Instance", f"Public IP {ip}")
            else:
                yield self.passed(name_of(inst), "AWS::EC2::Instance", "No public IP")


class UnencryptedEbsVolume(Check):
    id = "EC2-002"
    title = "EBS volume is not encrypted"
    severity = "high"
    service = "ec2"
    cis_ref = "CIS 2.2.1 (related); AWS FSBP EC2.3"
    description = ("Unencrypted disks and their snapshots expose data if they are copied, "
                   "shared or restored by someone else.")
    recommendation = ("Create an encrypted copy of the volume (snapshot, copy with encryption, "
                      "restore) and turn on EBS encryption by default for the region.")

    def evaluate(self):
        pages = self.aws.client("ec2").get_paginator("describe_volumes").paginate()
        for page in pages:
            for vol in page["Volumes"]:
                attached = ", ".join(a["InstanceId"] for a in vol.get("Attachments", [])) or "unattached"
                if vol.get("Encrypted"):
                    yield self.passed(vol["VolumeId"], "AWS::EC2::Volume", f"Encrypted ({attached})")
                else:
                    yield self.failed(vol["VolumeId"], "AWS::EC2::Volume", f"Not encrypted ({attached})")


class ImdsV1Allowed(Check):
    id = "EC2-003"
    title = "EC2 instance allows IMDSv1"
    severity = "high"
    service = "ec2"
    cis_ref = "CIS 5.6"
    description = ("IMDSv1 answers simple GET requests, so an SSRF bug in an app on the "
                   "instance can be used to steal the instance role's credentials. IMDSv2 "
                   "requires a session token and blocks this.")
    recommendation = "Set the instance metadata option HttpTokens to 'required' (IMDSv2 only)."

    def evaluate(self):
        for inst in all_instances(self.aws):
            opts = inst.get("MetadataOptions", {})
            if opts.get("HttpEndpoint") == "disabled" or opts.get("HttpTokens") == "required":
                yield self.passed(name_of(inst), "AWS::EC2::Instance", "IMDSv2 required")
            else:
                yield self.failed(name_of(inst), "AWS::EC2::Instance",
                                  f"HttpTokens = {opts.get('HttpTokens', 'optional')}")


CHECKS = [PublicIpAttached, UnencryptedEbsVolume, ImdsV1Allowed]
