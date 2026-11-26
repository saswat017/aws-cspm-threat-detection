"""Security group checks: inbound rules open to the whole internet."""
from scanner.checks.base import Check

WORLD = {"0.0.0.0/0", "::/0"}


def world_open_rules(sg):
    """Yield (protocol, from_port, to_port, cidr) for every inbound rule open to the internet."""
    for perm in sg.get("IpPermissions", []):
        cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
        cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
        for cidr in cidrs:
            if cidr in WORLD:
                yield (perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"), cidr)


def covers_port(rule, port):
    proto, start, end, _ = rule
    if proto == "-1":                       # "-1" = all protocols, all ports
        return True
    if proto not in ("tcp", "6"):
        return False
    return start is not None and start <= port <= end


def is_all_traffic(rule):
    proto, start, end, _ = rule
    return proto == "-1" or (start in (0, None) and end in (65535, None))


def describe(rule):
    proto, start, end, cidr = rule
    ports = "all" if proto == "-1" else (f"{start}" if start == end else f"{start}-{end}")
    return f"{'all' if proto == '-1' else proto}/{ports} from {cidr}"


def all_security_groups(aws):
    pages = aws.client("ec2").get_paginator("describe_security_groups").paginate()
    for page in pages:
        yield from page["SecurityGroups"]


class _PortOpenCheck(Check):
    """Shared logic: FAIL if any inbound rule opens `port` to 0.0.0.0/0 or ::/0."""
    port = None
    service = "ec2"

    def evaluate(self):
        for sg in all_security_groups(self.aws):
            bad = [describe(r) for r in world_open_rules(sg) if covers_port(r, self.port)]
            sg_id = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
            if bad:
                yield self.failed(sg_id, "AWS::EC2::SecurityGroup", "; ".join(bad))
            else:
                yield self.passed(sg_id, "AWS::EC2::SecurityGroup",
                                  f"Port {self.port} not open to the internet")


class SshOpenToInternet(_PortOpenCheck):
    id = "SG-001"
    title = "Security group allows SSH (22) from the internet"
    severity = "high"
    port = 22
    cis_ref = "CIS 5.2 / 5.3"
    description = ("SSH open to 0.0.0.0/0 or ::/0 exposes servers to constant brute-force "
                   "and exploit attempts from the whole internet.")
    recommendation = ("Remove the rule. Allow SSH only from a known IP range, or use SSM "
                      "Session Manager and open no inbound ports at all.")


class RdpOpenToInternet(_PortOpenCheck):
    id = "SG-002"
    title = "Security group allows RDP (3389) from the internet"
    severity = "high"
    port = 3389
    cis_ref = "CIS 5.2 / 5.3"
    description = "RDP open to the internet is a common ransomware entry point."
    recommendation = "Remove the rule; allow RDP only from a VPN or known admin IP range."


class AllTrafficOpen(Check):
    id = "SG-003"
    title = "Security group allows all ports from the internet"
    severity = "critical"
    service = "ec2"
    cis_ref = "CIS 5.2 / 5.3 (related)"
    description = "A rule allowing every port from the internet exposes every service on the host."
    recommendation = "Replace it with rules for only the specific ports that must be public."

    def evaluate(self):
        for sg in all_security_groups(self.aws):
            bad = [describe(r) for r in world_open_rules(sg) if is_all_traffic(r)]
            sg_id = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
            if bad:
                yield self.failed(sg_id, "AWS::EC2::SecurityGroup", "; ".join(bad))
            else:
                yield self.passed(sg_id, "AWS::EC2::SecurityGroup", "No all-ports rule open to the internet")


class OtherPortOpen(Check):
    id = "SG-004"
    title = "Security group allows another port from the internet"
    severity = "medium"
    service = "ec2"
    cis_ref = "n/a (AWS FSBP EC2.18)"
    description = "Any port open to the whole internet increases the attack surface."
    recommendation = "Confirm the port must be public; otherwise restrict the source range."

    def evaluate(self):
        for sg in all_security_groups(self.aws):
            bad = [describe(r) for r in world_open_rules(sg)
                   if not is_all_traffic(r) and not covers_port(r, 22) and not covers_port(r, 3389)]
            sg_id = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
            if bad:
                yield self.failed(sg_id, "AWS::EC2::SecurityGroup", "; ".join(bad))
            else:
                yield self.passed(sg_id, "AWS::EC2::SecurityGroup", "No other ports open to the internet")


class DefaultSecurityGroupRestricts(Check):
    id = "SG-005"
    title = "Default security group allows traffic"
    severity = "low"
    service = "ec2"
    cis_ref = "CIS 5.4"
    description = ("Resources launched without an explicit security group land in the VPC's "
                   "default group. It should allow nothing, so mistakes fail closed.")
    recommendation = "Remove all inbound and outbound rules from every default security group."

    def evaluate(self):
        for sg in all_security_groups(self.aws):
            if sg.get("GroupName") != "default":
                continue
            n_in, n_out = len(sg.get("IpPermissions", [])), len(sg.get("IpPermissionsEgress", []))
            sg_id = f"{sg['GroupId']} (default, {sg.get('VpcId', '')})"
            if n_in or n_out:
                yield self.failed(sg_id, "AWS::EC2::SecurityGroup",
                                  f"{n_in} inbound and {n_out} outbound rules")
            else:
                yield self.passed(sg_id, "AWS::EC2::SecurityGroup", "No rules")


CHECKS = [SshOpenToInternet, RdpOpenToInternet, AllTrafficOpen, OtherPortOpen,
          DefaultSecurityGroupRestricts]
