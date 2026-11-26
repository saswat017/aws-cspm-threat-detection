from scanner.checks.ec2 import ImdsV1Allowed, PublicIpAttached, UnencryptedEbsVolume
from scanner.checks.security_groups import (AllTrafficOpen, DefaultSecurityGroupRestricts,
                                            OtherPortOpen, RdpOpenToInternet, SshOpenToInternet)


def make_groups(ec2):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ssh = ec2.create_security_group(GroupName="ssh-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ssh, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    web = ec2.create_security_group(GroupName="web-v6", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    allp = ec2.create_security_group(GroupName="all-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=allp, IpPermissions=[{
        "IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    private = ec2.create_security_group(GroupName="private", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=private, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}])
    return {"ssh": ssh, "web": web, "all": allp, "private": private}


def by_group(findings, gid):
    return next(f.status for f in findings if f.resource_id.startswith(gid))


def test_ssh_check(aws):
    g = make_groups(aws.client("ec2"))
    out = SshOpenToInternet(aws).run()
    assert by_group(out, g["ssh"]) == "FAIL"
    assert by_group(out, g["all"]) == "FAIL"      # all ports includes 22
    assert by_group(out, g["private"]) == "PASS"  # VPC-only source is fine
    assert by_group(out, g["web"]) == "PASS"


def test_rdp_all_and_other_ports(aws):
    g = make_groups(aws.client("ec2"))
    assert by_group(RdpOpenToInternet(aws).run(), g["ssh"]) == "PASS"
    assert by_group(AllTrafficOpen(aws).run(), g["all"]) == "FAIL"
    assert by_group(AllTrafficOpen(aws).run(), g["ssh"]) == "PASS"
    other = OtherPortOpen(aws).run()
    assert by_group(other, g["web"]) == "FAIL"     # 443 from ::/0
    assert by_group(other, g["ssh"]) == "PASS"     # 22 is reported by SG-001 instead


def test_default_group_with_rules_fails(aws):
    aws.client("ec2").create_vpc(CidrBlock="10.1.0.0/16")
    out = DefaultSecurityGroupRestricts(aws).run()
    assert out and all(f.status == "FAIL" for f in out)  # AWS default groups ship with rules


def launch(ec2, **kwargs):
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    return ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                             **kwargs)["Instances"][0]["InstanceId"]


def test_imds_and_public_ip(aws):
    ec2 = aws.client("ec2")
    v1 = launch(ec2, MetadataOptions={"HttpTokens": "optional"})
    v2 = launch(ec2, MetadataOptions={"HttpTokens": "required"})
    imds = {f.resource_id.split()[0]: f.status for f in ImdsV1Allowed(aws).run()}
    assert imds == {v1: "FAIL", v2: "PASS"}
    assert all(f.status in ("PASS", "FAIL") for f in PublicIpAttached(aws).run())


def test_unencrypted_volume(aws):
    ec2 = aws.client("ec2")
    bad = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)["VolumeId"]
    good = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)["VolumeId"]
    out = {f.resource_id: f.status for f in UnencryptedEbsVolume(aws).run()}
    assert out[bad] == "FAIL" and out[good] == "PASS"
