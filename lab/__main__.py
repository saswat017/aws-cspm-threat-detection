"""Local AWS lab (emulator) controller.

    python -m lab up       start the emulator and deploy terraform/target + terraform/monitoring into it
    python -m lab status   show whether the emulator is running and what is deployed
    python -m lab reset    wipe the emulator and deploy again from scratch
    python -m lab down     stop the emulator
    python -m lab serve    run the emulator in this window, reachable from other computers
                           (on a second machine acting as "the cloud")

Remote cloud: set EMULATOR_ENDPOINT=http://<other machine's private IP>:5001 in .env;
`up` then connects to that machine instead of starting a local emulator.

This NEVER touches real AWS: it forces use_emulator=true, dummy credentials and a
local endpoint. Real AWS is deployed by running terraform yourself, on purpose.

Why an emulator: the project's AWS account is restricted by an AWS Organizations
service control policy that denies EC2, CloudTrail, SNS, EventBridge, SSM and
GuardDuty. moto (https://github.com/getmoto/moto) emulates those APIs locally.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from common import config
from common.aws import AwsContext, is_emulator_address

ROOT = config.ROOT
TF = ROOT / "terraform"
STACKS = ["target", "monitoring"]
WORKSPACE = "emulator"
PID_FILE = config.RESULTS_DIR / ".emulator.pid"
LOG_FILE = config.RESULTS_DIR / "emulator.log"
ENDPOINT = config.EMULATOR_ENDPOINT
# Remote = the emulator runs on another machine (the "cloud" laptop), not here.
REMOTE = urlparse(ENDPOINT).hostname not in ("127.0.0.1", "localhost")
if not is_emulator_address(ENDPOINT):
    sys.exit(f"EMULATOR_ENDPOINT {ENDPOINT} must be this computer or a private IP address.")


# ----------------------------------------------------------------- emulator --
def emulator_running() -> bool:
    try:
        with urllib.request.urlopen(f"{ENDPOINT}/moto-api/", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def start_emulator() -> bool:
    """Start moto_server in the background. Returns True if it was freshly started."""
    if emulator_running():
        return False
    if REMOTE:
        sys.exit(f"The emulator at {ENDPOINT} is not reachable. On that machine run:\n"
                 "  python -m moto.server -H 0.0.0.0 -p 5001\n"
                 "allow port 5001 in its firewall, and use the same Wi-Fi or hotspot.")
    url = urlparse(ENDPOINT)
    cmd = [sys.executable, "-m", "moto.server", "-H", url.hostname, "-p", str(url.port)]
    kwargs = {}
    if os.name == "nt":  # Windows: keep running after this command exits
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    else:
        kwargs["start_new_session"] = True
    log = open(LOG_FILE, "ab")
    # Make AWS managed policies (e.g. AdministratorAccess) exist in the emulator.
    env = {**os.environ, "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}
    proc = subprocess.Popen(cmd, stdout=log, stderr=log, env=env, **kwargs)
    PID_FILE.write_text(str(proc.pid))
    for _ in range(40):
        if emulator_running():
            print(f"Emulator started at {ENDPOINT} (pid {proc.pid})")
            return True
        time.sleep(0.5)
    sys.exit(f"Emulator did not start; see {LOG_FILE}")


def serve(port):
    """Run moto in the foreground on all network interfaces (machine acting as the cloud)."""
    env = {**os.environ, "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}
    print(f"Mock AWS cloud listening on port {port} on every network interface. Ctrl+C to stop.\n"
          "Only use a private network (home Wi-Fi or hotspot): the emulator has no password.")
    subprocess.run([sys.executable, "-m", "moto.server", "-H", "0.0.0.0", "-p", str(port)], env=env)


def stop_emulator():
    if REMOTE:
        print(f"The emulator runs on another machine ({ENDPOINT}); stop it there with Ctrl+C.")
        return
    if not PID_FILE.exists():
        print("No emulator started by this tool.")
        return
    pid = int(PID_FILE.read_text())
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
        print(f"Emulator stopped (pid {pid}).")
    except ProcessLookupError:
        print("Emulator was not running.")
    PID_FILE.unlink(missing_ok=True)


def reset_emulator():
    req = urllib.request.Request(f"{ENDPOINT}/moto-api/reset", method="POST")
    urllib.request.urlopen(req, timeout=10)


# ---------------------------------------------------------------- terraform --
def terraform(stack, *args, check=True):
    exe = shutil.which("terraform")
    if not exe:
        sys.exit("Terraform is not installed or not on PATH.")
    env = dict(os.environ)
    env.pop("AWS_PROFILE", None)                      # never pick up a real profile
    env.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
               AWS_REGION=config.REGION, TF_IN_AUTOMATION="1")
    cmd = [exe, f"-chdir={TF / stack}", *args]
    return subprocess.run(cmd, env=env, check=check)


def emulator_state_file(stack) -> Path:
    return TF / stack / "terraform.tfstate.d" / WORKSPACE / "terraform.tfstate"


def deploy():
    tf_vars = ["-var", "use_emulator=true", "-var", f"emulator_endpoint={ENDPOINT}"]
    for stack in STACKS:
        print(f"\n=== terraform apply: {stack} (emulator) ===")
        # Always init: it is quick, and it repairs a missing or stale lock file.
        terraform(stack, "init", "-input=false")
        terraform(stack, "workspace", "select", "-or-create", WORKSPACE)
        try:
            extra = ["-var", "alert_email=alerts@example.com"] if stack == "monitoring" else []
            terraform(stack, "apply", "-auto-approve", "-input=false", *tf_vars, *extra)
        finally:
            # Leave the folder on the "default" workspace, which is the real-AWS one.
            terraform(stack, "workspace", "select", "default", check=False)
    emulator_fixups()


def emulator_fixups():
    """Things Terraform cannot create in the emulator, created the same way with boto3."""
    aws = AwsContext(mode="demo")
    print("\n=== emulator fix-ups (boto3) ===")

    # 1) CloudTrail trail (same settings as terraform/monitoring/cloudtrail.tf).
    ct, name = aws.client("cloudtrail"), f"{config.PROJECT}-trail"
    existing = [t["Name"] for t in ct.describe_trails()["trailList"]]
    if name not in existing:
        role = aws.client("iam").get_role(RoleName=f"{config.PROJECT}-cloudtrail-to-logs")["Role"]["Arn"]
        ct.create_trail(
            Name=name, S3BucketName=f"{config.PROJECT}-cloudtrail-{aws.account_id}",
            IsMultiRegionTrail=True, IncludeGlobalServiceEvents=True, EnableLogFileValidation=True,
            CloudWatchLogsLogGroupArn=(f"arn:aws:logs:{aws.region}:{aws.account_id}:log-group:"
                                       f"{config.CLOUDTRAIL_LOG_GROUP}:*"),
            CloudWatchLogsRoleArn=role)
        ct.start_logging(Name=name)
        print(f"created CloudTrail trail {name}")

    # 2) The lab's admin IAM user, mirroring the real account (cspm-admin with an access key).
    iam = aws.client("iam")
    if "cspm-admin" not in [u["UserName"] for u in iam.list_users()["Users"]]:
        iam.create_user(UserName="cspm-admin")
        iam.attach_user_policy(UserName="cspm-admin",
                               PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        iam.create_access_key(UserName="cspm-admin")
        print("created IAM user cspm-admin (AdministratorAccess + access key)")


def outputs(stack) -> dict:
    """Read a stack's outputs from its emulator state file."""
    path = emulator_state_file(stack)
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {k: v["value"] for k, v in data.get("outputs", {}).items()}


# --------------------------------------------------------------------- CLI --
def lab_missing() -> bool:
    """True if the emulator does not contain the lab (e.g. it was restarted, or it is
    another machine's fresh emulator), so old Terraform state must be thrown away."""
    vpcs = AwsContext(mode="demo", endpoint=ENDPOINT).client("ec2").describe_vpcs(
        Filters=[{"Name": "tag:Project", "Values": [config.PROJECT]}])["Vpcs"]
    return not vpcs


def cmd_up(args):
    fresh = start_emulator()
    if fresh or args.reset or lab_missing():
        if not fresh:
            reset_emulator()
        # The emulator keeps everything in memory, so old state files are stale.
        for stack in STACKS:
            emulator_state_file(stack).unlink(missing_ok=True)
        # A fresh emulator is a new environment: forget what the detection engine
        # learned about the old one (checkpoints, baselines).
        (config.RESULTS_DIR / "detection_state.json").unlink(missing_ok=True)
    deploy()
    print("\nLab is up. Try: python -m scanner scan")


def cmd_status(_args):
    if not emulator_running():
        print(f"Emulator: NOT running ({ENDPOINT}). Start it with: python -m lab up")
        return
    print(f"Emulator: running at {ENDPOINT}")
    for stack in STACKS:
        out = outputs(stack)
        print(f"\n[{stack}] {'deployed' if out else 'not deployed'}")
        for k, v in out.items():
            print(f"  {k:24} {v}")


def main():
    parser = argparse.ArgumentParser(prog="python -m lab", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    up = sub.add_parser("up", help="start the emulator and deploy the lab")
    up.add_argument("--reset", action="store_true", help="wipe the emulator first")
    up.set_defaults(func=cmd_up)
    sub.add_parser("reset", help="wipe and redeploy").set_defaults(
        func=lambda a: cmd_up(argparse.Namespace(reset=True)))
    sub.add_parser("status", help="show emulator and deployment status").set_defaults(func=cmd_status)
    sub.add_parser("down", help="stop the emulator").set_defaults(func=lambda a: stop_emulator())
    srv = sub.add_parser("serve", help="run the emulator here for other computers")
    srv.add_argument("--port", type=int, default=5001)
    srv.set_defaults(func=lambda a: serve(a.port))
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
