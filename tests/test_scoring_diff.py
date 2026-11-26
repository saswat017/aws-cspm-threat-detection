from scanner.diff import diff_scans
from scanner.models import Finding
from scanner.prowler_runner import normalize_ocsf
from scanner.scoring import posture_score, summarize


def f(check, status, severity="high", resource="r1"):
    return Finding(check_id=check, title="t", severity=severity, status=status,
                   resource_id=resource, resource_type="x", region="us-east-1",
                   service="s", cis_ref="n/a", description="", recommendation="")


def test_score_weights():
    # critical PASS (10) + high FAIL (5) -> 100 * (1 - 5/15) = 66.7
    assert posture_score([f("A", "PASS", "critical"), f("B", "FAIL", "high")]) == 66.7
    assert posture_score([]) == 100.0


def test_errors_excluded_from_score_but_lower_coverage():
    s = summarize([f("A", "PASS"), f("B", "ERROR")])
    assert s["score"] == 100.0 and s["coverage_pct"] == 50.0 and s["errors"] == 1


def test_diff_new_and_resolved():
    old = {"scan_id": "1", "summary": {"score": 80}, "findings": [f("A", "FAIL"), f("B", "FAIL")]}
    new = {"scan_id": "2", "summary": {"score": 70}, "findings": [f("B", "FAIL"), f("C", "FAIL"), f("A", "PASS")]}
    d = diff_scans(old, new)
    assert [x.check_id for x in d["new"]] == ["C"]
    assert [x.check_id for x in d["resolved"]] == ["A"]
    assert d["unchanged"] == 1 and d["score_change"] == -10


def test_prowler_ocsf_normalization(tmp_path):
    sample = [{
        "status_code": "FAIL", "severity": "High", "status_detail": "Root has no MFA",
        "finding_info": {"title": "Ensure MFA is enabled for the root account", "uid": "x"},
        "metadata": {"event_code": "iam_root_mfa_enabled"},
        "resources": [{"uid": "arn:aws:iam::123:root", "type": "AwsIamUser", "region": "us-east-1",
                       "group": {"name": "iam"}}],
        "remediation": {"desc": "Enable MFA"},
        "unmapped": {"compliance": {"CIS-3.0": ["1.5"]}}}]
    path = tmp_path / "p.ocsf.json"
    import json
    path.write_text(json.dumps(sample))
    out = normalize_ocsf(path)[0]
    assert (out.check_id, out.status, out.severity, out.cis_ref, out.source) == (
        "iam_root_mfa_enabled", "FAIL", "high", "CIS-3.0 1.5", "prowler")


def test_low_coverage_flag():
    s = summarize([f("A", "PASS")] + [f(str(i), "ERROR") for i in range(9)])
    assert s["coverage_pct"] == 10.0 and s["low_coverage"] is True
    assert summarize([f("A", "PASS"), f("B", "FAIL")])["low_coverage"] is False


def test_comparable_scans_same_environment(tmp_path, monkeypatch):
    import json
    from common import config
    from scanner import results
    monkeypatch.setattr(config, "RESULTS_DIR", tmp_path)
    for stamp, mode, acct in [("20260101T000001Z", "demo", "1"), ("20260101T000002Z", "live", "2"),
                              ("20260101T000003Z", "demo", "1")]:
        (tmp_path / f"scan-{stamp}.json").write_text(json.dumps({"mode": mode, "account_id": acct}))
    assert [p.name for p in results.comparable_scans("demo")] == [
        "scan-20260101T000001Z.json", "scan-20260101T000003Z.json"]
    assert [p.name for p in results.comparable_scans("live")] == ["scan-20260101T000002Z.json"]


def test_save_and_load_scan_round_trip(tmp_path, monkeypatch):
    from common import config
    from scanner import results
    monkeypatch.setattr(config, "RESULTS_DIR", tmp_path)
    path = results.save_scan({"mode": config.MODE, "account_id": "1", "summary": summarize([f("A", "FAIL")])},
                             [f("A", "FAIL")])
    loaded = results.load_scan(path)
    assert loaded["findings"][0].check_id == "A"
    assert [p.name for p in results.comparable_scans()] == [path.split("/")[-1].split("\\")[-1]]
