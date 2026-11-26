"""Drift detection: compare two scans and report what changed.

A finding is identified by check_id + resource_id. Between the older and the
newer scan:
  new       = FAIL now, but not FAIL before (something got worse: drift)
  resolved  = FAIL before, but not FAIL now (something was fixed)
"""


def diff_scans(old: dict, new: dict) -> dict:
    old_fail = {f.key: f for f in old["findings"] if f.status == "FAIL"}
    new_fail = {f.key: f for f in new["findings"] if f.status == "FAIL"}
    return {
        "old_scan": old["scan_id"],
        "new_scan": new["scan_id"],
        "score_change": round(new["summary"]["score"] - old["summary"]["score"], 1),
        "new": [new_fail[k] for k in sorted(new_fail.keys() - old_fail.keys())],
        "resolved": [old_fail[k] for k in sorted(old_fail.keys() - new_fail.keys())],
        "unchanged": len(new_fail.keys() & old_fail.keys()),
    }
