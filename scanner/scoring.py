"""Posture score: one number (0-100) for how secure the account is.

Every evaluated check result (PASS or FAIL) carries the weight of its
severity. The score is the share of that weight that passed:

    score = 100 * (1 - failed_weight / evaluated_weight)

ERROR results are left out of the score (we could not check them), but they
lower the "coverage" figure so they are never mistaken for a pass.
"""
from collections import Counter

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
# Below this share of evaluated checks, the score says too little to be trusted.
MIN_COVERAGE_PCT = 50.0


def posture_score(findings) -> float:
    evaluated = [f for f in findings if f.status in ("PASS", "FAIL")]
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in evaluated)
    if total == 0:
        return 100.0
    failed = sum(SEVERITY_WEIGHTS[f.severity] for f in evaluated if f.status == "FAIL")
    return round(100 * (1 - failed / total), 1)


def summarize(findings) -> dict:
    status = Counter(f.status for f in findings)
    failed_by_severity = Counter(f.severity for f in findings if f.status == "FAIL")
    evaluated = status["PASS"] + status["FAIL"]
    total = evaluated + status["ERROR"]
    return {
        "score": posture_score(findings),
        "results": total,
        "passed": status["PASS"],
        "failed": status["FAIL"],
        "errors": status["ERROR"],
        "coverage_pct": round(100 * evaluated / total, 1) if total else 100.0,
        "low_coverage": total > 0 and 100 * evaluated / total < MIN_COVERAGE_PCT,
        "failed_by_severity": {s: failed_by_severity.get(s, 0) for s in SEVERITY_WEIGHTS},
    }
