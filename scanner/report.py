"""HTML assessment report: `python -m scanner report`.

Builds one self-contained HTML file (no internet needed to open it) from the
latest scan, the drift against the previous scan, the fired alerts and the
MTTD measurements. Saved as results/report-<scan_id>.html.
"""
from collections import Counter, OrderedDict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from common import config
from scanner import results
from scanner.diff import diff_scans
from scanner.scoring import SEVERITY_WEIGHTS

TEMPLATES = config.ROOT / "scanner" / "templates"
SEV_ORDER = {s: i for i, s in enumerate(SEVERITY_WEIGHTS)}


def build_report() -> str:
    scans = results.list_scans()
    if not scans:
        raise SystemExit("No scans yet. Run: python -m scanner scan")
    latest = results.load_scan(scans[-1])
    drift = diff_scans(results.load_scan(scans[-2]), latest) if len(scans) > 1 else None

    findings = latest["findings"]
    fails = sorted((f for f in findings if f.status == "FAIL"),
                   key=lambda f: (SEV_ORDER[f.severity], f.check_id))
    errors = [f for f in findings if f.status == "ERROR"]

    # One recommendation per failed check (not per resource), most severe first.
    recs = OrderedDict()
    for f in fails:
        rec = recs.setdefault(f.check_id, {"finding": f, "resources": []})
        rec["resources"].append(f.resource_id)

    by_service = Counter(f.service for f in fails)

    # Detection and MTTD are optional extras (they exist once simulations have run).
    from detection.engine import read_alerts
    from simulation.cli import compute_mttd
    alerts = read_alerts()
    mttd = compute_mttd()
    detected = [r["mttd_seconds"] for r in mttd if r["mttd_seconds"] is not None]

    trend = [{"scan_id": s.stem.replace("scan-", ""),
              "score": results.load_scan(s)["summary"]["score"]} for s in scans[-10:]]

    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    html = env.get_template("report.html.j2").render(
        scan=latest, summary=latest["summary"], fails=fails, errors=errors,
        recommendations=list(recs.values()), by_service=by_service.most_common(),
        drift=drift, alerts=alerts[-50:], alert_count=len(alerts),
        alerts_by_rule=Counter(f"{a['rule_id']} {a['rule_name']}" for a in alerts).most_common(),
        mttd=mttd, mttd_detected=len(detected), mttd_mean=round(sum(detected) / len(detected)) if detected else None,
        trend=trend, weights=SEVERITY_WEIGHTS)
    path = config.RESULTS_DIR / f"report-{latest['scan_id']}.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
