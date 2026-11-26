"""Streamlit dashboard: control panel + views for posture, drift, threats and MTTD.

Run:  python -m streamlit run dashboard/app.py

Everything here calls the same Python functions as the command line tools, so
the dashboard and the CLI always agree.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # so `import scanner` etc. work under `streamlit run`

import altair as alt  # noqa: E402
import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from common import config  # noqa: E402
from common.aws import AwsContext  # noqa: E402
from detection.engine import DetectionEngine, read_alerts  # noqa: E402
from detection.rules import load_rules  # noqa: E402
from scanner import results  # noqa: E402
from scanner.cli import run_scan  # noqa: E402
from scanner.diff import diff_scans  # noqa: E402
from simulation.cli import compute_mttd, read_log, revert_one, run_one  # noqa: E402
from simulation.scenarios import SCENARIOS  # noqa: E402

# Severity uses the fixed status palette, always shown together with its text label.
SEVERITIES = ["critical", "high", "medium", "low"]
SEV_COLORS = ["#dc3c3d", "#f18a59", "#fbb315", "#9c9c9c"]
ACCENT = "#257de0"
# Streamlit counts the title and axes inside a chart's height; this is their share (px).
CHART_OVERHEAD = 90
CIS_SECTIONS = {"1": "1 Identity and Access", "2": "2 Storage", "3": "3 Logging",
                "4": "4 Monitoring", "5": "5 Networking"}

st.set_page_config(page_title="AWS CSPM and Threat Detection", page_icon="🛡️", layout="wide")


# ------------------------------------------------------------------ helpers --
def get_aws():
    """AwsContext, or None (with the reason) if AWS / the emulator is unreachable."""
    try:
        aws = AwsContext()
        _ = aws.account_id  # forces a connection check
        return aws, None
    except SystemExit as e:
        return None, str(e)
    except Exception as e:  # credentials, network, ...
        return None, f"{type(e).__name__}: {e}"


def load_all_scans():
    """Scans of the newest scan's environment only (same mode and account)."""
    return [results.load_scan(p) for p in results.comparable_scans()]


def findings_frame(scan):
    df = pd.DataFrame([f.to_dict() for f in scan["findings"]])
    df["cis_section"] = df["cis_ref"].str.extract(r"CIS (\d)")[0].map(CIS_SECTIONS).fillna("Not a CIS control")
    return df


def severity_bar(df, title):
    """Horizontal bars of failed findings per severity (status colors + text labels)."""
    counts = (df[df.status == "FAIL"].groupby("severity").size()
              .reindex(SEVERITIES, fill_value=0).reset_index(name="findings"))
    return (alt.Chart(counts, title=title).mark_bar(cornerRadiusEnd=4)
            .encode(y=alt.Y("severity:N", sort=SEVERITIES, title=None,
                            scale=alt.Scale(paddingInner=0.35)),
                    x=alt.X("findings:Q", title="Failed findings", axis=alt.Axis(tickMinStep=1)),
                    color=alt.Color("severity:N", scale=alt.Scale(domain=SEVERITIES, range=SEV_COLORS),
                                    legend=None),
                    tooltip=["severity", "findings"])
            .properties(height=CHART_OVERHEAD + 34 * len(SEVERITIES)))


def count_bar(df, field, title, x_title="Failed findings"):
    counts = df.groupby(field).size().reset_index(name="count").sort_values("count", ascending=False)
    return (alt.Chart(counts, title=title).mark_bar(cornerRadiusEnd=4, color=ACCENT)
            .encode(y=alt.Y(f"{field}:N", sort="-x", title=None, scale=alt.Scale(paddingInner=0.35),
                            axis=alt.Axis(labelLimit=220)),
                    x=alt.X("count:Q", title=x_title, axis=alt.Axis(tickMinStep=1)),
                    tooltip=[field, "count"])
            .properties(height=CHART_OVERHEAD + 34 * len(counts)))


def show(container, chart):
    """Render an Altair chart full-width at the height set in its spec."""
    height = chart.height if isinstance(chart.height, int) else "content"
    container.altair_chart(chart, width="stretch", height=height)


def act(label, func, *args):
    """Run a dashboard action; keep its error (if any) to show after the page reloads."""
    try:
        func(*args)
    except (SystemExit, Exception) as e:
        st.session_state.setdefault("errors", []).append(f"{label}: {e}")


def run_lab(command):
    with st.spinner(f"python -m lab {command} (deploying takes about 2-3 minutes)..."):
        proc = subprocess.run([sys.executable, "-m", "lab", command], cwd=ROOT,
                              capture_output=True, text=True, timeout=1200)
    out = (proc.stdout + proc.stderr).strip().splitlines()
    (st.success if proc.returncode == 0 else st.error)("\n".join(out[-6:]) or "done")


# ------------------------------------------------------------------ sidebar --
aws, aws_error = get_aws()

with st.sidebar:
    st.title("🛡️ Cloud security lab")
    if config.MODE == "demo":
        st.warning("**DEMO MODE**: local AWS emulator (moto), not a real AWS account. "
                   "Activity events are generated by the simulator.")
    else:
        st.info(f"**LIVE MODE**: real AWS, profile `{config.AWS_PROFILE}`.")
    if aws:
        st.caption(f"Account `{aws.account_id}` · {aws.region}")
    else:
        st.error(aws_error)

    if config.MODE == "demo":
        st.subheader("Lab")
        c1, c2 = st.columns(2)
        if c1.button("Start / deploy"):
            run_lab("up")
            st.rerun()
        if c2.button("Stop", width="stretch"):
            run_lab("down")
            st.rerun()

    st.subheader("Assess and detect")
    live_ok = config.MODE == "demo" or st.checkbox("I understand actions change REAL AWS")
    if st.button("Run posture scan", type="primary", width="stretch", disabled=aws is None):
        with st.spinner("Scanning..."):
            path, meta, _ = run_scan(aws, quiet=True)
        st.success(f"Score {meta['summary']['score']}/100 · {meta['summary']['failed']} failed")
    if st.button("Check for threats now", width="stretch", disabled=aws is None):
        found = DetectionEngine(aws).run_once()
        st.success(f"{len(found)} new alert(s)")
    live_detection = st.toggle("Live detection (every 10 s)", value=False, disabled=aws is None)

    st.subheader("Report")
    if st.button("Generate HTML report", width="stretch"):
        from scanner.report import build_report
        try:
            st.session_state["report"] = build_report()
        except SystemExit as e:
            st.error(str(e))
    if st.session_state.get("report"):
        report_path = Path(st.session_state["report"])
        st.download_button("Download report", report_path.read_bytes(), file_name=report_path.name,
                           mime="text/html", width="stretch")


# ------------------------------------------------------------------- header --
scans = load_all_scans()
alerts = read_alerts()
mttd_rows = compute_mttd()

st.title("Continuous Security Posture and Threat Detection")
if not scans:
    st.info("No scans yet. Start the lab (sidebar), then press **Run posture scan**.")

latest = scans[-1] if scans else None
previous = scans[-2] if len(scans) > 1 else None
detected = [r["mttd_seconds"] for r in mttd_rows if r["mttd_seconds"] is not None]

m1, m2, m3, m4, m5 = st.columns(5)
if latest:
    s = latest["summary"]
    delta = round(s["score"] - previous["summary"]["score"], 1) if previous else None
    m1.metric("Posture score", f"{s['score']}/100", delta=delta,
              help=f"Coverage {s['coverage_pct']}% of checks evaluated")
    if s.get("low_coverage"):
        st.warning(f"Only {s['coverage_pct']}% of checks could be evaluated (missing read permissions), "
                   "so the posture score is not meaningful.")
    m2.metric("Failed checks", s["failed"])
    m3.metric("Critical findings", s["failed_by_severity"]["critical"])
m4.metric("Alerts raised", len(alerts))
m5.metric("Mean time to detect", f"{sum(detected) / len(detected):.0f} s" if detected else "-",
          help="From simulated attack to first matching alert")

tab_overview, tab_findings, tab_drift, tab_threats, tab_sim = st.tabs(
    ["Overview", "Findings", "Drift", "Threat detection", "Attack simulation"])

# ------------------------------------------------------------------ overview --
with tab_overview:
    if latest:
        trend = pd.DataFrame([{"scan": i + 1, "time": x["scan_id"], "score": x["summary"]["score"],
                               "failed": x["summary"]["failed"]} for i, x in enumerate(scans)])
        line = (alt.Chart(trend, title="Posture score per scan")
                .mark_line(strokeWidth=2, color=ACCENT, point=alt.OverlayMarkDef(size=64, color=ACCENT))
                .encode(x=alt.X("scan:O", title="Scan number", axis=alt.Axis(labelAngle=0)),
                        y=alt.Y("score:Q", title="Score", scale=alt.Scale(domain=[0, 100])),
                        tooltip=["scan", alt.Tooltip("time", title="scan id (UTC)"), "score", "failed"])
                .properties(height=300))
        show(st, line)

        df = findings_frame(latest)
        fails = df[df.status == "FAIL"]
        c1, c2, c3 = st.columns(3)
        show(c1, severity_bar(df, "By severity"))
        if len(fails):
            show(c2, count_bar(fails, "service", "By service"))
            show(c3, count_bar(fails, "cis_section", "By CIS section"))
        st.caption(f"Latest scan {latest['scan_id']} · mode {latest['mode']} · account {latest['account_id']} · "
                   f"coverage {latest['summary']['coverage_pct']}% · Prowler: {latest['prowler']} · "
                   "only scans of this environment are shown")

# ------------------------------------------------------------------ findings --
with tab_findings:
    if latest:
        df = findings_frame(latest)
        f1, f2, f3 = st.columns(3)
        sev = f1.multiselect("Severity", SEVERITIES, default=SEVERITIES)
        status = f2.multiselect("Status", ["FAIL", "ERROR", "PASS"], default=["FAIL", "ERROR"])
        service = f3.multiselect("Service", sorted(df.service.unique()), default=sorted(df.service.unique()))
        view = df[df.severity.isin(sev) & df.status.isin(status) & df.service.isin(service)].copy()
        view["order"] = view.severity.map({s: i for i, s in enumerate(SEVERITIES)})
        view = view.sort_values(["order", "check_id"])
        st.dataframe(view[["severity", "status", "check_id", "title", "resource_id", "cis_ref",
                           "evidence", "recommendation"]], hide_index=True, width="stretch")

# --------------------------------------------------------------------- drift --
with tab_drift:
    if previous:
        d = diff_scans(previous, latest)
        st.markdown(f"Comparing scan **{d['old_scan']}** with **{d['new_scan']}** · score change "
                    f"**{d['score_change']:+}** · unchanged findings: {d['unchanged']}")
        c1, c2 = st.columns(2)
        c1.subheader(f"🔺 New findings ({len(d['new'])})")
        c1.dataframe(pd.DataFrame([{"severity": f.severity, "check": f.check_id, "resource": f.resource_id,
                                    "evidence": f.evidence} for f in d["new"]]),
                     hide_index=True, width="stretch")
        c2.subheader(f"✅ Resolved findings ({len(d['resolved'])})")
        c2.dataframe(pd.DataFrame([{"severity": f.severity, "check": f.check_id, "resource": f.resource_id}
                                   for f in d["resolved"]]),
                     hide_index=True, width="stretch")
    else:
        st.info("Drift needs two scans. Run a scan, run an attack simulation, then scan again.")

# ------------------------------------------------------------ threat detection --
with tab_threats:
    @st.fragment(run_every="10s" if live_detection else None)
    def live_alerts():
        if live_detection and aws:
            new = DetectionEngine(aws).run_once()
            for a in new:
                st.toast(f"{a['severity'].upper()}: {a['rule_name']}", icon="🚨")
        current = read_alerts()
        st.caption(("🟢 Live detection is on: checking CloudTrail and flow logs every 10 s"
                    if live_detection else "Live detection is off (toggle it in the sidebar)")
                   + f" · {len(current)} alerts")
        if current:
            adf = pd.DataFrame(current[::-1])
            adf["detected_at"] = adf["detected_at"].str.replace("T", " ").str[:19]
            st.dataframe(adf[["detected_at", "severity", "rule_id", "rule_name", "mitre_technique",
                              "summary", "source_ip", "resource"]], hide_index=True,
                         width="stretch", height=320)
            show(st, count_bar(adf.assign(rule=adf.rule_id + " " + adf.rule_name), "rule",
                                      "Alerts per rule", x_title="Alerts"))
    live_alerts()

    st.subheader("Detection rules and MITRE ATT&CK mapping")
    st.dataframe(pd.DataFrame([{"rule": r.id, "name": r.name, "severity": r.severity, "type": r.type,
                                "MITRE technique": f"{r.mitre['technique_id']} {r.mitre['technique']}",
                                "tactic": r.mitre["tactic"]} for r in load_rules()]),
                 hide_index=True, width="stretch")

# --------------------------------------------------------- attack simulation --
with tab_sim:
    st.markdown("Each scenario performs a careless-admin or attacker action. **Revert** is manual "
                "cleanup by the defender; nothing is fixed automatically.")
    log = read_log()
    last_action = {}
    for entry in log:
        last_action[entry["scenario"]] = f"{entry['action']} at {entry['started_at'][11:19]}"
    disabled = aws is None or not live_ok

    b1, b2, _ = st.columns([1, 1, 4])
    for msg in st.session_state.pop("errors", []):
        st.error(msg)
    if b1.button("Run all scenarios", type="primary", disabled=disabled):
        for name in SCENARIOS:
            act(name, run_one, aws, name)
        st.rerun()
    if b2.button("Revert all", disabled=disabled):
        for name in reversed(list(SCENARIOS)):
            act(name, revert_one, aws, name)
        st.rerun()

    for name, cls in SCENARIOS.items():
        c1, c2, c3, c4 = st.columns([4, 2, 1, 1])
        c1.markdown(f"**{name}**{' · demo only' if cls.demo_only else ''}  \n{cls.title}")
        c2.caption(f"expects {', '.join(cls.expected_rules)}  \nlast: {last_action.get(name, '-')}")
        if c3.button("Run", key=f"run-{name}", disabled=disabled):
            act(name, run_one, aws, name)
            st.rerun()
        if c4.button("Revert", key=f"rev-{name}", disabled=disabled):
            act(name, revert_one, aws, name)
            st.rerun()

    st.subheader("Mean time to detect")
    if mttd_rows:
        mdf = pd.DataFrame(mttd_rows)
        mdf["detected"] = mdf.detected_at.notna().map({True: "detected", False: "MISSED"})
        st.dataframe(mdf[["scenario", "rule_id", "started_at", "detected_at", "detected", "mttd_seconds"]],
                     hide_index=True, width="stretch")
        latest_runs = mdf.dropna(subset=["mttd_seconds"]).groupby(["scenario", "rule_id"], as_index=False).last()
        if len(latest_runs):
            latest_runs["attack"] = latest_runs.scenario + " / " + latest_runs.rule_id
            show(st, alt.Chart(latest_runs, title="Seconds from attack to first alert (latest run)")
                .mark_bar(cornerRadiusEnd=4, color=ACCENT)
                .encode(y=alt.Y("attack:N", sort="-x", title=None, scale=alt.Scale(paddingInner=0.35),
                                axis=alt.Axis(labelLimit=260)),
                        x=alt.X("mttd_seconds:Q", title="Seconds"),
                        tooltip=["scenario", "rule_id", "mttd_seconds"])
                .properties(height=32 * len(latest_runs)))
    else:
        st.info("No simulations yet. Press **Run all scenarios**, then **Check for threats now**.")
