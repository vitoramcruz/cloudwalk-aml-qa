"""
CloudWalk Payments Inc. — AML/CTF Monitoring Dashboard
======================================================
Streamlit front-end over the tested case detection engine.

Design
------
* Ingestion layer   : st.file_uploader (.xlsx) + population guard-rail that
                      reconciles real ID counts (501 / 100 / 630) against the
                      openpyxl padded-range artifact (ws.max_row ~= 999).
* Calculation layer : imports the already-tested detection functions from
                      `detection_engine` (the importable extraction of
                      Section4b + Section2a). Detection logic is NOT reimplemented
                      here; the app only orchestrates, caches and visualizes.
* Visualization     : KPI header, Plotly trend / breakdown / distribution charts.
* Investigation     : entity drill-down (customer / merchant) + live alert
                      simulator that re-runs structuring / device-sharing
                      detection against the in-session dataset on every slider
                      change.

Run:  streamlit run app.py
"""

import io
import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import detection_engine as de

# Optional: auto-load a workbook sitting next to app.py (dev convenience).
SAMPLE_PATH = "AMLFT_Analyst_JIM__1_.xlsx"

st.set_page_config(page_title="CloudWalk AML Monitoring Dashboard",
                   page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------------------
# Cached compute layer (keyed on raw file bytes so re-runs are instant)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_bundle(file_bytes: bytes):
    return de.load_and_validate(io.BytesIO(file_bytes))


@st.cache_data(show_spinner="Running 11-typology detection engine…")
def run_engine(file_bytes: bytes):
    bundle = load_bundle(file_bytes)          # reuses the cached parse
    return de.run_all_typologies(bundle)


@st.cache_data(show_spinner=False)
def run_edd(file_bytes: bytes):
    bundle = load_bundle(file_bytes)          # reuses the cached parse
    return de.run_edd(bundle.cust, bundle.cards)


# ---------------------------------------------------------------------------
# Sidebar — ingestion + global controls
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ CloudWalk AML")
st.sidebar.caption("AML/CTF transaction-monitoring dashboard")

uploaded = st.sidebar.file_uploader("Upload AML workbook (.xlsx)", type=["xlsx"])

file_bytes = None
if uploaded is not None:
    file_bytes = uploaded.getvalue()
elif os.path.exists(SAMPLE_PATH):
    with open(SAMPLE_PATH, "rb") as fh:
        file_bytes = fh.read()
    st.sidebar.info(f"Using bundled workbook: `{SAMPLE_PATH}`")

if file_bytes is None:
    st.title("CloudWalk Payments Inc. — AML/CTF Monitoring Dashboard")
    st.info("⬅️ Upload the AML analyst workbook (`.xlsx`) to begin. "
            "Expected sheets: Transactions, Customers_KYC, Merchants_KYB, Cards.")
    st.stop()

# ---- Load + validate populations (guard-rail) -----------------------------
bundle = load_bundle(file_bytes)
v = bundle.validation

st.sidebar.subheader("Population validation")
for key in ["customers", "merchants", "cards", "transactions"]:
    row = v[key]
    exp = row["expected"]
    if exp is None:
        st.sidebar.write(f"{'✅'} {key.title()}: **{row['observed']:,}**")
    else:
        icon = "✅" if row["ok"] else "⚠️"
        st.sidebar.write(f"{icon} {key.title()}: **{row['observed']:,}** / {exp:,} expected")

if not v["all_ok"]:
    st.sidebar.warning("Observed populations differ from expected 501 / 100 / 630. "
                       "If this is a refreshed dataset that is fine; otherwise check "
                       "for blank-row padding (ws.max_row artifact).")

st.sidebar.divider()
st.sidebar.subheader("Escalation / SAR settings")
sar_escalation_score = st.sidebar.slider(
    "SAR escalation score cut", min_value=0, max_value=300, value=100, step=5,
    help="Alerting customers with a composite suspicion score at or above this "
         "cut are treated as SAR-escalation candidates. Used for the FPR proxy.")
sar_filed_count = st.sidebar.number_input(
    "SARs filed (case disposition)", min_value=0, value=3, step=1,
    help="Actual SARs filed per the case management system. Defaults to the case "
         "file value (device/IP mule-ring subjects).")

# ---- Run engine -----------------------------------------------------------
result = run_engine(file_bytes)
edd_pop = run_edd(file_bytes)
kpi = de.compute_kpis(result, bundle, sar_escalation_score, sar_filed_count)

cs = result["cust_score"]
txn_hits = result["txn_hits"]

# ---------------------------------------------------------------------------
# Header + KPI row
# ---------------------------------------------------------------------------
st.title("CloudWalk Payments Inc. — AML/CTF Monitoring Dashboard")
st.caption("Non-bank payment processor · sponsor-bank model · examiner-grade monitoring view")

k1, k2, k3, k4 = st.columns(4)
k1.metric("Total alerts", f"{kpi['total_alerts']:,}",
          help="Distinct customers with ≥1 typology hit across the 11-typology engine.")
k2.metric("False-positive rate (proxy)", f"{kpi['fpr_proxy']*100:.1f}%",
          delta=f"{kpi['escalated_candidates']:,} escalated", delta_color="off",
          help="Monitoring-model proxy = 1 − (escalation candidates ÷ total alerts) "
               "at the current score cut. A validated FPR requires case-disposition "
               "labels from the case management system.")
k3.metric("SARs filed", f"{kpi['sar_filed']:,}",
          help="Case-disposition input (sidebar). Defaults to the case file value.")
k4.metric("Portfolio chargeback ratio", f"{kpi['chargeback_ratio']*100:.2f}%",
          help="is_chargeback ÷ total transactions. Documented baseline ≈ 0.73%.")

st.divider()

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_charts, tab_drill, tab_sim, tab_edd = st.tabs(
    ["📊 Portfolio charts", "🔎 Entity drill-down", "🎚️ Alert simulator", "📋 EDD population"])

# ===========================================================================
# TAB 1 — CHARTS
# ===========================================================================
with tab_charts:
    c1, c2 = st.columns([3, 2])

    # --- Monthly alert trend (stacked by typology) -------------------------
    with c1:
        st.subheader("Monthly alert trend")
        if len(txn_hits):
            th = txn_hits.dropna(subset=["txn_timestamp_utc"]).copy()
            th["month"] = th["txn_timestamp_utc"].dt.to_period("M").dt.to_timestamp()
            th["typology_label"] = th["typology"].map(de.TYPOLOGY_LABELS).fillna(th["typology"])
            # distinct alerting transactions per month per typology
            trend = (th.groupby(["month", "typology_label"])["txn_id"]
                       .nunique().reset_index(name="alerting_txns"))
            fig = px.bar(trend, x="month", y="alerting_txns", color="typology_label",
                         labels={"month": "Month", "alerting_txns": "Alerting transactions",
                                 "typology_label": "Typology"})
            fig.update_layout(height=420, legend_title_text="Typology",
                              margin=dict(t=10, b=10), barmode="stack")
            st.plotly_chart(fig, width='stretch')
            st.caption("Distinct transactions that contributed to ≥1 typology alert, by month.")
        else:
            st.info("No transaction-level hits to plot.")

    # --- Risk-rating distribution ------------------------------------------
    with c2:
        st.subheader("Risk-rating distribution")
        scope = st.radio("Scope", ["Alerting customers", "Whole portfolio"],
                         horizontal=True, label_visibility="collapsed")
        if scope == "Alerting customers" and len(cs):
            rr = cs["risk_rating"].fillna("unknown").value_counts().reset_index()
        else:
            rr = bundle.cust["risk_rating"].fillna("unknown").value_counts().reset_index()
        rr.columns = ["risk_rating", "count"]
        order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
        rr = rr.sort_values("risk_rating", key=lambda s: s.map(lambda x: order.get(x, 9)))
        color_map = {"high": "#c0392b", "medium": "#e67e22", "low": "#27ae60", "unknown": "#7f8c8d"}
        fig = px.pie(rr, names="risk_rating", values="count", hole=0.5,
                     color="risk_rating", color_discrete_map=color_map)
        fig.update_layout(height=360, margin=dict(t=10, b=10))
        st.plotly_chart(fig, width='stretch')

    st.divider()

    # --- Breakdown by typology ---------------------------------------------
    st.subheader("Alerting customers by typology")
    if len(result["customer_hits"]):
        ch = result["customer_hits"].copy()
        by_typ = (ch.groupby("typology")["customer_id"].nunique()
                    .reset_index(name="alerting_customers"))
        by_typ["label"] = by_typ["typology"].map(de.TYPOLOGY_LABELS).fillna(by_typ["typology"])
        by_typ = by_typ.sort_values("alerting_customers", ascending=True)
        fig = px.bar(by_typ, x="alerting_customers", y="label", orientation="h",
                     labels={"alerting_customers": "Distinct alerting customers", "label": ""},
                     text="alerting_customers")
        fig.update_traces(marker_color="#2c5f8a", textposition="outside")
        fig.update_layout(height=430, margin=dict(t=10, b=10))
        st.plotly_chart(fig, width='stretch')
    else:
        st.info("No customer-level hits to plot.")

# ===========================================================================
# TAB 2 — DRILL-DOWN
# ===========================================================================
with tab_drill:
    entity = st.radio("Entity type", ["Customer", "Merchant"], horizontal=True)

    # ----- CUSTOMER --------------------------------------------------------
    if entity == "Customer":
        score_lookup = cs.set_index("customer_id") if len(cs) else pd.DataFrame()
        # Order: alerting customers (by rank) first, then remaining
        if len(cs):
            ranked_ids = cs.sort_values("rank")["customer_id"].tolist()
        else:
            ranked_ids = []
        remaining = [c for c in bundle.cust["customer_id"].tolist() if c not in ranked_ids]
        options = ranked_ids + remaining
        name_map = bundle.cust.set_index("customer_id")["full_name"].to_dict()

        def cust_label(cid):
            base = f"{cid} — {name_map.get(cid, '')}"
            if cid in score_lookup.index:
                r = int(score_lookup.loc[cid, "rank"])
                return f"#{r:>3}  {base}"
            return f"      {base}"

        cid = st.selectbox("Select customer_id", options, format_func=cust_label)
        crow = bundle.cust[bundle.cust["customer_id"] == cid].iloc[0]

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk rating", str(crow["risk_rating"]))
        m2.metric("KYC level", str(crow["kyc_level"]))
        m3.metric("Sanctions score", f"{crow['sanctions_match_score']:.2f}")
        m4.metric("PEP", "Yes" if crow["pep_flag"] else "No")

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown(f"**Name:** {crow['full_name']}  \n"
                        f"**Country / doc issue:** {crow['country']} / {crow['doc_issue_country']}  \n"
                        f"**Occupation:** {crow.get('occupation','—')}  \n"
                        f"**Source of funds:** {crow.get('source_of_funds','—')}  \n"
                        f"**Expected monthly vol.:** ${crow['expected_monthly_volume_usd']:,.0f}")
        with col_b:
            if cid in score_lookup.index:
                sr = score_lookup.loc[cid]
                floor = " (regulatory escalation floor applied)" if sr.get("regulatory_escalation_floor_applied") else ""
                st.markdown(f"**Suspicion rank:** #{int(sr['rank'])} of {len(cs)}{floor}  \n"
                            f"**Composite score:** {sr['final_score']:.1f}  \n"
                            f"**Distinct typologies:** {int(sr['n_distinct_typologies'])}")
                typ_labels = [de.TYPOLOGY_LABELS.get(t, t) for t in sr["typologies"]]
                st.markdown("**Typologies triggered:** " + ", ".join(typ_labels))
            else:
                st.markdown("_No typology alerts for this customer._")

        # Evidence
        ch = result["customer_hits"]
        ev = ch[ch["customer_id"] == cid] if len(ch) else pd.DataFrame()
        if len(ev):
            with st.expander("Evidence / flags", expanded=False):
                for _, e in ev.iterrows():
                    st.markdown(f"- **{de.TYPOLOGY_LABELS.get(e['typology'], e['typology'])}** "
                                f"(weight {e['weight']:.1f}): {e['evidence']}")

        # Transactions + timeline
        ctx = bundle.tx[bundle.tx["customer_id"] == cid].sort_values("txn_timestamp_utc")
        st.markdown(f"**Transactions ({len(ctx):,})**")
        if len(ctx):
            fig = px.scatter(ctx, x="txn_timestamp_utc", y="amount_usd", color="status",
                             hover_data=["txn_id", "merchant_name", "mcc", "channel",
                                         "merchant_country", "is_chargeback"],
                             labels={"txn_timestamp_utc": "Time", "amount_usd": "Amount (USD)"})
            fig.update_layout(height=320, margin=dict(t=10, b=10), legend_title_text="Status")
            st.plotly_chart(fig, width='stretch')
            st.dataframe(
                ctx[["txn_id", "txn_timestamp_utc", "merchant_id", "merchant_name", "mcc",
                     "channel", "pos_entry_mode", "amount_usd", "merchant_country",
                     "status", "is_chargeback", "device_id", "ip_address"]],
                width='stretch', height=280)

    # ----- MERCHANT --------------------------------------------------------
    else:
        mids = bundle.merch["merchant_id"].tolist()
        mname = bundle.merch.set_index("merchant_id")["dba_name"].to_dict()
        mid = st.selectbox("Select merchant_id", mids,
                           format_func=lambda m: f"{m} — {mname.get(m, '')}")
        mrow = bundle.merch[bundle.merch["merchant_id"] == mid].iloc[0]

        mtx = bundle.tx[bundle.tx["merchant_id"] == mid]
        cb_ratio = (mtx["is_chargeback"].sum() / len(mtx)) if len(mtx) else 0.0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Primary MCC", str(mrow["primary_mcc"]))
        m2.metric("Risk rating", str(mrow["risk_rating"]))
        m3.metric("OFAC match score", f"{mrow['ofac_match_score']:.2f}"
                  if pd.notna(mrow["ofac_match_score"]) else "—")
        m4.metric("Chargeback ratio", f"{cb_ratio*100:.1f}%")

        st.markdown(f"**Legal / DBA:** {mrow['legal_name']} / {mrow['dba_name']}  \n"
                    f"**Incorporation country:** {mrow['incorporation_country']}  \n"
                    f"**High-risk MCC flag:** {mrow['high_risk_mcc_flag']}  ·  "
                    f"**PEP UBO flag:** {mrow['pep_ubo_flag']}  \n"
                    f"**Expected monthly vol.:** ${mrow['expected_monthly_volume_usd']:,.0f}")

        with st.expander("Beneficial owners (UBO JSON)"):
            st.code(str(mrow["beneficial_owners_json"]), language="json")

        st.markdown(f"**Transactions ({len(mtx):,})**")
        if len(mtx):
            mtx_s = mtx.sort_values("txn_timestamp_utc")
            fig = px.scatter(mtx_s, x="txn_timestamp_utc", y="amount_usd", color="status",
                             hover_data=["txn_id", "customer_id", "channel", "is_chargeback"],
                             labels={"txn_timestamp_utc": "Time", "amount_usd": "Amount (USD)"})
            fig.update_layout(height=320, margin=dict(t=10, b=10), legend_title_text="Status")
            st.plotly_chart(fig, width='stretch')
            st.dataframe(
                mtx_s[["txn_id", "txn_timestamp_utc", "customer_id", "mcc", "channel",
                       "amount_usd", "status", "is_chargeback"]],
                width='stretch', height=280)

# ===========================================================================
# TAB 3 — ALERT SIMULATOR
# ===========================================================================
with tab_sim:
    st.subheader("Threshold simulator")
    st.caption("Sliders re-run the structuring and device-sharing detectors against "
               "the in-session dataset in real time. Baseline = case default thresholds.")

    sim_l, sim_r = st.columns(2)

    # ----- Structuring -----------------------------------------------------
    with sim_l:
        st.markdown("#### Structuring (T01)")
        band = st.slider("Amount band (USD)", 900.0, 1000.0, (980.0, 995.0), step=1.0)
        win_days = st.slider("Look-back window (days)", 1, 30, 7)
        min_txns = st.slider("Min. transactions in window", 2, 8, 3)

        sim = de.count_structuring_alerts(bundle.txe, band[0], band[1], win_days, min_txns)
        base = de.count_structuring_alerts(bundle.txe, 980.0, 995.0, 7, 3)

        a, b = st.columns(2)
        a.metric("Alerting customers", sim["alert_customers"],
                 delta=sim["alert_customers"] - base["alert_customers"])
        b.metric("In-band transactions", f"{sim['in_band_txns']:,}",
                 delta=sim["in_band_txns"] - base["in_band_txns"])
        st.caption(f"Baseline (980–995, 7d, ≥3): {base['alert_customers']} customers, "
                   f"{base['in_band_txns']:,} in-band txns.")
        if sim["customer_ids"]:
            st.write("Flagged customer_ids:", ", ".join(sim["customer_ids"]))

    # ----- Device sharing --------------------------------------------------
    with sim_r:
        st.markdown("#### Device sharing / mule ring (T03)")
        ds_win = st.slider("Sliding window (minutes)", 15, 240, 60, step=5)
        ds_min = st.slider("Min. distinct customers on device", 2, 12, 3)
        ds_hold = st.slider("Hard-block floor (customers)", 3, 12, 5)

        sim = de.count_device_sharing_alerts(bundle.txe, ds_win, ds_min, ds_hold)
        base = de.count_device_sharing_alerts(bundle.txe, 60, 3, 5)

        a, b, c = st.columns(3)
        a.metric("Alerting devices", sim["alert_devices"],
                 delta=sim["alert_devices"] - base["alert_devices"])
        b.metric("Hard blocks", sim["hard_blocks"],
                 delta=sim["hard_blocks"] - base["hard_blocks"])
        c.metric("Max customers / device", sim["max_customers"],
                 delta=sim["max_customers"] - base["max_customers"])
        st.caption(f"Baseline (60 min, ≥3, hold 5): {base['alert_devices']} device(s), "
                   f"max {base['max_customers']} customers.")
        if sim["max_customers"] >= 12:
            st.info("At this window the flagship ring surfaces its full 12-customer "
                    "extent (the strict 60-min window caps at 11 by a boundary margin — "
                    "the 12 txns span 66 minutes end-to-end).")
        if sim["device_ids"]:
            st.write("Flagged device_ids:", ", ".join(map(str, sim["device_ids"])))

# ===========================================================================
# TAB 4 — EDD POPULATION
# ===========================================================================
with tab_edd:
    st.subheader("Enhanced Due Diligence — flagged population")
    e1, e2, e3 = st.columns(3)
    e1.metric("EDD population", f"{len(edd_pop):,}",
              help="Customers triggering ≥1 EDD criterion (A–K).")
    e2.metric("URGENT", int((edd_pop["urgency"] == "URGENT").sum()) if len(edd_pop) else 0)
    e3.metric("HIGH", int((edd_pop["urgency"] == "HIGH").sum()) if len(edd_pop) else 0)

    urgency_filter = st.multiselect("Filter by urgency", ["URGENT", "HIGH", "MEDIUM"],
                                    default=["URGENT", "HIGH"])
    view = edd_pop[edd_pop["urgency"].isin(urgency_filter)] if len(edd_pop) else edd_pop
    st.dataframe(
        view[["customer_id", "full_name", "country", "kyc_level", "risk_rating",
              "pep_flag", "sanctions_match_score", "doc_issue_country",
              "expected_monthly_volume_usd", "criteria_codes", "urgency", "deadline"]],
        width='stretch', height=460)

st.divider()
st.caption("Detection logic imported from `detection_engine` (extraction of Section4b "
           "typology engine + Section2a EDD script). FPR shown is a monitoring-model "
           "proxy, not a QA-validated disposition rate. SAR confidentiality "
           "(31 U.S.C. § 5318(g)(2)) applies to all downstream case handling.")
