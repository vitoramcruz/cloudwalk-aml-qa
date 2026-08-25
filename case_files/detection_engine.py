"""
detection_engine.py
CloudWalk Payments Inc. — AML/CTF Monitoring — Importable Detection Engine
=========================================================================

WHAT THIS MODULE IS
-------------------
This is the *importable* form of the two tested case scripts:

  * Section2a_EDD_Customer_List_Analysis_Script.py   (EDD population detection)
  * Section4b_Typology_Analysis_Script.py            (11-typology suspect engine)

The original scripts are monolithic "run-on-import" programs that hardcode
thresholds as module constants, read a fixed workbook path, and write Excel
outputs at import time. That makes them impossible to `import` cleanly and
impossible to re-run with tuned thresholds (which the dashboard's live alert
simulator needs).

This module lifts the SAME detection logic and the SAME default parameters
out of those scripts, verbatim where the logic is pure, and exposes them as
callable functions that take (dataframes, params) as arguments. No detection
rule was re-derived or re-tuned: the sliding-window anchor pattern, the EDD
A–K criteria, the 11 typologies, the composite weight table, the
diversification bonus and the OFAC regulatory-escalation floor are all carried
over unchanged. The only additions are (a) parameterization so the simulator
can vary structuring band / device-sharing window, and (b) a population
guard-rail that reconciles real ID counts (501 / 100 / 630) against the
openpyxl padded-range artifact (ws.max_row can report ~999 blank-padded rows).

All code, comments and output labels are in English.
"""

from __future__ import annotations

import json
import re
import warnings
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Optional

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# Fuzzy matching (Typology 10) is optional; degrade gracefully if unavailable.
try:
    from rapidfuzz import fuzz
    _HAS_RAPIDFUZZ = True
except Exception:  # pragma: no cover
    _HAS_RAPIDFUZZ = False


# ===========================================================================
# EXPECTED POPULATIONS (population validation guard-rail — Playbook Section 0)
# ===========================================================================
EXPECTED_CUSTOMERS = 501
EXPECTED_MERCHANTS = 100
EXPECTED_CARDS = 630

SHEET_TRANSACTIONS = "Transactions"
SHEET_CUSTOMERS = "Customers_KYC"
SHEET_MERCHANTS = "Merchants_KYB"
SHEET_CARDS = "Cards"

HIGH_RISK_MCCS = [4829, 5944, 5967, 6011, 6051, 7995]


# ===========================================================================
# PARAMETER OBJECTS (documented defaults == the values used in the case)
# ===========================================================================
@dataclass
class TypologyParams:
    """Thresholds for the 11-typology engine. Defaults reproduce Section4b."""
    analysis_date: pd.Timestamp = pd.Timestamp("2025-11-07T23:59:59Z")

    # T01 Structuring
    struct_min_txns: int = 3
    struct_low: float = 980.00
    struct_high: float = 995.00
    struct_window_days: int = 7

    # T02 Card testing
    ct_min_attempts: int = 5
    ct_window_minutes: int = 30
    ct_threshold: float = 5.00
    ct_min_merchants: int = 3

    # T03 Device sharing / mule ring
    ds_min_customers: int = 3
    ds_hold_customers: int = 5
    ds_window_minutes: int = 60

    # T04 Geo-hopping cross-border
    gh_min_xborder_txns: int = 3

    # T05 PEP + high-risk MCC
    pep_ticket_multiplier: float = 2.0

    # T06 ECOM without 3DS
    ecom3ds_min: int = 5

    # T07 Chargeback outlier
    cb_alert_threshold: float = 0.05

    # T08 Cash-in / cash-out (tightened calibration per brief)
    cio_window_hours: int = 72
    cio_min_leg_usd: float = 500.00
    cio_ratio: float = 0.80

    # T09 IP ring
    ip_min_customers: int = 3

    # T10 Self-merchant
    self_merchant_fuzzy_threshold: int = 88

    # T11 FATF / OFAC jurisdiction
    ofac_block_countries: tuple = ("IR", "KP", "SY", "CU")
    fatf_grey_countries: tuple = ("VE",)


@dataclass
class EddParams:
    """EDD A–K triggering criteria. Defaults reproduce Section2a."""
    analysis_date: str = "2025-11-07"
    sanctions_score_threshold: float = 0.5          # A
    high_volume_threshold: float = 5000             # K
    very_high_volume_threshold: float = 10000       # F
    kyc_refresh_months: int = 12                    # G
    ofac_comprehensive_countries: tuple = ("IR", "KP", "SY", "CU", "SD")        # E
    ofac_comprehensive_strict: tuple = ("IR", "KP", "SY", "CU")                 # I
    iran_nexus_sanctions_score: float = 0.3         # I
    fatf_grey_country: str = "VE"                   # H


# Composite score weights — carried over verbatim from Section4b.
TYPOLOGY_WEIGHTS = {
    "T11_FATF_OFAC_JURISDICTION": 32,
    "T10_SELF_MERCHANT": 25,
    "T03_DEVICE_SHARING": 20,
    "T09_IP_RING": 18,
    "T08_CASH_IN_CASH_OUT": 16,
    "T01_STRUCTURING": 16,
    "T05_PEP_HIGH_RISK_MCC": 13,
    "T02_CARD_TESTING": 10,
    "T04_GEO_HOPPING_XBORDER": 10,
    "T06_ECOM_NO_3DS": 8,
    "T07_CHARGEBACK_OUTLIER": 8,
}

TYPOLOGY_LABELS = {
    "T01_STRUCTURING": "Structuring",
    "T02_CARD_TESTING": "Card testing",
    "T03_DEVICE_SHARING": "Device sharing / mule ring",
    "T04_GEO_HOPPING_XBORDER": "Geo-hopping cross-border",
    "T05_PEP_HIGH_RISK_MCC": "PEP + high-risk MCC",
    "T06_ECOM_NO_3DS": "ECOM without 3DS",
    "T07_CHARGEBACK_OUTLIER": "Chargeback outlier",
    "T08_CASH_IN_CASH_OUT": "Cash-in / cash-out",
    "T09_IP_RING": "IP ring",
    "T10_SELF_MERCHANT": "Self-merchant (undisclosed UBO)",
    "T11_FATF_OFAC_JURISDICTION": "FATF / OFAC jurisdiction",
}


# ===========================================================================
# DATA BUNDLE + INGESTION (with population guard-rail)
# ===========================================================================
@dataclass
class DataBundle:
    tx: pd.DataFrame
    cust: pd.DataFrame
    merch: pd.DataFrame
    cards: pd.DataFrame
    txe: pd.DataFrame                      # enriched transactions
    validation: dict = field(default_factory=dict)


def _load_real_rows(xls: pd.ExcelFile, sheet: str) -> pd.DataFrame:
    """Load a sheet and drop fully-blank padding rows.

    openpyxl/pandas may report a padded range larger than the real data
    (ws.max_row ~= 999). Reconciling on non-null rows restores the true
    population and prevents understating risk concentration ~10x.
    """
    df = pd.read_excel(xls, sheet_name=sheet)
    df = df.dropna(how="all").reset_index(drop=True)
    return df


def load_and_validate(path_or_buffer) -> DataBundle:
    """Load the AML workbook, reconcile real populations, and enrich txns.

    `path_or_buffer` may be a filesystem path or an uploaded file-like object
    (e.g. Streamlit's UploadedFile). Returns a DataBundle whose `.validation`
    dict reports observed vs. expected counts and pass/fail flags.
    """
    xls = pd.ExcelFile(path_or_buffer)

    tx = _load_real_rows(xls, SHEET_TRANSACTIONS)
    cust = _load_real_rows(xls, SHEET_CUSTOMERS)
    merch = _load_real_rows(xls, SHEET_MERCHANTS)
    cards = _load_real_rows(xls, SHEET_CARDS)

    # Reconcile on distinct IDs (the authoritative population), not row count.
    n_cust = cust["customer_id"].nunique()
    n_merch = merch["merchant_id"].nunique()
    n_cards = cards["card_id"].nunique()

    validation = {
        "customers": {"observed": int(n_cust), "expected": EXPECTED_CUSTOMERS,
                      "ok": int(n_cust) == EXPECTED_CUSTOMERS},
        "merchants": {"observed": int(n_merch), "expected": EXPECTED_MERCHANTS,
                      "ok": int(n_merch) == EXPECTED_MERCHANTS},
        "cards": {"observed": int(n_cards), "expected": EXPECTED_CARDS,
                  "ok": int(n_cards) == EXPECTED_CARDS},
        "transactions": {"observed": int(len(tx)), "expected": None, "ok": True},
    }
    validation["all_ok"] = all(v["ok"] for k, v in validation.items()
                               if k != "all_ok")

    # Type coercion
    tx["txn_timestamp_utc"] = pd.to_datetime(tx["txn_timestamp_utc"], errors="coerce")
    cust["created_at"] = pd.to_datetime(cust.get("created_at"), errors="coerce")
    merch["onboarding_date"] = pd.to_datetime(merch.get("onboarding_date"), errors="coerce")

    txe = _enrich(tx, cust, merch, cards)
    return DataBundle(tx=tx, cust=cust, merch=merch, cards=cards, txe=txe,
                      validation=validation)


def _enrich(tx, cust, merch, cards) -> pd.DataFrame:
    """Attach merchant + customer attributes to every transaction (Section4b)."""
    merch_small = merch[[
        "merchant_id", "dba_name", "primary_mcc", "high_risk_mcc_flag",
        "risk_rating", "beneficial_owners_json", "ofac_match_score",
        "incorporation_country",
    ]].rename(columns={"risk_rating": "merchant_risk_rating"})

    cust_small = cust[[
        "customer_id", "full_name", "country", "doc_issue_country", "pep_flag",
        "sanctions_match_score", "risk_rating", "expected_avg_ticket_usd",
        "expected_monthly_volume_usd", "kyc_level",
    ]].rename(columns={"risk_rating": "customer_risk_rating"})

    txe = tx.merge(merch_small, on="merchant_id", how="left")
    txe = txe.merge(cust_small, on="customer_id", how="left")
    return txe


# ===========================================================================
# CORE SLIDING-WINDOW PRIMITIVE (verbatim from Section4b)
# ===========================================================================
def sliding_window_group(df, group_col, ts_col, window, min_events,
                         extra_qualify: Optional[Callable] = None,
                         select: str = "earliest",
                         rank_key: Optional[Callable] = None):
    """Anchor-row -> forward-window aggregate, replicating the Task 3.1 SQL.

    For each row, look forward `window` within the same group, collect rows in
    that span, and keep groups whose window satisfies `min_events`.

    select="earliest" -> keep first qualifying window (Query 1/Query 3 style).
    select="best"     -> keep window maximizing rank_key (Query 2 style).
    """
    results = []
    for gval, gdf in df.groupby(group_col):
        gdf = gdf.sort_values(ts_col).reset_index(drop=True)
        ts = gdf[ts_col].values
        n = len(gdf)
        qualifying = []
        for i in range(n):
            end_ts = ts[i] + np.timedelta64(int(window.total_seconds()), "s")
            j = i
            while j < n and ts[j] <= end_ts:
                j += 1
            window_df = gdf.iloc[i:j]
            if extra_qualify is not None and not extra_qualify(window_df):
                continue
            if len(window_df) >= min_events:
                qualifying.append(window_df)
                if select == "earliest":
                    break
        if not qualifying:
            continue
        if select == "earliest":
            results.append((gval, qualifying[0]))
        else:
            best_df = max(qualifying, key=rank_key)
            results.append((gval, best_df))
    return results


# ===========================================================================
# EDD POPULATION DETECTION (extracted from Section2a)
# ===========================================================================
def run_edd(cust: pd.DataFrame, cards: pd.DataFrame,
            params: EddParams = EddParams()) -> pd.DataFrame:
    """Apply EDD criteria A–K and return the flagged population with urgency,
    corrected risk rating, docs required and deadline (Section2a logic)."""
    customers = cust.copy()
    analysis_date = pd.Timestamp(params.analysis_date)
    customers["last_kyc_refresh_dt"] = pd.to_datetime(customers["last_kyc_refresh"], errors="coerce")
    customers["months_since_refresh"] = (
        (analysis_date - customers["last_kyc_refresh_dt"]).dt.days / 30.44
    )

    blocked_pep_customers = set(
        cards.loc[cards["status"] == "blocked", "customer_id"].unique()
    )

    OFAC = list(params.ofac_comprehensive_countries)
    OFAC_STRICT = list(params.ofac_comprehensive_strict)

    def evaluate(row):
        t = []
        if row["sanctions_match_score"] > params.sanctions_score_threshold:
            t.append(f"A: sanctions_match_score={row['sanctions_match_score']:.2f} > 0.5")
        if row["pep_flag"] == True:  # noqa: E712
            t.append("B: pep_flag=True")
        if row["country"] != "US":
            t.append(f"C: country={row['country']} (non-US)")
        if row["kyc_level"] == "basic" and row["risk_rating"] == "high":
            t.append("D: kyc_level=basic AND risk_rating=high")
        if row["doc_issue_country"] in OFAC:
            t.append(f"E: doc_issue_country={row['doc_issue_country']} (OFAC comprehensive)")
        if row["expected_monthly_volume_usd"] > params.very_high_volume_threshold and row["kyc_level"] != "enhanced":
            t.append(f"F: expected_monthly_volume_usd=${row['expected_monthly_volume_usd']:,.0f} > $10,000, kyc_level={row['kyc_level']}")
        if row["months_since_refresh"] > params.kyc_refresh_months:
            t.append(f"G: last_kyc_refresh={row['last_kyc_refresh']} ({row['months_since_refresh']:.1f} months ago)")
        if row["country"] == params.fatf_grey_country:
            t.append("H: country=VE (FATF Grey List Oct 2025)")
        if row["doc_issue_country"] in OFAC_STRICT and row["sanctions_match_score"] > params.iran_nexus_sanctions_score:
            t.append(f"I: doc_issue_country={row['doc_issue_country']} AND sanctions_match_score={row['sanctions_match_score']:.2f} > 0.3")
        if row["customer_id"] in blocked_pep_customers and row["pep_flag"] == True:  # noqa: E712
            t.append("J: has blocked card AND pep_flag=True")
        if row["expected_monthly_volume_usd"] > params.high_volume_threshold and row["kyc_level"] in ["basic", "standard"]:
            t.append(f"K: expected_monthly_volume_usd=${row['expected_monthly_volume_usd']:,.0f} > $5,000, kyc_level={row['kyc_level']}")
        return t

    customers["criteria_triggered"] = customers.apply(evaluate, axis=1)
    customers["n_criteria"] = customers["criteria_triggered"].apply(len)
    customers["criteria_codes"] = customers["criteria_triggered"].apply(
        lambda lst: ", ".join([c.split(":")[0] for c in lst]))
    customers["criteria_detail"] = customers["criteria_triggered"].apply(lambda lst: " | ".join(lst))

    edd = customers[customers["n_criteria"] >= 1].copy()

    def urgency(row):
        codes = set(row["criteria_codes"].split(", ")) if row["criteria_codes"] else set()
        if row["sanctions_match_score"] > 0.7 or "E" in codes or "I" in codes or "J" in codes:
            return "URGENT"
        if "B" in codes or "H" in codes or "D" in codes:
            return "HIGH"
        return "MEDIUM"

    def deadline(row):
        return {"URGENT": "24-48 hours", "HIGH": "7 calendar days"}.get(row["urgency"], "30 calendar days")

    edd["urgency"] = edd.apply(urgency, axis=1)
    edd["deadline"] = edd.apply(deadline, axis=1)

    order = {"URGENT": 0, "HIGH": 1, "MEDIUM": 2}
    edd["urgency_sort"] = edd["urgency"].map(order)
    edd = edd.sort_values(
        by=["urgency_sort", "sanctions_match_score", "expected_monthly_volume_usd"],
        ascending=[True, False, False]).drop(columns=["urgency_sort"])
    return edd.reset_index(drop=True)


# ===========================================================================
# TYPOLOGY ENGINE (extracted from Section4b, parameterized)
# ===========================================================================
def run_all_typologies(bundle: DataBundle, params: TypologyParams = TypologyParams()) -> dict:
    """Run all 11 typologies, build composite customer ranking, and return a
    result dict:

      {
        "tables":        {typology_key: DataFrame, ...},
        "customer_hits": DataFrame,     # customer_id, typology, weight, evidence, txn_ids
        "txn_hits":      DataFrame,      # txn_id, typology, weight, note (+ ts/customer merged)
        "cust_score":    DataFrame,      # ranked customers w/ final_score, typologies, KYC
        "portfolio_chargeback_ratio": float,
      }
    """
    txe = bundle.txe
    cust = bundle.cust
    merch = bundle.merch
    HR = HIGH_RISK_MCCS
    W = TYPOLOGY_WEIGHTS

    TABLES: dict = {}
    CUSTOMER_HITS: list = []
    TXN_HITS: list = []

    dataset_max_ts = txe["txn_timestamp_utc"].max()

    # ---- T01 Structuring ---------------------------------------------------
    band = txe[(txe["amount_usd"].between(params.struct_low, params.struct_high))
               & (txe["mcc"].isin(HR))]
    struct_windows = sliding_window_group(
        band, "customer_id", "txn_timestamp_utc",
        timedelta(days=params.struct_window_days), params.struct_min_txns)
    rows = []
    for cid, wdf in struct_windows:
        rows.append({"customer_id": cid, "window_start": wdf["txn_timestamp_utc"].min(),
                     "window_end": wdf["txn_timestamp_utc"].max(), "txns_in_window": len(wdf),
                     "total_amount_in_window": wdf["amount_usd"].sum(),
                     "mccs_in_window": sorted(wdf["mcc"].unique().tolist()),
                     "txn_ids": ",".join(wdf["txn_id"].tolist())})
        weight = W["T01_STRUCTURING"] * min(1.5, 1 + 0.1 * (len(wdf) - params.struct_min_txns))
        CUSTOMER_HITS.append({"customer_id": cid, "typology": "T01_STRUCTURING", "weight": weight,
                              "evidence": f"{len(wdf)} txns in ${params.struct_low}-${params.struct_high} band within {params.struct_window_days}d",
                              "txn_ids": wdf["txn_id"].tolist()})
        for _, r in wdf.iterrows():
            TXN_HITS.append({"txn_id": r["txn_id"], "typology": "T01_STRUCTURING",
                             "weight": weight / len(wdf), "note": f"Structuring window ({len(wdf)} txns)"})
    TABLES["T01_Structuring"] = pd.DataFrame(rows)

    # ---- T02 Card testing --------------------------------------------------
    low_ecom = txe[(txe["channel"] == "ECOM") & (txe["amount_usd"] < params.ct_threshold)]
    card_windows = sliding_window_group(
        low_ecom, "card_id", "txn_timestamp_utc",
        timedelta(minutes=params.ct_window_minutes), params.ct_min_attempts,
        extra_qualify=lambda w: (w["merchant_id"].nunique() >= params.ct_min_merchants)
                                and (w["status"] == "approved").any())
    rows = []
    for card_id, wdf in card_windows:
        cid = wdf["customer_id"].iloc[0]
        rows.append({"card_id": card_id, "customer_id": cid, "attempts_in_window": len(wdf),
                     "distinct_merchants": wdf["merchant_id"].nunique(),
                     "window_start": wdf["txn_timestamp_utc"].min(),
                     "window_end": wdf["txn_timestamp_utc"].max(),
                     "txn_ids": ",".join(wdf["txn_id"].tolist())})
        weight = W["T02_CARD_TESTING"] * min(1.5, 1 + 0.05 * (len(wdf) - params.ct_min_attempts))
        CUSTOMER_HITS.append({"customer_id": cid, "typology": "T02_CARD_TESTING", "weight": weight,
                              "evidence": f"{len(wdf)} sub-${params.ct_threshold:.0f} ECOM attempts on {card_id} across {wdf['merchant_id'].nunique()} merchants",
                              "txn_ids": wdf["txn_id"].tolist()})
        for _, r in wdf.iterrows():
            TXN_HITS.append({"txn_id": r["txn_id"], "typology": "T02_CARD_TESTING",
                             "weight": weight / len(wdf), "note": f"Card-testing burst ({len(wdf)}/30min)"})
    TABLES["T02_Card_Testing"] = pd.DataFrame(rows)

    # ---- T03 Device sharing / mule ring ------------------------------------
    dev_txns = txe[(txe["mcc"].isin(HR)) & (txe["device_id"].notna())]
    dev_windows = sliding_window_group(
        dev_txns, "device_id", "txn_timestamp_utc",
        timedelta(minutes=params.ds_window_minutes), params.ds_min_customers,
        extra_qualify=lambda w: w["customer_id"].nunique() >= params.ds_min_customers,
        select="best", rank_key=lambda w: w["customer_id"].nunique())
    rows = []
    for dev, wdf in dev_windows:
        n = wdf["customer_id"].nunique()
        atype = "DEVICE_SHARING_HARD_BLOCK" if n >= params.ds_hold_customers else "DEVICE_SHARING_ALERT"
        rows.append({"alert_type": atype, "device_id": dev, "distinct_customers": n,
                     "window_start": wdf["txn_timestamp_utc"].min(),
                     "window_end": wdf["txn_timestamp_utc"].max(),
                     "customer_ids": ",".join(sorted(wdf["customer_id"].unique().tolist())),
                     "txn_ids": ",".join(wdf["txn_id"].tolist())})
        scaled = W["T03_DEVICE_SHARING"] * min(1.6, 1 + 0.08 * (n - params.ds_min_customers))
        for cid in wdf["customer_id"].unique():
            ctx = wdf.loc[wdf["customer_id"] == cid, "txn_id"].tolist()
            CUSTOMER_HITS.append({"customer_id": cid, "typology": "T03_DEVICE_SHARING", "weight": scaled,
                                  "evidence": f"Shared device {dev} with {n} customers within {params.ds_window_minutes}min ({atype})",
                                  "txn_ids": ctx})
        for _, r in wdf.iterrows():
            TXN_HITS.append({"txn_id": r["txn_id"], "typology": "T03_DEVICE_SHARING",
                             "weight": scaled / len(wdf), "note": f"{atype} ({n} customers)"})
    # Confirmed full-session reconciliation for MCC 4829 (boundary artifact)
    mcc4829 = txe[txe["mcc"] == 4829].groupby("device_id")["customer_id"].nunique()
    ds_df_tmp = pd.DataFrame(rows)
    for dev, raw_n in mcc4829[mcc4829 >= params.ds_hold_customers].items():
        windowed = ds_df_tmp.loc[ds_df_tmp["device_id"] == dev, "distinct_customers"].max() if len(ds_df_tmp) else 0
        windowed = 0 if pd.isna(windowed) else windowed
        if raw_n > windowed:
            full = txe[(txe["device_id"] == dev) & (txe["mcc"] == 4829)]
            rows.append({"alert_type": "DEVICE_SHARING_HARD_BLOCK_FULL_SESSION", "device_id": dev,
                         "distinct_customers": int(raw_n),
                         "window_start": full["txn_timestamp_utc"].min(),
                         "window_end": full["txn_timestamp_utc"].max(),
                         "customer_ids": ",".join(sorted(full["customer_id"].unique().tolist())),
                         "txn_ids": ",".join(full["txn_id"].tolist())})
            scaled = W["T03_DEVICE_SHARING"] * 1.6
            for cid in full["customer_id"].unique():
                ctx = full.loc[full["customer_id"] == cid, "txn_id"].tolist()
                CUSTOMER_HITS.append({"customer_id": cid, "typology": "T03_DEVICE_SHARING", "weight": scaled,
                                      "evidence": f"Full coordinated session on {dev} (MCC 4829): {int(raw_n)} customers",
                                      "txn_ids": ctx})
    TABLES["T03_Device_Sharing"] = pd.DataFrame(rows)

    # ---- T04 Geo-hopping cross-border --------------------------------------
    xb_hr = txe[(txe["mcc"].isin(HR)) & (txe["merchant_country"] != "US")]
    all_hr = txe[txe["mcc"].isin(HR)]
    per_hr = all_hr.groupby("customer_id").agg(hr_txn_count=("txn_id", "count")).reset_index()
    per_xb = xb_hr.groupby("customer_id").agg(
        hr_xb_txn_count=("txn_id", "count"), hr_xb_amount=("amount_usd", "sum"),
        countries=("merchant_country", lambda s: sorted(s.unique().tolist())),
        txn_ids=("txn_id", lambda s: s.tolist())).reset_index()
    gh = per_hr.merge(per_xb, on="customer_id", how="inner")
    gh["xborder_share"] = gh["hr_xb_txn_count"] / gh["hr_txn_count"]
    gh = gh[gh["hr_xb_txn_count"] >= params.gh_min_xborder_txns]
    TABLES["T04_Geo_Hopping_XBorder"] = gh
    for _, r in gh.iterrows():
        mult = (1.0 + 0.4 * r["xborder_share"]) * min(1.3, 1 + 0.02 * (r["hr_xb_txn_count"] - 3))
        weight = W["T04_GEO_HOPPING_XBORDER"] * mult
        CUSTOMER_HITS.append({"customer_id": r["customer_id"], "typology": "T04_GEO_HOPPING_XBORDER",
                              "weight": weight,
                              "evidence": f"{r['hr_xb_txn_count']} high-risk-MCC cross-border txns ({r['xborder_share']*100:.0f}% share)",
                              "txn_ids": r["txn_ids"]})
        pw = weight / len(r["txn_ids"])
        for tid in r["txn_ids"]:
            TXN_HITS.append({"txn_id": tid, "typology": "T04_GEO_HOPPING_XBORDER", "weight": pw,
                             "note": "Geo-hopping cross-border"})

    # ---- T05 PEP + high-risk MCC -------------------------------------------
    pep_hr = txe[(txe["pep_flag"] == True) & (txe["high_risk_mcc_flag"] == True)].copy()  # noqa: E712
    pep_hr["ticket_multiple"] = pep_hr["amount_usd"] / pep_hr["expected_avg_ticket_usd"].replace(0, np.nan)
    pep_alert = pep_hr[pep_hr["ticket_multiple"] > params.pep_ticket_multiplier]
    TABLES["T05_PEP_High_Risk_MCC"] = pep_alert[[
        "txn_id", "customer_id", "full_name", "expected_avg_ticket_usd", "amount_usd",
        "ticket_multiple", "merchant_id", "dba_name", "mcc", "txn_timestamp_utc"]]
    pep_cust = pep_alert.groupby("customer_id").agg(
        pep_txn_count=("txn_id", "count"), max_ticket_multiple=("ticket_multiple", "max"),
        total_amount=("amount_usd", "sum"), txn_ids=("txn_id", lambda s: s.tolist())).reset_index()
    for _, r in pep_cust.iterrows():
        mult = min(1.8, 1 + 0.06 * (r["max_ticket_multiple"] - params.pep_ticket_multiplier) + 0.03 * (r["pep_txn_count"] - 1))
        weight = W["T05_PEP_HIGH_RISK_MCC"] * mult
        CUSTOMER_HITS.append({"customer_id": r["customer_id"], "typology": "T05_PEP_HIGH_RISK_MCC",
                              "weight": weight,
                              "evidence": f"PEP: {r['pep_txn_count']} txn(s) > 2x expected ticket (max {r['max_ticket_multiple']:.1f}x)",
                              "txn_ids": r["txn_ids"]})
    for _, r in pep_alert.iterrows():
        tw = W["T05_PEP_HIGH_RISK_MCC"] * min(1.6, 1 + 0.05 * (r["ticket_multiple"] - params.pep_ticket_multiplier))
        TXN_HITS.append({"txn_id": r["txn_id"], "typology": "T05_PEP_HIGH_RISK_MCC", "weight": tw,
                         "note": f"PEP at high-risk MCC {r['mcc']} ({r['ticket_multiple']:.1f}x)"})

    # ---- T06 ECOM without 3DS ----------------------------------------------
    keyed_hr = txe[(txe["channel"] == "ECOM") & (txe["pos_entry_mode"] == "KEYED")
                   & (txe["high_risk_mcc_flag"] == True)]  # noqa: E712
    ecom = keyed_hr.groupby("customer_id").agg(
        keyed_txn_count=("txn_id", "count"),
        keyed_xborder_count=("merchant_country", lambda s: (s != "US").sum()),
        total_amount=("amount_usd", "sum"), txn_ids=("txn_id", lambda s: s.tolist())).reset_index()
    ecom = ecom[ecom["keyed_txn_count"] >= params.ecom3ds_min]
    ecom["alert_type"] = np.where(ecom["keyed_xborder_count"] > 0,
                                  "ECOM_NO_3DS_HIGH_RISK_XBORDER_DOUBLE_RISK", "ECOM_NO_3DS_HIGH_RISK_MCC")
    TABLES["T06_ECOM_No_3DS"] = ecom.drop(columns=["txn_ids"])
    for _, r in ecom.iterrows():
        double = r["keyed_xborder_count"] > 0
        mult = (1.3 if double else 1.0) * min(1.5, 1 + 0.04 * (r["keyed_txn_count"] - params.ecom3ds_min))
        weight = W["T06_ECOM_NO_3DS"] * mult
        CUSTOMER_HITS.append({"customer_id": r["customer_id"], "typology": "T06_ECOM_NO_3DS", "weight": weight,
                              "evidence": f"{r['keyed_txn_count']} KEYED (no-3DS) ECOM txns at high-risk MCC",
                              "txn_ids": r["txn_ids"]})
        pw = weight / len(r["txn_ids"])
        for tid in r["txn_ids"]:
            TXN_HITS.append({"txn_id": tid, "typology": "T06_ECOM_NO_3DS", "weight": pw,
                             "note": "KEYED/no-3DS at high-risk MCC"})

    # ---- T07 Chargeback outlier (merchant-level, customers linked) ---------
    mr = txe.groupby("merchant_id").agg(total_txns=("txn_id", "count"),
                                        chargebacks=("is_chargeback", "sum")).reset_index()
    mr["chargeback_ratio"] = mr["chargebacks"] / mr["total_txns"]
    mr = mr.merge(merch[["merchant_id", "dba_name"]], on="merchant_id", how="left")
    cb_out = mr[mr["chargeback_ratio"] > params.cb_alert_threshold].sort_values("chargeback_ratio", ascending=False)
    cb_out["alert_type"] = np.select(
        [cb_out["chargeback_ratio"] >= 0.08, cb_out["chargeback_ratio"] > 0.05],
        ["CHARGEBACK_RATIO_AUTO_SUSPEND", "CHARGEBACK_RATIO_RED_ESCALATION"],
        default="CHARGEBACK_RATIO_YELLOW_ALERT")
    portfolio_cb_ratio = float(txe["is_chargeback"].sum() / len(txe))
    TABLES["T07_Chargeback_Outlier"] = cb_out
    for _, m in cb_out.iterrows():
        cb_txns = txe[(txe["merchant_id"] == m["merchant_id"]) & (txe["is_chargeback"] == True)]  # noqa: E712
        for cid, g in cb_txns.groupby("customer_id"):
            weight = W["T07_CHARGEBACK_OUTLIER"] * min(1.5, 1 + 0.15 * (len(g) - 1))
            CUSTOMER_HITS.append({"customer_id": cid, "typology": "T07_CHARGEBACK_OUTLIER", "weight": weight,
                                  "evidence": f"{len(g)} chargeback(s) at outlier merchant {m['merchant_id']} ({m['chargeback_ratio']*100:.1f}%)",
                                  "txn_ids": g["txn_id"].tolist()})
            pw = weight / len(g)
            for tid in g["txn_id"].tolist():
                TXN_HITS.append({"txn_id": tid, "typology": "T07_CHARGEBACK_OUTLIER", "weight": pw,
                                 "note": f"Chargeback at outlier merchant {m['merchant_id']}"})

    # ---- T08 Cash-in / cash-out (tightened) --------------------------------
    win = timedelta(hours=params.cio_window_hours)
    atm = txe[(txe["mcc"] == 6011) & (txe["status"] == "approved") & (txe["amount_usd"] >= params.cio_min_leg_usd)]
    remit = txe[(txe["mcc"] == 4829) & (txe["status"] == "approved") & (txe["amount_usd"] >= params.cio_min_leg_usd)]
    pairs = []
    for cid, adf in atm.groupby("customer_id"):
        rdf = remit[remit["customer_id"] == cid]
        if rdf.empty:
            continue
        for _, a in adf.iterrows():
            wr = rdf[(rdf["txn_timestamp_utc"] > a["txn_timestamp_utc"])
                     & (rdf["txn_timestamp_utc"] <= a["txn_timestamp_utc"] + win)]
            for _, r in wr.iterrows():
                ratio = r["amount_usd"] / a["amount_usd"]
                if ratio >= params.cio_ratio:
                    pairs.append({"customer_id": cid, "atm_txn_id": a["txn_id"], "atm_amount": a["amount_usd"],
                                  "remit_txn_id": r["txn_id"], "remit_amount": r["amount_usd"],
                                  "hours_between": (r["txn_timestamp_utc"] - a["txn_timestamp_utc"]).total_seconds() / 3600,
                                  "observed_ratio": ratio})
    cio_df = pd.DataFrame(pairs)
    TABLES["T08_Cash_In_Cash_Out"] = cio_df
    if len(cio_df):
        pc = cio_df.groupby("customer_id").agg(
            pair_count=("atm_txn_id", "count"), max_ratio=("observed_ratio", "max"),
            min_hours=("hours_between", "min"),
            atm_ids=("atm_txn_id", lambda s: list(s)), remit_ids=("remit_txn_id", lambda s: list(s))).reset_index()
        for _, r in pc.iterrows():
            ids = r["atm_ids"] + r["remit_ids"]
            weight = W["T08_CASH_IN_CASH_OUT"] * min(1.8, 1 + 0.25 * (r["pair_count"] - 1) + 0.3 * (r["max_ratio"] - params.cio_ratio))
            CUSTOMER_HITS.append({"customer_id": r["customer_id"], "typology": "T08_CASH_IN_CASH_OUT", "weight": weight,
                                  "evidence": f"{r['pair_count']} ATM->remittance pair(s) <=72h, up to {r['max_ratio']*100:.0f}% ratio",
                                  "txn_ids": ids})
            pw = weight / len(ids)
            for tid in ids:
                TXN_HITS.append({"txn_id": tid, "typology": "T08_CASH_IN_CASH_OUT", "weight": pw,
                                 "note": "Cash-in/cash-out layering pair"})

    # ---- T09 IP ring -------------------------------------------------------
    ecom_ip = txe[(txe["channel"] == "ECOM") & (txe["ip_address"].notna())]
    ip_hr = ecom_ip[ecom_ip["high_risk_mcc_flag"] == True]  # noqa: E712
    ip_hr_agg = ip_hr.groupby("ip_address").agg(
        distinct_customers=("customer_id", "nunique"),
        customer_ids=("customer_id", lambda s: sorted(s.unique().tolist()))).reset_index()
    ip_hr_alert = ip_hr_agg[ip_hr_agg["distinct_customers"] >= params.ip_min_customers].copy()
    ip_hr_alert["alert_type"] = "IP_RING_HIGH_RISK_MCC"
    ip_gen_agg = ecom_ip.groupby("ip_address").agg(
        distinct_customers=("customer_id", "nunique"),
        customer_ids=("customer_id", lambda s: sorted(s.unique().tolist()))).reset_index()
    flagged = set(ip_hr_alert["ip_address"])
    ip_gen_alert = ip_gen_agg[(ip_gen_agg["distinct_customers"] >= params.ip_min_customers)
                              & (~ip_gen_agg["ip_address"].isin(flagged))].copy()
    ip_gen_alert["alert_type"] = "IP_RING_GENERAL"
    ip_ring = pd.concat([ip_hr_alert, ip_gen_alert], ignore_index=True).sort_values("distinct_customers", ascending=False)
    TABLES["T09_IP_Ring"] = ip_ring
    for _, r in ip_ring.iterrows():
        scaled = W["T09_IP_RING"] * min(1.6, 1 + 0.08 * (r["distinct_customers"] - params.ip_min_customers))
        if r["alert_type"] == "IP_RING_GENERAL":
            scaled *= 0.85
        ip_slice = ecom_ip[ecom_ip["ip_address"] == r["ip_address"]]
        for cid in r["customer_ids"]:
            ctx = ip_slice.loc[ip_slice["customer_id"] == cid, "txn_id"].tolist()
            CUSTOMER_HITS.append({"customer_id": cid, "typology": "T09_IP_RING", "weight": scaled,
                                  "evidence": f"Shared IP {r['ip_address']} with {r['distinct_customers']} customers ({r['alert_type']})",
                                  "txn_ids": ctx})
            for tid in ctx:
                TXN_HITS.append({"txn_id": tid, "typology": "T09_IP_RING", "weight": scaled / max(len(ctx), 1),
                                 "note": r["alert_type"]})

    # ---- T10 Self-merchant (name + DOB corroboration) ----------------------
    self_rows = []
    if _HAS_RAPIDFUZZ:
        ubo_rows = []
        for _, m in merch.iterrows():
            if pd.isna(m["beneficial_owners_json"]):
                continue
            try:
                ubos = json.loads(m["beneficial_owners_json"])
            except (json.JSONDecodeError, TypeError):
                continue
            for u in ubos:
                ubo_rows.append({"merchant_id": m["merchant_id"], "dba_name": m["dba_name"],
                                 "ubo_name": u.get("name"), "ubo_dob": u.get("dob"),
                                 "ownership_pct": u.get("ownership_pct")})
        ubo_df = pd.DataFrame(ubo_rows)

        def norm(s):
            return re.sub(r"[^a-z ]", "", str(s).lower()).strip()

        cn = cust[["customer_id", "full_name", "dob"]].copy()
        cn["norm"] = cn["full_name"].apply(norm)
        if len(ubo_df):
            ubo_df["norm"] = ubo_df["ubo_name"].apply(norm)
            for _, u in ubo_df.iterrows():
                for _, c in cn.iterrows():
                    sc = fuzz.token_sort_ratio(u["norm"], c["norm"])
                    if sc >= params.self_merchant_fuzzy_threshold and str(c["dob"]) == str(u["ubo_dob"]):
                        txns = txe[(txe["customer_id"] == c["customer_id"]) & (txe["merchant_id"] == u["merchant_id"])]
                        if len(txns):
                            self_rows.append({"customer_id": c["customer_id"], "merchant_id": u["merchant_id"],
                                              "ownership_pct": u["ownership_pct"], "txn_ids": txns["txn_id"].tolist()})
        for r in self_rows:
            mult = 1.2 * (1.3 if (pd.notna(r["ownership_pct"]) and r["ownership_pct"] >= 50) else 1.0)
            weight = W["T10_SELF_MERCHANT"] * min(1.7, mult)
            CUSTOMER_HITS.append({"customer_id": r["customer_id"], "typology": "T10_SELF_MERCHANT", "weight": weight,
                                  "evidence": f"DOB-corroborated UBO match at own merchant {r['merchant_id']}",
                                  "txn_ids": r["txn_ids"]})
    TABLES["T10_Self_Merchant"] = pd.DataFrame(self_rows)

    # ---- T11 FATF / OFAC jurisdiction --------------------------------------
    OFAC = list(params.ofac_block_countries)
    GREY = list(params.fatf_grey_countries)
    fatf = txe[(txe["merchant_country"] != "US")
               & (txe["country"].isin(OFAC + GREY) | txe["doc_issue_country"].isin(OFAC + GREY))].copy()
    fatf["alert_type"] = np.where(fatf["country"].isin(OFAC) | fatf["doc_issue_country"].isin(OFAC),
                                  "OFAC_SANCTIONED_JURISDICTION_XBORDER", "FATF_GREYLIST_JURISDICTION_XBORDER")
    TABLES["T11_FATF_OFAC_Jurisdiction"] = fatf[[
        "alert_type", "txn_id", "customer_id", "full_name", "country", "doc_issue_country",
        "merchant_id", "merchant_country", "mcc", "amount_usd", "txn_timestamp_utc", "sanctions_match_score"]]
    pf = fatf.groupby("customer_id").agg(
        txn_count=("txn_id", "count"), total_amount=("amount_usd", "sum"),
        alert_type=("alert_type", "first"), txn_ids=("txn_id", lambda s: s.tolist()),
        sanctions_match_score=("sanctions_match_score", "first")).reset_index()
    for _, r in pf.iterrows():
        is_ofac = r["alert_type"] == "OFAC_SANCTIONED_JURISDICTION_XBORDER"
        mult = (1.4 if is_ofac else 1.0) * ((1 + r["sanctions_match_score"]) if pd.notna(r["sanctions_match_score"]) else 1.0)
        weight = W["T11_FATF_OFAC_JURISDICTION"] * min(2.2, mult)
        CUSTOMER_HITS.append({"customer_id": r["customer_id"], "typology": "T11_FATF_OFAC_JURISDICTION", "weight": weight,
                              "evidence": f"{r['txn_count']} cross-border txn(s) ({r['alert_type']}), score={r['sanctions_match_score']}",
                              "txn_ids": r["txn_ids"]})
        pw = weight / len(r["txn_ids"])
        for tid in r["txn_ids"]:
            TXN_HITS.append({"txn_id": tid, "typology": "T11_FATF_OFAC_JURISDICTION", "weight": pw,
                             "note": r["alert_type"]})

    # ---- Composite scoring + regulatory escalation floor -------------------
    hits_df = pd.DataFrame(CUSTOMER_HITS)
    if len(hits_df):
        cust_score = hits_df.groupby("customer_id").agg(
            composite_score=("weight", "sum"), n_typology_hits=("typology", "count"),
            n_distinct_typologies=("typology", "nunique"),
            typologies=("typology", lambda s: sorted(set(s)))).reset_index()
        cust_score["diversification_multiplier"] = 1 + 0.15 * (cust_score["n_distinct_typologies"] - 1)
        cust_score["final_score"] = cust_score["composite_score"] * cust_score["diversification_multiplier"]
        cust_score = cust_score.sort_values("final_score", ascending=False).reset_index(drop=True)

        ofac_custs = set(cust.loc[cust["country"].isin(OFAC) | cust["doc_issue_country"].isin(OFAC), "customer_id"])
        if ofac_custs:
            floor = cust_score["final_score"].iloc[min(4, len(cust_score) - 1)] + 1.0
            esc = cust_score["customer_id"].isin(ofac_custs)
            cust_score.loc[esc, "regulatory_escalation_floor_applied"] = cust_score.loc[esc, "final_score"] < floor
            cust_score.loc[esc, "final_score"] = np.maximum(cust_score.loc[esc, "final_score"], floor)
            cust_score["regulatory_escalation_floor_applied"] = cust_score["regulatory_escalation_floor_applied"].fillna(False)
            cust_score = cust_score.sort_values("final_score", ascending=False).reset_index(drop=True)
        else:
            cust_score["regulatory_escalation_floor_applied"] = False

        cust_score = cust_score.merge(
            cust[["customer_id", "full_name", "country", "risk_rating", "pep_flag",
                  "kyc_level", "sanctions_match_score", "expected_monthly_volume_usd"]],
            on="customer_id", how="left")
        cust_score["rank"] = range(1, len(cust_score) + 1)
    else:
        cust_score = pd.DataFrame()

    # ---- Attach timestamps to txn hits (for the monthly-trend chart) -------
    txn_hits_df = pd.DataFrame(TXN_HITS)
    if len(txn_hits_df):
        ts_map = bundle.tx.set_index("txn_id")["txn_timestamp_utc"]
        cust_map = bundle.tx.set_index("txn_id")["customer_id"]
        txn_hits_df["txn_timestamp_utc"] = txn_hits_df["txn_id"].map(ts_map)
        txn_hits_df["customer_id"] = txn_hits_df["txn_id"].map(cust_map)

    return {"tables": TABLES, "customer_hits": hits_df, "txn_hits": txn_hits_df,
            "cust_score": cust_score, "portfolio_chargeback_ratio": portfolio_cb_ratio}


# ===========================================================================
# FAST SIMULATOR FUNCTIONS (single-typology recompute for live sliders)
# ===========================================================================
def count_structuring_alerts(txe: pd.DataFrame, low: float, high: float,
                             window_days: int, min_txns: int) -> dict:
    """Recompute the T01 structuring alert set for tuned thresholds. Returns
    {alert_customers, alert_windows, in_band_txns, customer_ids}."""
    band = txe[(txe["amount_usd"].between(low, high)) & (txe["mcc"].isin(HIGH_RISK_MCCS))]
    windows = sliding_window_group(band, "customer_id", "txn_timestamp_utc",
                                   timedelta(days=window_days), min_txns)
    ids = [cid for cid, _ in windows]
    return {"alert_customers": len(ids), "alert_windows": len(windows),
            "in_band_txns": int(len(band)), "customer_ids": ids}


def count_device_sharing_alerts(txe: pd.DataFrame, window_minutes: int,
                                min_customers: int, hold_customers: int = 5) -> dict:
    """Recompute the T03 device-sharing alert set for a tuned window / floor.
    Returns {alert_devices, hard_blocks, max_customers, device_ids}."""
    dev_txns = txe[(txe["mcc"].isin(HIGH_RISK_MCCS)) & (txe["device_id"].notna())]
    windows = sliding_window_group(
        dev_txns, "device_id", "txn_timestamp_utc",
        timedelta(minutes=window_minutes), min_customers,
        extra_qualify=lambda w: w["customer_id"].nunique() >= min_customers,
        select="best", rank_key=lambda w: w["customer_id"].nunique())
    devices, counts, hard = [], [], 0
    for dev, wdf in windows:
        n = wdf["customer_id"].nunique()
        devices.append(dev)
        counts.append(n)
        if n >= hold_customers:
            hard += 1
    return {"alert_devices": len(devices), "hard_blocks": hard,
            "max_customers": int(max(counts)) if counts else 0, "device_ids": devices}


# ===========================================================================
# KPI COMPUTATION
# ===========================================================================
def compute_kpis(result: dict, bundle: DataBundle,
                 sar_escalation_score: float, sar_filed_count: int) -> dict:
    """Compute the header KPIs.

    total_alerts        = distinct customers with >=1 typology hit (computed)
    escalated           = alerting customers with final_score >= sar_escalation_score
    fpr_proxy           = 1 - escalated/total_alerts  (monitoring-model proxy;
                          a validated FPR requires case-disposition labels)
    sar_filed_count     = case-disposition input (default from the case file)
    chargeback_ratio    = is_chargeback / total txns (computed, ~0.73%)
    """
    cs = result["cust_score"]
    total_alerts = int(len(cs)) if len(cs) else 0
    escalated = int((cs["final_score"] >= sar_escalation_score).sum()) if total_alerts else 0
    fpr_proxy = (1 - escalated / total_alerts) if total_alerts else 0.0
    return {
        "total_alerts": total_alerts,
        "escalated_candidates": escalated,
        "fpr_proxy": fpr_proxy,
        "sar_filed": int(sar_filed_count),
        "chargeback_ratio": result["portfolio_chargeback_ratio"],
    }


if __name__ == "__main__":
    # Smoke test against the case workbook.
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "AMLFT_Analyst_JIM__1_.xlsx"
    b = load_and_validate(path)
    print("Validation:", json.dumps(b.validation, indent=2))
    res = run_all_typologies(b)
    print("Alerting customers:", len(res["cust_score"]))
    print("Portfolio chargeback ratio: %.2f%%" % (res["portfolio_chargeback_ratio"] * 100))
    edd = run_edd(b.cust, b.cards)
    print("EDD population:", len(edd))
