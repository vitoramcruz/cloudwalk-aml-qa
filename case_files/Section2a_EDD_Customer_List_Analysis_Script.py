# ============================================================
# TASK 2.1 — Enhanced Due Diligence (EDD) Population Detection
# CloudWalk AML/CTF Case — AML-FT Analyst
# ============================================================
# CONFIGURATION — update these variables for each new dataset
# ============================================================
INPUT_FILE = "/mnt/project/AMLFT_Analyst_JIM__1_.xlsx"  # path to dataset
SHEET_CUSTOMERS = "Customers_KYC"
SHEET_CARDS = "Cards"
ANALYSIS_DATE = "2025-11-07"          # reference date for time-based filters
SANCTIONS_SCORE_THRESHOLD = 0.5       # Criterion A
HIGH_VOLUME_THRESHOLD = 5000          # Criterion K, monthly USD
VERY_HIGH_VOLUME_THRESHOLD = 10000    # Criterion F, monthly USD
KYC_REFRESH_MONTHS = 12               # Criterion G — flag if older than this
OFAC_COMPREHENSIVE_COUNTRIES = ["IR", "KP", "SY", "CU", "SD"]  # Criterion E
OFAC_COMPREHENSIVE_COUNTRIES_STRICT = ["IR", "KP", "SY", "CU"]  # Criterion I (no SD)
IRAN_NEXUS_SANCTIONS_SCORE = 0.3      # Criterion I
URGENT_SANCTIONS_SCORE = 0.7          # Urgency escalation tier (Section 2.1 urgency logic)
FATF_GREY_LIST_COUNTRY = "VE"         # Criterion H — Venezuela, FATF Grey List Oct 2025
# ============================================================

import pandas as pd
import numpy as np
from datetime import datetime

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

# ------------------------------------------------------------
# STEP 1 — Load and validate real population (see Playbook Section 0.1)
# ------------------------------------------------------------
def load_real_rows(xls_path, sheet_name):
    """Load a sheet and drop fully-blank padding rows.
    openpyxl/pandas may report a padded range larger than the actual data."""
    df = pd.read_excel(xls_path, sheet_name=sheet_name)
    df = df.dropna(how="all").reset_index(drop=True)
    return df

customers = load_real_rows(INPUT_FILE, SHEET_CUSTOMERS)
cards = load_real_rows(INPUT_FILE, SHEET_CARDS)

print(f"Real population loaded: {len(customers)} customers, {len(cards)} cards")
assert len(customers) == 501, f"Expected 501 real customer rows, got {len(customers)}"
assert len(cards) == 630, f"Expected 630 real card rows, got {len(cards)}"

analysis_date = pd.Timestamp(ANALYSIS_DATE)
customers["last_kyc_refresh_dt"] = pd.to_datetime(customers["last_kyc_refresh"])
customers["months_since_refresh"] = (
    (analysis_date - customers["last_kyc_refresh_dt"]).dt.days / 30.44
)

# ------------------------------------------------------------
# STEP 2 — Join card status (blocked) + pep_flag for Criterion J
# ------------------------------------------------------------
blocked_pep_customers = set(
    cards.loc[cards["status"] == "blocked", "customer_id"].unique()
)

# ------------------------------------------------------------
# STEP 3 — Apply each EDD triggering criterion
# ------------------------------------------------------------
def evaluate_criteria(row):
    triggers = []

    # A — sanctions_match_score > 0.5
    if row["sanctions_match_score"] > SANCTIONS_SCORE_THRESHOLD:
        triggers.append(f"A: sanctions_match_score={row['sanctions_match_score']:.2f} > 0.5")

    # B — pep_flag = True
    if row["pep_flag"] == True:
        triggers.append("B: pep_flag=True")

    # C — country NOT IN ['US']
    if row["country"] != "US":
        triggers.append(f"C: country={row['country']} (non-US)")

    # D — kyc_level = 'basic' AND risk_rating = 'high'
    if row["kyc_level"] == "basic" and row["risk_rating"] == "high":
        triggers.append("D: kyc_level=basic AND risk_rating=high")

    # E — doc_issue_country IN OFAC comprehensive list (incl. SD)
    if row["doc_issue_country"] in OFAC_COMPREHENSIVE_COUNTRIES:
        triggers.append(f"E: doc_issue_country={row['doc_issue_country']} (OFAC comprehensive)")

    # F — expected_monthly_volume_usd > 10,000 AND kyc_level != 'enhanced'
    if row["expected_monthly_volume_usd"] > VERY_HIGH_VOLUME_THRESHOLD and row["kyc_level"] != "enhanced":
        triggers.append(
            f"F: expected_monthly_volume_usd=${row['expected_monthly_volume_usd']:,.0f} > $10,000, "
            f"kyc_level={row['kyc_level']}"
        )

    # G — last_kyc_refresh older than 12 months from analysis date
    if row["months_since_refresh"] > KYC_REFRESH_MONTHS:
        triggers.append(
            f"G: last_kyc_refresh={row['last_kyc_refresh']} "
            f"({row['months_since_refresh']:.1f} months ago)"
        )

    # H — country = 'VE' (Venezuela, FATF Grey List Oct 2025)
    if row["country"] == FATF_GREY_LIST_COUNTRY:
        triggers.append("H: country=VE (FATF Grey List Oct 2025)")

    # I — doc_issue_country IN OFAC comprehensive (strict) AND sanctions_match_score > 0.3
    if (row["doc_issue_country"] in OFAC_COMPREHENSIVE_COUNTRIES_STRICT
            and row["sanctions_match_score"] > IRAN_NEXUS_SANCTIONS_SCORE):
        triggers.append(
            f"I: doc_issue_country={row['doc_issue_country']} AND "
            f"sanctions_match_score={row['sanctions_match_score']:.2f} > 0.3"
        )

    # J — card status = 'blocked' AND pep_flag = True
    if row["customer_id"] in blocked_pep_customers and row["pep_flag"] == True:
        triggers.append("J: has blocked card AND pep_flag=True")

    # K — expected_monthly_volume_usd > 5,000 AND kyc_level IN ['basic','standard']
    if row["expected_monthly_volume_usd"] > HIGH_VOLUME_THRESHOLD and row["kyc_level"] in ["basic", "standard"]:
        triggers.append(
            f"K: expected_monthly_volume_usd=${row['expected_monthly_volume_usd']:,.0f} > $5,000, "
            f"kyc_level={row['kyc_level']}"
        )

    return triggers

customers["criteria_triggered"] = customers.apply(evaluate_criteria, axis=1)
customers["n_criteria"] = customers["criteria_triggered"].apply(len)
customers["criteria_codes"] = customers["criteria_triggered"].apply(
    lambda lst: ", ".join([c.split(":")[0] for c in lst])
)
customers["criteria_detail"] = customers["criteria_triggered"].apply(
    lambda lst: " | ".join(lst)
)

edd_population = customers[customers["n_criteria"] >= 1].copy()
print(f"\nTotal customers triggering >= 1 EDD criterion: {len(edd_population)} of {len(customers)}")

# ------------------------------------------------------------
# STEP 4 — Urgency scoring
# ------------------------------------------------------------
MANDATORY_CODES = {"A", "E", "H", "I", "J"}  # sanctions/PEP/OFAC/FATF-grey/blocked-PEP triggers

def urgency_level(row):
    codes = set(row["criteria_codes"].split(", ")) if row["criteria_codes"] else set()
    # URGENT: any OFAC comprehensive country nexus, or sanctions_score>0.7-class severity, or blocked PEP card
    if row["sanctions_match_score"] > URGENT_SANCTIONS_SCORE or "E" in codes or "I" in codes or "J" in codes:
        return "URGENT"
    # HIGH: PEP, FATF Grey List (VE), or D-criterion (basic KYC + high risk)
    if "B" in codes or "H" in codes or "D" in codes:
        return "HIGH"
    # Everything else (C, F, G, K only) = MEDIUM
    return "MEDIUM"

edd_population["urgency"] = edd_population.apply(urgency_level, axis=1)

def correct_risk_rating(row):
    codes = set(row["criteria_codes"].split(", ")) if row["criteria_codes"] else set()
    if row["sanctions_match_score"] > URGENT_SANCTIONS_SCORE or "E" in codes or "H" in codes or "B" in codes or "I" in codes:
        return "high"
    if "J" in codes or "D" in codes:
        return "high"
    if "F" in codes or "K" in codes:
        return "medium" if row["risk_rating"] == "low" else row["risk_rating"]
    return row["risk_rating"]

edd_population["correct_risk_rating"] = edd_population.apply(correct_risk_rating, axis=1)

def deadline(row):
    if row["urgency"] == "URGENT":
        return "24-48 hours"
    if row["urgency"] == "HIGH":
        return "7 calendar days"
    return "30 calendar days"

edd_population["deadline"] = edd_population.apply(deadline, axis=1)

def docs_required(row):
    codes = set(row["criteria_codes"].split(", ")) if row["criteria_codes"] else set()
    docs = []
    if "A" in codes or "I" in codes or "E" in codes:
        docs.append("Independent sanctions-list verification; source-of-wealth documentation")
    if "B" in codes:
        docs.append("PEP relationship disclosure; senior management approval memo")
    if "C" in codes:
        docs.append("Foreign document independent verification (doc_issue_country)")
    if "D" in codes:
        docs.append("Full CDD upgrade package (basic KYC insufficient for high-risk rating)")
    if "F" in codes or "K" in codes:
        docs.append("Updated source-of-funds/source-of-income narrative supporting expected volume")
    if "G" in codes:
        docs.append("Full KYC refresh (identity document, address, screening re-run)")
    if "H" in codes:
        docs.append("Venezuela-specific EDD: enhanced source-of-funds, adverse media check, UBO/beneficiary review")
    if "J" in codes:
        docs.append("Root-cause review of card block; senior compliance re-approval of relationship")
    return "; ".join(sorted(set(docs)))

edd_population["docs_required"] = edd_population.apply(docs_required, axis=1)

# Order by urgency then sanctions score then volume
urgency_order = {"URGENT": 0, "HIGH": 1, "MEDIUM": 2}
edd_population["urgency_sort"] = edd_population["urgency"].map(urgency_order)
edd_population = edd_population.sort_values(
    by=["urgency_sort", "sanctions_match_score", "expected_monthly_volume_usd"],
    ascending=[True, False, False]
).drop(columns=["urgency_sort"])

# ------------------------------------------------------------
# STEP 5 — Validation checks against known dataset facts
# ------------------------------------------------------------
c88888 = edd_population[edd_population["customer_id"] == "C88888"]
ve_customers = edd_population[edd_population["country"] == "VE"]
blocked_pep_in_edd = edd_population[edd_population["customer_id"].isin(blocked_pep_customers) & (edd_population["pep_flag"] == True)]

print(f"\nValidation — C88888 in EDD population: {len(c88888) == 1}")
print(f"Validation — VE customers in EDD population: {len(ve_customers)} (expect 2)")
print(f"Validation — blocked+PEP customers in EDD population: {len(blocked_pep_in_edd)}")
print(f"Validation — Criterion K population (K in codes): "
      f"{edd_population['criteria_codes'].str.contains('K').sum()} (playbook cites 214 dataset-wide)")

# Urgency breakdown
print("\nUrgency breakdown:")
print(edd_population["urgency"].value_counts())

# ------------------------------------------------------------
# STEP 6 — Build output tables
# ------------------------------------------------------------
output_cols = [
    "customer_id", "full_name", "country", "kyc_level", "risk_rating",
    "pep_flag", "sanctions_match_score", "doc_issue_country",
    "expected_monthly_volume_usd", "last_kyc_refresh", "months_since_refresh",
    "criteria_codes", "criteria_detail", "urgency", "docs_required",
    "deadline", "correct_risk_rating"
]
full_population_df = edd_population[output_cols].reset_index(drop=True)

# Priority case file: URGENT + HIGH only
priority_df = full_population_df[full_population_df["urgency"].isin(["URGENT", "HIGH"])].reset_index(drop=True)

print(f"\nFull EDD population: {len(full_population_df)}")
print(f"Priority (URGENT+HIGH) case file: {len(priority_df)}")

# Save intermediate CSVs for inspection
import os
os.makedirs("./output", exist_ok=True)
full_population_df.to_csv("./output/edd_full_population.csv", index=False)
priority_df.to_csv("./output/edd_priority_cases.csv", index=False)

print("\nTop 10 priority cases:")
print(priority_df[["customer_id", "full_name", "country", "urgency", "criteria_codes"]].head(10).to_string())
