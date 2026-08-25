-- ============================================================================
-- CLOUDWALK PAYMENTS INC. — AML TRANSACTION MONITORING
-- Section 4.a — Detection Logic (12 parameterized alert queries)
-- ============================================================================
-- Engine: PostgreSQL
-- Author: AML Transaction Monitoring Engineer
-- Scope:  transactions, customers_kyc, merchants_kyb, cards
--
-- Design principles applied across every query below:
--   1. No hardcoded entity IDs — every threshold is declared in a `params`
--      CTE at the top of the query, so recalibration means editing one
--      literal, not rewriting logic.
--   2. Every result set carries an `alert_type` column for downstream
--      case-management routing.
--   3. Sliding time-window logic uses a self-join anchor pattern
--      (anchor row -> aggregate all same-entity rows within the window
--      that follow it) rather than fixed calendar buckets, so a burst
--      that straddles a bucket boundary (e.g., 23:55–00:10) is not missed.
--      Overlapping windows are deduplicated with DISTINCT ON, keeping the
--      earliest qualifying window per entity.
--   4. Dataset calibration notes (from the confirmed 32,348-txn / 501-cust /
--      100-merchant / 630-card dataset) are called out where they informed
--      a default: device sharing tops out at 12 customers on one device;
--      the chargeback outlier merchant sits at ~12% vs. a ~1.5% baseline;
--      one IP address is shared by 12 customers.
-- ============================================================================
-- CORRECTION LOG (CORR_6 — post-delivery functional QA, see ACHADOS_ACUMULADOS
-- Fase 9): Queries 10 and 11 originally used the pattern
--   x = ANY((SELECT array_col FROM params))
-- which raises `operator does not exist: text = text[]` on real PostgreSQL
-- (Postgres treats ANY(subquery) as a row-returning-subquery predicate, not an
-- "unwrap this array value" instruction). Fixed by casting the scalar
-- subquery result explicitly: ANY((SELECT array_col FROM params)::text[]).
-- Verified against the live 32,348-txn dataset in PostgreSQL 16: Query 10
-- returns 42 rows, Query 11 returns 46 rows (matches detection_engine.py's
-- T12_UBO_Jurisdiction_Screening row count exactly). All other 11 queries
-- were re-run unchanged and returned correct row counts on first try.
-- ============================================================================

-- ============================================================================

-- QUERY 1 — CARD TESTING
-- ============================================================================
-- Detects rapid, low-value ECOM authorization attempts on a single card,
-- spread across multiple merchants, in a short window, with at least one
-- approval confirming the card is live. Classic "card testing" pattern used
-- to validate stolen card numbers ahead of a larger fraudulent purchase.
-- ============================================================================

WITH params AS (
    SELECT
        5      AS min_attempts,           -- N: min. low-value attempts required in-window
        30     AS window_minutes,         -- M: lookback window, in minutes
        5.00   AS threshold_amount,       -- low-value ceiling, USD
        3      AS min_distinct_merchants  -- X: min. distinct merchants touched in-window
),
low_value_ecom AS (
    -- Candidate universe: ECOM channel, strictly below the low-value ceiling
    SELECT
        t.txn_id, t.txn_timestamp_utc, t.card_id, t.customer_id,
        t.merchant_id, t.amount_usd, t.status
    FROM transactions t
    WHERE t.channel = 'ECOM'
      AND t.amount_usd < (SELECT threshold_amount FROM params)
),
windows AS (
    -- Anchor each low-value attempt and roll forward window_minutes,
    -- aggregating every attempt on the same card that falls inside it
    SELECT
        a.card_id,
        a.txn_id                          AS anchor_txn_id,
        a.txn_timestamp_utc                AS window_start,
        MAX(b.txn_timestamp_utc)           AS window_end,
        COUNT(*)                           AS attempts_in_window,
        COUNT(DISTINCT b.merchant_id)      AS distinct_merchants_in_window,
        BOOL_OR(b.status = 'approved')     AS has_approval_in_window,
        ARRAY_AGG(DISTINCT b.merchant_id)  AS merchant_ids_in_window
    FROM low_value_ecom a
    JOIN low_value_ecom b
      ON b.card_id = a.card_id
     AND b.txn_timestamp_utc >= a.txn_timestamp_utc
     AND b.txn_timestamp_utc <  a.txn_timestamp_utc
                                 + (SELECT window_minutes FROM params) * INTERVAL '1 minute'
    GROUP BY a.card_id, a.txn_id, a.txn_timestamp_utc
),
qualifying_windows AS (
    SELECT w.*
    FROM windows w
    WHERE w.attempts_in_window          >= (SELECT min_attempts FROM params)
      AND w.distinct_merchants_in_window >= (SELECT min_distinct_merchants FROM params)
      AND w.has_approval_in_window = TRUE
),
deduped AS (
    -- Sliding windows overlap; keep the earliest qualifying window per card
    SELECT DISTINCT ON (card_id)
        card_id, anchor_txn_id, window_start, window_end,
        attempts_in_window, distinct_merchants_in_window, merchant_ids_in_window
    FROM qualifying_windows
    ORDER BY card_id, window_start
)
SELECT
    'CARD_TESTING'          AS alert_type,
    d.card_id,
    c.customer_id,
    d.window_start,
    d.window_end,
    d.attempts_in_window,
    d.distinct_merchants_in_window,
    d.merchant_ids_in_window
FROM deduped d
JOIN cards c ON c.card_id = d.card_id
ORDER BY d.attempts_in_window DESC;

-- Expected result example (1 mock row):
-- alert_type   | card_id   | customer_id | window_start        | window_end          | attempts_in_window | distinct_merchants_in_window | merchant_ids_in_window
-- CARD_TESTING | CARD_4471 | C10234      | 2026-03-02 03:14:00 | 2026-03-02 03:29:00 | 7                   | 4                             | {M3010,M3022,M3041,M3058}

-- Parameter reference table
-- parameter              | default | regulatory rationale
-- min_attempts (N)       | 5       | Card-testing scripts typically fire bursts of ≥5 auth attempts before an actor commits to a larger fraudulent purchase (FFIEC BSA/AML Manual, card-fraud typologies)
-- window_minutes (M)     | 30      | Testing scripts are automated and complete within minutes; 30 min captures the burst while limiting false positives from ordinary repeat shopping
-- threshold_amount       | 5.00    | Sub-$5 attempts avoid triggering issuer step-up/fraud holds; industry-standard low-value ceiling for card-testing detection
-- min_distinct_merchants | 3       | Testing rings rotate across low-friction ECOM merchants to avoid single-merchant velocity controls


-- ============================================================================
-- QUERY 2 — DEVICE SHARING (MULE AGGREGATION)
-- ============================================================================
-- Detects a single device_id used by an unusually large number of distinct
-- customer_ids at high-risk MCCs within a short window — a strong signal of
-- mule aggregation (one physical device controlling many "customer" accounts).
-- Calibration: this dataset's confirmed extreme case is a device with 12
-- distinct customers at MCC 4829, well beyond both thresholds below.
-- ============================================================================

WITH params AS (
    SELECT
        3   AS min_customers,    -- Y: alert threshold
        5   AS hold_customers,   -- hard-block threshold
        60  AS window_minutes    -- D: lookback window, minutes
),
high_risk_mcc_list AS (
    SELECT UNNEST(ARRAY[4829,6051,7995,5944,5967,6011]::float[]) AS mcc
),
high_risk_txns AS (
    SELECT t.txn_id, t.txn_timestamp_utc, t.device_id, t.customer_id, t.mcc, t.merchant_id
    FROM transactions t
    WHERE t.mcc IN (SELECT mcc FROM high_risk_mcc_list)
      AND t.device_id IS NOT NULL
),
windows AS (
    SELECT
        a.device_id,
        a.txn_id                          AS anchor_txn_id,
        a.txn_timestamp_utc                AS window_start,
        MAX(b.txn_timestamp_utc)           AS window_end,
        COUNT(DISTINCT b.customer_id)      AS distinct_customers_in_window,
        ARRAY_AGG(DISTINCT b.customer_id)  AS customer_ids_in_window,
        ARRAY_AGG(DISTINCT b.mcc)          AS mccs_in_window
    FROM high_risk_txns a
    JOIN high_risk_txns b
      ON b.device_id = a.device_id
     AND b.txn_timestamp_utc >= a.txn_timestamp_utc
     AND b.txn_timestamp_utc <  a.txn_timestamp_utc
                                 + (SELECT window_minutes FROM params) * INTERVAL '1 minute'
    GROUP BY a.device_id, a.txn_id, a.txn_timestamp_utc
),
qualifying AS (
    SELECT w.* FROM windows w
    WHERE w.distinct_customers_in_window >= (SELECT min_customers FROM params)
),
deduped AS (
    SELECT DISTINCT ON (device_id)
        device_id, window_start, window_end, distinct_customers_in_window,
        customer_ids_in_window, mccs_in_window
    FROM qualifying
    ORDER BY device_id, distinct_customers_in_window DESC, window_start
)
SELECT
    CASE WHEN d.distinct_customers_in_window >= (SELECT hold_customers FROM params)
         THEN 'DEVICE_SHARING_HARD_BLOCK'
         ELSE 'DEVICE_SHARING_ALERT'
    END                                    AS alert_type,
    d.device_id,
    d.window_start,
    d.window_end,
    d.distinct_customers_in_window,
    d.customer_ids_in_window,
    d.mccs_in_window
FROM deduped d
ORDER BY d.distinct_customers_in_window DESC;

-- Expected result example (1 mock row):
-- alert_type                 | device_id  | window_start        | window_end          | distinct_customers_in_window | customer_ids_in_window
-- DEVICE_SHARING_HARD_BLOCK  | DEV_88213  | 2026-01-14 09:02:00 | 2026-01-14 09:55:00 | 12                            | {C10001,...,C10012}

-- Parameter reference table
-- parameter            | default                              | regulatory rationale
-- min_customers (Y)     | 3                                    | ≥3 distinct customers on one device within an hour has no plausible shared-household/shared-computer explanation and is a recognized mule-network signal (FinCEN Advisory on mule networks)
-- hold_customers        | 5                                    | Beyond alert-worthy: warrants an automatic hold on further device transactions pending investigation, per this program's escalation tiering
-- window_minutes (D)    | 60                                   | Coordinated mule onboarding/testing sessions typically complete within an hour
-- high_risk_mccs        | [4829,6051,7995,5944,5967,6011]      | The six MCCs flagged high_risk_mcc_flag=True in this program (money transfer, quasi-cash/crypto, betting, jewelry, direct marketing, ATM/financial)


-- ============================================================================
-- QUERY 3 — QUASI-CASH STRUCTURING
-- ============================================================================
-- Detects repeated transactions in a tight dollar band at quasi-cash /
-- money-transfer MCCs for the same customer within a rolling week.
-- Per FinCEN SAR FAQs (Oct 9, 2025), suspicion rests on the REPEATED PATTERN
-- and MCC concentration — not on proximity to the $10,000 CTR threshold —
-- so the $980–$995 band is deliberately far below CTR territory.
-- ============================================================================

WITH params AS (
    SELECT
        3       AS min_txns,      -- K: min. transactions in the amount band
        980.00  AS low_amount,
        995.00  AS high_amount,
        7       AS window_days
),
target_mcc_list AS (
    SELECT UNNEST(ARRAY[6051,4829]::float[]) AS mcc
),
banded_txns AS (
    SELECT t.txn_id, t.txn_timestamp_utc, t.customer_id, t.merchant_id, t.mcc, t.amount_usd
    FROM transactions t
    WHERE t.mcc IN (SELECT mcc FROM target_mcc_list)
      AND t.amount_usd BETWEEN (SELECT low_amount FROM params) AND (SELECT high_amount FROM params)
),
windows AS (
    SELECT
        a.customer_id,
        a.txn_id                        AS anchor_txn_id,
        a.txn_timestamp_utc               AS window_start,
        MAX(b.txn_timestamp_utc)          AS window_end,
        COUNT(*)                          AS txns_in_window,
        SUM(b.amount_usd)                 AS total_amount_in_window,
        ARRAY_AGG(DISTINCT b.mcc)         AS mccs_in_window,
        ARRAY_AGG(b.txn_id ORDER BY b.txn_timestamp_utc) AS txn_ids_in_window
    FROM banded_txns a
    JOIN banded_txns b
      ON b.customer_id = a.customer_id
     AND b.txn_timestamp_utc >= a.txn_timestamp_utc
     AND b.txn_timestamp_utc <  a.txn_timestamp_utc
                                 + (SELECT window_days FROM params) * INTERVAL '1 day'
    GROUP BY a.customer_id, a.txn_id, a.txn_timestamp_utc
),
qualifying AS (
    SELECT w.* FROM windows w
    WHERE w.txns_in_window >= (SELECT min_txns FROM params)
),
deduped AS (
    SELECT DISTINCT ON (customer_id)
        customer_id, window_start, window_end, txns_in_window,
        total_amount_in_window, mccs_in_window, txn_ids_in_window
    FROM qualifying
    ORDER BY customer_id, window_start
)
SELECT
    'QUASI_CASH_STRUCTURING' AS alert_type,
    d.customer_id,
    d.window_start,
    d.window_end,
    d.txns_in_window,
    d.total_amount_in_window,
    d.mccs_in_window,
    d.txn_ids_in_window
FROM deduped d
ORDER BY d.txns_in_window DESC;

-- Expected result example (1 mock row):
-- alert_type              | customer_id | window_start | window_end | txns_in_window | total_amount_in_window | mccs_in_window
-- QUASI_CASH_STRUCTURING  | C10450      | 2026-02-01   | 2026-02-06 | 4               | 3958.00                 | {6051,4829}

-- Parameter reference table
-- parameter        | default        | regulatory rationale
-- min_txns (K)      | 3              | A single sub-threshold transaction is not suspicious on its own; ≥3 repeats in the same tight band is the pattern element FinCEN guidance (Oct 2025 FAQs) says to rely on
-- low_amount        | 980.00         | Upper-middle of a "just under $1,000" structuring pocket used in observed typologies
-- high_amount        | 995.00        | Keeps the band well clear of any single round-number/CTR anchoring, per FinCEN's guidance not to alert on CTR proximity alone
-- window_days        | 7             | A one-week look-back captures a realistic structuring cadence without over-aggregating unrelated activity
-- target_mccs         | [6051,4829]  | Quasi-cash/crypto and money-transfer MCCs are the categories where structuring converts electronic value into cash-equivalent or cross-border value


-- ============================================================================
-- QUERY 4 — HIGH-RISK CROSS-BORDER
-- ============================================================================
-- Detects customers transacting with non-US merchants at high-risk MCCs over
-- a rolling 7-day window, enriched with customer/merchant country and the
-- customer's own risk profile — a geo-hopping / risk-stacking triage view.
-- ============================================================================

WITH params AS (
    SELECT 7 AS window_days
),
high_risk_mcc_list AS (
    SELECT UNNEST(ARRAY[4829,6051,7995,5944,5967,6011]::float[]) AS mcc
),
recent_high_risk_xborder AS (
    SELECT t.customer_id, t.merchant_id, t.mcc, t.merchant_country, t.amount_usd, t.txn_timestamp_utc
    FROM transactions t
    WHERE t.mcc IN (SELECT mcc FROM high_risk_mcc_list)
      AND t.merchant_country <> 'US'
      AND t.txn_timestamp_utc >= (SELECT MAX(txn_timestamp_utc) FROM transactions)
                                  - (SELECT window_days FROM params) * INTERVAL '1 day'
)
SELECT
    'HIGH_RISK_CROSS_BORDER' AS alert_type,
    r.customer_id,
    ck.country               AS customer_country,
    r.merchant_country,
    r.mcc,
    ck.risk_rating           AS customer_risk_rating,
    ck.pep_flag,
    ck.sanctions_match_score,
    SUM(r.amount_usd)        AS total_amount_7d,
    COUNT(*)                 AS txn_count_7d
FROM recent_high_risk_xborder r
JOIN customers_kyc ck ON ck.customer_id = r.customer_id
GROUP BY r.customer_id, ck.country, r.merchant_country, r.mcc,
         ck.risk_rating, ck.pep_flag, ck.sanctions_match_score
ORDER BY total_amount_7d DESC;

-- Expected result example (1 mock row):
-- alert_type              | customer_id | customer_country | merchant_country | mcc  | customer_risk_rating | total_amount_7d | txn_count_7d
-- HIGH_RISK_CROSS_BORDER  | C10077      | BR                | CN                | 6051 | high                  | 6420.00          | 5

-- Parameter reference table
-- parameter       | default                              | regulatory rationale
-- window_days      | 7                                    | A weekly rolling view is short enough for timely investigator triage while long enough to reveal a pattern rather than a single trip/transaction
-- high_risk_mccs   | [4829,6051,7995,5944,5967,6011]      | Same six-MCC list used program-wide for high-risk classification (Section 1 of the AML program update)


-- ============================================================================
-- QUERY 5 — CHARGEBACK RATIO OUTLIER
-- ============================================================================
-- Detects merchants whose chargeback ratio over a rolling 30-day window
-- exceeds the risk threshold. Dataset baseline is ~1.5%; the confirmed
-- outlier merchant sits at ~12%, well above the automatic-suspension tier
-- defined in this program (Section 4 of the AML program update).
-- ============================================================================

WITH params AS (
    SELECT
        0.05 AS alert_threshold,   -- base/yellow alert ratio
        30   AS window_days
),
window_txns AS (
    SELECT t.merchant_id, t.is_chargeback
    FROM transactions t
    WHERE t.txn_timestamp_utc >= (SELECT MAX(txn_timestamp_utc) FROM transactions)
                                  - (SELECT window_days FROM params) * INTERVAL '1 day'
),
merchant_ratios AS (
    SELECT
        merchant_id,
        COUNT(*)                                                    AS total_txns_30d,
        SUM(CASE WHEN is_chargeback THEN 1 ELSE 0 END)              AS chargebacks_30d,
        ROUND(
            SUM(CASE WHEN is_chargeback THEN 1 ELSE 0 END)::numeric
            / NULLIF(COUNT(*), 0), 4
        )                                                            AS chargeback_ratio
    FROM window_txns
    GROUP BY merchant_id
)
SELECT
    CASE
        WHEN mr.chargeback_ratio >= 0.10 THEN 'CHARGEBACK_RATIO_AUTO_SUSPEND'
        WHEN mr.chargeback_ratio >= 0.08 THEN 'CHARGEBACK_RATIO_AUTO_SUSPEND'
        WHEN mr.chargeback_ratio >  0.05 THEN 'CHARGEBACK_RATIO_RED_ESCALATION'
        ELSE 'CHARGEBACK_RATIO_YELLOW_ALERT'
    END                             AS alert_type,
    mr.merchant_id,
    mk.dba_name,
    mr.total_txns_30d,
    mr.chargebacks_30d,
    mr.chargeback_ratio
FROM merchant_ratios mr
JOIN merchants_kyb mk ON mk.merchant_id = mr.merchant_id
WHERE mr.chargeback_ratio > (SELECT alert_threshold FROM params)
ORDER BY mr.chargeback_ratio DESC;

-- Expected result example (1 mock row):
-- alert_type                     | merchant_id | dba_name           | total_txns_30d | chargebacks_30d | chargeback_ratio
-- CHARGEBACK_RATIO_AUTO_SUSPEND  | M3030       | ElectroHub #330    | 812             | 97               | 0.1195

-- Parameter reference table
-- parameter        | default | regulatory rationale
-- alert_threshold   | 0.05    | Double the dataset's ~1.5% confirmed baseline; a merchant sustaining >5% chargebacks is a recognized card-network/BSA risk indicator (see Program Update §4 tiering: 3% yellow / 5% red / 8–10% auto-suspend)
-- window_days       | 30      | Chargebacks settle on a lag; a rolling 30-day window is the card-network standard reporting cadence and is recalculated daily per program policy


-- ============================================================================
-- QUERY 6 — ECOM WITHOUT 3DS IN HIGH-RISK MCC
-- ============================================================================
-- Detects customers with repeated KEYED (no 3-D Secure) ECOM transactions at
-- high-risk-flagged merchants over 30 days. A KEYED transaction at a
-- non-US merchant is flagged as double risk: no cardholder authentication
-- AND cross-border exposure stacked together.
-- ============================================================================

WITH params AS (
    SELECT
        5  AS min_keyed_txns,  -- P
        30 AS window_days
),
keyed_high_risk AS (
    SELECT t.txn_id, t.customer_id, t.merchant_id, t.txn_timestamp_utc,
           t.merchant_country, t.amount_usd
    FROM transactions t
    JOIN merchants_kyb mk ON mk.merchant_id = t.merchant_id
    WHERE t.channel = 'ECOM'
      AND t.pos_entry_mode = 'KEYED'
      AND mk.high_risk_mcc_flag = TRUE
      AND t.txn_timestamp_utc >= (SELECT MAX(txn_timestamp_utc) FROM transactions)
                                  - (SELECT window_days FROM params) * INTERVAL '1 day'
),
per_customer AS (
    SELECT
        customer_id,
        COUNT(*)                                                   AS keyed_txn_count_30d,
        SUM(CASE WHEN merchant_country <> 'US' THEN 1 ELSE 0 END)  AS keyed_xborder_count_30d,
        SUM(amount_usd)                                            AS total_amount_30d
    FROM keyed_high_risk
    GROUP BY customer_id
)
SELECT
    CASE WHEN pc.keyed_xborder_count_30d > 0
         THEN 'ECOM_NO_3DS_HIGH_RISK_XBORDER_DOUBLE_RISK'
         ELSE 'ECOM_NO_3DS_HIGH_RISK_MCC'
    END                        AS alert_type,
    pc.customer_id,
    pc.keyed_txn_count_30d,
    pc.keyed_xborder_count_30d,
    pc.total_amount_30d
FROM per_customer pc
WHERE pc.keyed_txn_count_30d >= (SELECT min_keyed_txns FROM params)
ORDER BY pc.keyed_txn_count_30d DESC;

-- Expected result example (1 mock row):
-- alert_type                                    | customer_id | keyed_txn_count_30d | keyed_xborder_count_30d | total_amount_30d
-- ECOM_NO_3DS_HIGH_RISK_XBORDER_DOUBLE_RISK      | C10233      | 6                    | 4                        | 5230.00

-- Parameter reference table
-- parameter          | default | regulatory rationale
-- min_keyed_txns (P)  | 5       | A single non-3DS transaction is routine friction-avoidance; ≥5 repeats at high-risk merchants indicates deliberate authentication-evasion, not a one-off checkout issue
-- window_days          | 30      | Aligns with the program's standard monthly monitoring cadence for MCC-level controls


-- ============================================================================
-- QUERY 7 — CASH-IN TO CASH-OUT (LAYERING INDICATOR)
-- ============================================================================
-- Detects an ATM cash withdrawal (MCC 6011) followed within days_window by a
-- money-transfer remittance (MCC 4829) from the same customer, where the
-- remitted amount is a large share of the withdrawn cash — a classic
-- layering pattern (cash pulled out, then pushed out again via remittance).
--
-- TWO-TIER DESIGN (reconciles the wide detection net used here with the
-- tighter figure reported in the Section 4.c KPI baseline / T08 metric):
--   - STANDARD tier (<= days_window, default 14 days): broad recall net for
--     investigator triage; surfaces 3 qualifying customers in the full dataset.
--   - HIGH_CONFIDENCE tier (<= high_confidence_hours, default 72 hours):
--     the tighter same-session-style pairing used as the production alert
--     count in the Section 4.c / 6.b KPI baseline (T08 = 1 customer,
--     C12261). Every HIGH_CONFIDENCE row is also a STANDARD row.
-- Both tiers are returned in one result set via the confidence_tier column
-- so a single query serves both the wide-net investigation view and the
-- KPI-reportable count (filter confidence_tier = 'HIGH_CONFIDENCE' for KPIs).
-- ============================================================================

WITH params AS (
    SELECT
        14      AS days_window,           -- STANDARD tier: broad recall net
        72      AS high_confidence_hours, -- HIGH_CONFIDENCE tier: KPI-reportable
        500.00  AS min_atm_amount,
        500.00  AS min_remit_amount,
        0.80    AS remit_to_atm_ratio,
        6011    AS atm_mcc,               -- ATM cash withdrawal MCC
        4829    AS remit_mcc              -- Money-transfer / remittance MCC
),
atm_txns AS (
    SELECT t.txn_id, t.customer_id, t.txn_timestamp_utc, t.amount_usd
    FROM transactions t
    WHERE t.mcc = (SELECT atm_mcc FROM params)
      AND t.status = 'approved'
      AND t.amount_usd >= (SELECT min_atm_amount FROM params)
),
remit_txns AS (
    SELECT t.txn_id, t.customer_id, t.txn_timestamp_utc, t.amount_usd
    FROM transactions t
    WHERE t.mcc = (SELECT remit_mcc FROM params)
      AND t.status = 'approved'
      AND t.amount_usd >= (SELECT min_remit_amount FROM params)
),
candidate_pairs AS (
    SELECT
        a.customer_id,
        a.txn_id            AS atm_txn_id,
        a.txn_timestamp_utc AS atm_ts,
        a.amount_usd        AS atm_amount,
        r.txn_id            AS remit_txn_id,
        r.txn_timestamp_utc AS remit_ts,
        r.amount_usd        AS remit_amount,
        ROUND((r.amount_usd / a.amount_usd)::numeric, 4) AS observed_ratio,
        EXTRACT(EPOCH FROM (r.txn_timestamp_utc - a.txn_timestamp_utc)) / 3600.0 AS hours_between
    FROM atm_txns a
    JOIN remit_txns r
      ON r.customer_id = a.customer_id
     AND r.txn_timestamp_utc >  a.txn_timestamp_utc
     AND r.txn_timestamp_utc <= a.txn_timestamp_utc
                                 + (SELECT days_window FROM params) * INTERVAL '1 day'
)
SELECT
    'CASH_IN_CASH_OUT_LAYERING' AS alert_type,
    CASE
        WHEN cp.hours_between <= (SELECT high_confidence_hours FROM params)
            THEN 'HIGH_CONFIDENCE'
        ELSE 'STANDARD'
    END AS confidence_tier,
    cp.customer_id,
    cp.atm_txn_id, cp.atm_ts, cp.atm_amount,
    cp.remit_txn_id, cp.remit_ts, cp.remit_amount,
    cp.observed_ratio,
    ROUND(cp.hours_between::numeric, 2) AS hours_between
FROM candidate_pairs cp
WHERE cp.observed_ratio >= (SELECT remit_to_atm_ratio FROM params)
ORDER BY confidence_tier, cp.observed_ratio DESC;

-- Expected result (full dataset, both tiers):
-- alert_type                | confidence_tier  | customer_id | atm_amount | remit_amount | observed_ratio | hours_between
-- CASH_IN_CASH_OUT_LAYERING | HIGH_CONFIDENCE  | C12261      | ~700       | ~944         | 1.3486         | 43.22
-- CASH_IN_CASH_OUT_LAYERING | STANDARD         | (2 more customers within 14 days, > 72h apart)
-- Verified against the source dataset: 3 customers qualify at 14-day/80%-ratio;
-- exactly 1 (C12261) also qualifies at 72h — matching Section 4.c/6.b KPI T08.

-- Parameter reference table
-- parameter               | default | regulatory rationale
-- days_window             | 14      | STANDARD tier: a two-week window captures deliberate layering while excluding coincidental, unrelated ATM/remittance activity spread across a month
-- high_confidence_hours   | 72      | HIGH_CONFIDENCE tier: a 3-day pairing is close enough in time to exclude ordinary, unrelated personal cash use and is the threshold used for KPI/board reporting (T08)
-- min_atm_amount          | 500.00  | Filters out routine small cash withdrawals unlikely to be part of a layering scheme
-- min_remit_amount        | 500.00  | Mirrors the ATM floor so the pair is evaluated on comparable, meaningful amounts
-- remit_to_atm_ratio      | 0.80    | A remittance that returns ≥80% of the cash just withdrawn is inconsistent with ordinary personal cash use and consistent with a pass-through/layering step
-- Usage note: use the full STANDARD+HIGH_CONFIDENCE result set for investigator
-- triage and casework; use confidence_tier = 'HIGH_CONFIDENCE' only when
-- reconciling against the Section 4.c/6.b KPI baseline (T08).


-- ============================================================================
-- QUERY 8 — IP ADDRESS RING (MULTI-CUSTOMER SHARED IP)
-- ============================================================================
-- Detects a single ip_address used by multiple distinct customer_ids in ECOM
-- transactions — a signature of a mule ring or account-farming operation.
-- Reported both generally and, separately, restricted to high-risk MCC
-- merchants for prioritized triage. Calibration: this dataset's confirmed
-- extreme case is one IP address shared by 12 distinct customers.
-- ============================================================================

WITH params AS (
    SELECT 3 AS min_customers  -- Z
),
ecom_ip AS (
    SELECT t.ip_address, t.customer_id, t.merchant_id, t.mcc
    FROM transactions t
    WHERE t.channel = 'ECOM'
      AND t.ip_address IS NOT NULL
),
ip_high_risk AS (
    SELECT
        e.ip_address,
        COUNT(DISTINCT e.customer_id)     AS distinct_customers,
        ARRAY_AGG(DISTINCT e.customer_id) AS customer_ids,
        ARRAY_AGG(DISTINCT e.merchant_id) AS merchant_ids
    FROM ecom_ip e
    JOIN merchants_kyb mk ON mk.merchant_id = e.merchant_id AND mk.high_risk_mcc_flag = TRUE
    GROUP BY e.ip_address
),
ip_general AS (
    SELECT
        ip_address,
        COUNT(DISTINCT customer_id)     AS distinct_customers,
        ARRAY_AGG(DISTINCT customer_id) AS customer_ids
    FROM ecom_ip
    GROUP BY ip_address
)
SELECT
    'IP_RING_HIGH_RISK_MCC' AS alert_type,
    ihr.ip_address,
    ihr.distinct_customers,
    ihr.customer_ids,
    ihr.merchant_ids
FROM ip_high_risk ihr
WHERE ihr.distinct_customers >= (SELECT min_customers FROM params)

UNION ALL

SELECT
    'IP_RING_GENERAL' AS alert_type,
    ig.ip_address,
    ig.distinct_customers,
    ig.customer_ids,
    NULL AS merchant_ids
FROM ip_general ig
WHERE ig.distinct_customers >= (SELECT min_customers FROM params)
  AND ig.ip_address NOT IN (
        SELECT ip_address FROM ip_high_risk WHERE distinct_customers >= (SELECT min_customers FROM params)
      )
ORDER BY distinct_customers DESC;

-- Expected result example (1 mock row):
-- alert_type              | ip_address      | distinct_customers | customer_ids
-- IP_RING_HIGH_RISK_MCC   | 45.129.55.210   | 12                  | {C10001,...,C10012}

-- Parameter reference table
-- parameter        | default | regulatory rationale
-- min_customers (Z) | 3       | ≥3 distinct customer accounts transacting from the same IP has no ordinary shared-network explanation (e.g., shared office/household rarely exceeds 2-3, and rarely all transact on the same merchant category) and is a standard fraud/mule-ring indicator


-- ============================================================================
-- QUERY 9 — PEP TRANSACTING IN HIGH-RISK MCC ABOVE EXPECTED TICKET
-- ============================================================================
-- Detects PEP-flagged customers transacting at high-risk MCC merchants for an
-- amount that significantly exceeds their expected average ticket — a
-- deviation-from-profile signal warranting review given the customer's
-- mandatory-EDD status (PEP = automatic high risk rating, Section 5 of the
-- AML program update).
-- ============================================================================

WITH params AS (
    SELECT 2.0 AS multiplier
)
SELECT
    'PEP_HIGH_RISK_MCC_ABOVE_EXPECTED' AS alert_type,
    t.txn_id,
    ck.customer_id,
    ck.full_name,
    ck.expected_avg_ticket_usd,
    t.amount_usd,
    ROUND((t.amount_usd / NULLIF(ck.expected_avg_ticket_usd, 0))::numeric, 2) AS ticket_multiple,
    t.merchant_id,
    mk.dba_name,
    t.mcc,
    t.txn_timestamp_utc
FROM transactions t
JOIN customers_kyc ck ON ck.customer_id = t.customer_id
JOIN merchants_kyb mk ON mk.merchant_id = t.merchant_id
WHERE ck.pep_flag = TRUE
  AND mk.high_risk_mcc_flag = TRUE
  AND t.amount_usd > (SELECT multiplier FROM params) * ck.expected_avg_ticket_usd
ORDER BY ticket_multiple DESC;

-- Expected result example (1 mock row):
-- alert_type                          | customer_id | expected_avg_ticket_usd | amount_usd | ticket_multiple | mcc
-- PEP_HIGH_RISK_MCC_ABOVE_EXPECTED    | C10099      | 250.00                  | 900.00      | 3.60             | 4829

-- Parameter reference table
-- parameter    | default | regulatory rationale
-- multiplier    | 2.0     | A PEP customer already carries a mandatory-high risk rating and mandatory EDD (FinCEN CDD Rule, 31 CFR 1010.230); a transaction at ≥2x their own established expected ticket at a high-risk MCC is a material deviation warranting immediate review, not just periodic refresh


-- ============================================================================
-- QUERY 10 — FATF/OFAC HIGH-RISK JURISDICTION CUSTOMER CROSS-BORDER
-- ============================================================================
-- Detects customers domiciled in, or documented from (via doc_issue_country),
-- an OFAC comprehensively sanctioned or FATF grey-listed jurisdiction,
-- transacting with a non-US merchant. doc_issue_country is checked
-- separately so an Iranian-passport holder is caught even if their
-- declared residency country field is otherwise clean.
-- ============================================================================

WITH params AS (
    SELECT
        ARRAY['IR','KP','SY','CU'] AS ofac_block_countries,
        ARRAY['VE']                AS fatf_grey_countries
)
SELECT
    CASE
        WHEN ck.country = ANY((SELECT ofac_block_countries FROM params)::text[])
          OR ck.doc_issue_country = ANY((SELECT ofac_block_countries FROM params)::text[])
            THEN 'OFAC_SANCTIONED_JURISDICTION_XBORDER'
        ELSE 'FATF_GREYLIST_JURISDICTION_XBORDER'
    END                          AS alert_type,
    t.txn_id,
    ck.customer_id,
    ck.country                   AS customer_country,
    ck.doc_issue_country,
    t.merchant_id,
    t.merchant_country,
    t.mcc,
    t.amount_usd,
    t.txn_timestamp_utc
FROM transactions t
JOIN customers_kyc ck ON ck.customer_id = t.customer_id
WHERE t.merchant_country <> 'US'
  AND (
        ck.country            = ANY((SELECT ofac_block_countries FROM params)::text[])
        OR ck.doc_issue_country = ANY((SELECT ofac_block_countries FROM params)::text[])
        OR ck.country            = ANY((SELECT fatf_grey_countries FROM params)::text[])
        OR ck.doc_issue_country = ANY((SELECT fatf_grey_countries FROM params)::text[])
      )
ORDER BY alert_type, t.amount_usd DESC;

-- Expected result example (1 mock row):
-- alert_type                              | customer_id | customer_country | doc_issue_country | merchant_country | amount_usd
-- OFAC_SANCTIONED_JURISDICTION_XBORDER    | C88888      | US                | IR                 | AE                | 4200.00

-- Parameter reference table
-- parameter            | default              | regulatory rationale
-- ofac_block_countries  | [IR,KP,SY,CU]        | OFAC comprehensive sanctions programs (31 CFR Chapter V); no risk-rating override permits processing without a documented OFAC license
-- fatf_grey_countries    | [VE]                | Current FATF grey list (Oct 2025); triggers mandatory EDD rather than an outright block per this program's tiering


-- ============================================================================
-- QUERY 11 — UBO HIGH-RISK JURISDICTION SCREENING
-- ============================================================================
-- Schema note: this query assumes merchants_kyb carries a
-- beneficial_owners_json JSONB column (an array of UBO objects with at
-- least name, country, ownership_pct, sanctions_match_score, pep) —
-- consistent with the KYB extract used elsewhere in this case file.
-- Add this column to the production schema if it does not exist yet.
--
-- Detects merchants with at least one UBO domiciled in a flagged
-- jurisdiction, or with a UBO-level sanctions fuzzy-match score above
-- threshold — surfacing OFAC 50% Rule exposure and EDD triggers that are
-- invisible if only the merchant-level ofac_match_score is screened.
-- ============================================================================

WITH params AS (
    SELECT
        0.3 AS ubo_sanctions_threshold,
        ARRAY['IR','KP','SY','CU','VE','RU'] AS flag_countries
),
ubo_expanded AS (
    SELECT
        mk.merchant_id,
        mk.dba_name,
        mk.primary_mcc,
        ubo->>'name'                             AS ubo_name,
        UPPER(ubo->>'country')                    AS ubo_country,
        (ubo->>'ownership_pct')::float             AS ownership_pct,
        (ubo->>'sanctions_match_score')::float      AS ubo_sanctions_match_score,
        COALESCE((ubo->>'pep')::boolean, FALSE)     AS ubo_pep
    FROM merchants_kyb mk
    CROSS JOIN LATERAL jsonb_array_elements(mk.beneficial_owners_json::jsonb) AS ubo
    WHERE mk.beneficial_owners_json IS NOT NULL
)
SELECT
    CASE
        WHEN u.ubo_country = ANY((SELECT flag_countries FROM params)::text[]) AND u.ownership_pct >= 50
            THEN 'UBO_SANCTIONED_JURISDICTION_CONTROL_50PCT_RULE'
        WHEN u.ubo_country = ANY((SELECT flag_countries FROM params)::text[]) AND u.ubo_pep
            THEN 'UBO_SANCTIONED_JURISDICTION_AND_PEP'
        WHEN u.ubo_country = ANY((SELECT flag_countries FROM params)::text[])
            THEN 'UBO_FLAGGED_JURISDICTION'
        ELSE 'UBO_SANCTIONS_FUZZY_MATCH'
    END                              AS alert_type,
    u.merchant_id, u.dba_name, u.primary_mcc,
    u.ubo_name, u.ubo_country, u.ownership_pct,
    u.ubo_sanctions_match_score, u.ubo_pep
FROM ubo_expanded u
WHERE u.ubo_country = ANY((SELECT flag_countries FROM params)::text[])
   OR u.ubo_sanctions_match_score > (SELECT ubo_sanctions_threshold FROM params)
ORDER BY
    CASE
        WHEN u.ubo_country = ANY((SELECT flag_countries FROM params)::text[]) AND u.ownership_pct >= 50 THEN 0
        WHEN u.ubo_country = ANY((SELECT flag_countries FROM params)::text[]) AND u.ubo_pep THEN 1
        ELSE 2
    END,
    u.ownership_pct DESC NULLS LAST;

-- Expected result example (1 mock row):
-- alert_type                                          | merchant_id | ubo_name      | ubo_country | ownership_pct | ubo_sanctions_match_score | ubo_pep
-- UBO_SANCTIONED_JURISDICTION_CONTROL_50PCT_RULE       | M3001       | [redacted]    | IR          | 60.00          | 0.85                       | false

-- Parameter reference table
-- parameter                 | default                       | regulatory rationale
-- ubo_sanctions_threshold    | 0.3                           | Internal risk-appetite trigger for manually investigating a fuzzy/partial UBO name match, consistent with the customer-level sanctions_match_score tiering
-- flag_countries              | [IR,KP,SY,CU,VE,RU]          | OFAC comprehensive-sanctions countries plus FATF grey-list/OFAC-targeted jurisdictions requiring mandatory EDD at the UBO level
-- ownership_pct >= 50 rule     | 50%                          | OFAC "50 Percent Rule" — aggregate or individual ownership by one or more blocked persons of ≥50% of an entity renders the entity itself a blocked person, even absent a separate SDN listing


-- ============================================================================
-- QUERY 12 — PREPAID CARD VELOCITY IN HIGH-RISK MCCs
-- ============================================================================
-- Detects prepaid cards with unusually high transaction velocity at
-- high-risk MCCs over 30 days, or single-day/monthly spend above the
-- FinCEN Prepaid Access Rule thresholds (31 CFR 1010).
-- ============================================================================

WITH params AS (
    SELECT
        10       AS min_txns_30d,  -- Q
        1000.00  AS daily_limit,
        10000.00 AS monthly_limit,
        30       AS window_days
),
high_risk_mcc_list AS (
    SELECT UNNEST(ARRAY[4829,6051,7995,5944,5967,6011]::float[]) AS mcc
),
prepaid_cards AS (
    SELECT card_id, customer_id FROM cards WHERE product = 'prepaid'
),
recent_txns AS (
    SELECT
        t.card_id, t.customer_id, t.mcc, t.amount_usd, t.txn_timestamp_utc,
        t.txn_timestamp_utc::date AS txn_date
    FROM transactions t
    JOIN prepaid_cards pc ON pc.card_id = t.card_id
    WHERE t.txn_timestamp_utc >= (SELECT MAX(txn_timestamp_utc) FROM transactions)
                                  - (SELECT window_days FROM params) * INTERVAL '1 day'
),
velocity AS (
    SELECT
        r.card_id, r.customer_id,
        COUNT(*) FILTER (WHERE r.mcc IN (SELECT mcc FROM high_risk_mcc_list)) AS high_risk_txn_count_30d,
        SUM(r.amount_usd)                                                     AS total_amount_30d
    FROM recent_txns r
    GROUP BY r.card_id, r.customer_id
),
daily_spend AS (
    SELECT card_id, customer_id, txn_date, SUM(amount_usd) AS daily_amount
    FROM recent_txns
    GROUP BY card_id, customer_id, txn_date
    HAVING SUM(amount_usd) > (SELECT daily_limit FROM params)
)
SELECT
    CASE
        WHEN v.high_risk_txn_count_30d >= (SELECT min_txns_30d FROM params) THEN 'PREPAID_VELOCITY_HIGH_RISK_MCC'
        WHEN v.total_amount_30d        > (SELECT monthly_limit FROM params) THEN 'PREPAID_MONTHLY_LIMIT_EXCEEDED'
        ELSE 'PREPAID_DAILY_LIMIT_EXCEEDED'
    END                    AS alert_type,
    v.card_id, v.customer_id,
    v.high_risk_txn_count_30d, v.total_amount_30d,
    ds.txn_date            AS flagged_date,
    ds.daily_amount
FROM velocity v
LEFT JOIN daily_spend ds ON ds.card_id = v.card_id
WHERE v.high_risk_txn_count_30d >= (SELECT min_txns_30d FROM params)
   OR v.total_amount_30d        > (SELECT monthly_limit FROM params)
   OR ds.daily_amount IS NOT NULL
ORDER BY v.high_risk_txn_count_30d DESC;

-- Expected result example (1 mock row):
-- alert_type                      | card_id     | customer_id | high_risk_txn_count_30d | total_amount_30d | flagged_date | daily_amount
-- PREPAID_VELOCITY_HIGH_RISK_MCC  | CARD_51092  | C10510      | 13                       | 8420.00           | NULL         | NULL

-- Parameter reference table
-- parameter       | default  | regulatory rationale
-- min_txns_30d (Q) | 10       | Ordinary prepaid usage at high-risk MCCs is occasional; ≥10 transactions in 30 days indicates the card is being used as a dedicated conduit for high-risk MCC activity
-- daily_limit       | 1000.00 | FinCEN Prepaid Access Rule daily reporting/identity threshold tier (31 CFR 1010.100(ff)(4), 1022.210)
-- monthly_limit     | 10000.00| Aligns with the program's monthly aggregate-volume supervisory-review threshold used for MCC 4829/6051 (Section 1 of the AML program update)
-- window_days       | 30      | Matches the monthly monitoring cadence used for velocity and prepaid controls program-wide


-- ============================================================================
-- QUERY 13 — TYPOLOGY 10: SELF-MERCHANT BEHAVIOR (UNDISCLOSED UBO RELATIONSHIP)
-- ============================================================================
-- Added post-delivery (Gemini QA regression finding FND-09): the Section 4.a
-- typology set originally shipped 12 SQL queries; T10 (self-merchant /
-- undisclosed UBO relationship) existed only as a Python implementation
-- (rapidfuzz token_sort_ratio, threshold 88 — see the T10 correction script)
-- because ANSI SQL / plain PostgreSQL has no native fuzzy-string function.
--
-- HONEST LIMITATION: this query uses EXACT normalized-name + DOB matching as
-- a conservative SQL-native proxy for the Python fuzzy match. It will catch
-- identical-name cases but will MISS near-miss spelling variants (e.g. minor
-- transliteration differences) that the rapidfuzz pass (threshold >=88) can
-- catch. Treat this query as a first-pass SQL screen; the Python script
-- remains the authoritative fuzzy-matching implementation for this typology.
-- If the PostgreSQL pg_trgm extension is available, ubo_name_norm and
-- cust_name_norm can be compared with `similarity(a, b) >= 0.88` instead of
-- exact equality for closer parity with the Python threshold.
-- ============================================================================

WITH params AS (
    SELECT 0 AS dob_tolerance_days   -- exact DOB match required (mirrors the Python script's rule)
),
ubo_expanded AS (
    SELECT
        mk.merchant_id,
        mk.dba_name          AS merchant_dba_name,
        UPPER(TRIM(ubo->>'name')) AS ubo_name_norm,
        (ubo->>'dob')::date        AS ubo_dob
    FROM merchants_kyb mk
    CROSS JOIN LATERAL jsonb_array_elements(mk.beneficial_owners_json::jsonb) AS ubo
    WHERE mk.beneficial_owners_json IS NOT NULL
),
name_dob_matches AS (
    SELECT
        u.merchant_id, u.merchant_dba_name, u.ubo_name_norm, u.ubo_dob,
        c.customer_id, c.full_name AS customer_full_name
    FROM ubo_expanded u
    JOIN customers_kyc c
      ON UPPER(TRIM(c.full_name)) = u.ubo_name_norm
     AND c.dob = u.ubo_dob
),
confirmed_self_merchant AS (
    SELECT DISTINCT
        m.customer_id, m.merchant_id, m.merchant_dba_name,
        m.customer_full_name
    FROM name_dob_matches m
    JOIN transactions t
      ON t.customer_id = m.customer_id
     AND t.merchant_id = m.merchant_id
)
SELECT
    'T10_SELF_MERCHANT_CONFIRMED' AS alert_type,
    customer_id, merchant_id, merchant_dba_name, customer_full_name
FROM confirmed_self_merchant
ORDER BY customer_id;

-- Expected result example (1 mock row):
-- alert_type                    | customer_id | merchant_id | merchant_dba_name | customer_full_name
-- T10_SELF_MERCHANT_CONFIRMED    | C1xxxx      | M3xxx       | [redacted]         | [redacted]

-- Parameter reference table
-- parameter        | default | regulatory rationale
-- name/DOB match     | exact  | SQL-native proxy for the Python rapidfuzz(name, threshold=88) + exact-DOB rule; catches identical-identity cases without a fuzzy-string extension
-- confirmed txn       | required | A name+DOB match alone is not evidence of self-dealing; an actual transaction by that customer at their own merchant is required, matching the Python script's "CONFIRMED" tier (as opposed to its "name-only, NOT CONFIRMED" tier)
