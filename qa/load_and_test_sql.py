"""
qa/load_and_test_sql.py
========================
Loads the four data sheets from the AML workbook into a PostgreSQL database
and runs every query in Section4a_SQL_Detection_Queries.sql individually,
recording pass/fail + row counts into a markdown report.

Designed to run inside GitHub Actions against the built-in `postgres:16`
service container (see .github/workflows/qa-full-test.yml), but works
against any reachable PostgreSQL instance via the standard PG* env vars:
  PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE
"""
import os
import re
import sys
import glob
import traceback

import pandas as pd
from sqlalchemy import create_engine, text

# ---------------------------------------------------------------------------
# CONFIG — adjust these two lines if your filenames differ
# ---------------------------------------------------------------------------
WORKBOOK_GLOB = "case_files/*.xlsx"
SQL_FILE_GLOB = "case_files/*SQL_Detection_Queries*.sql"

SHEET_TO_TABLE = {
    "Transactions": "transactions",
    "Customers_KYC": "customers_kyc",
    "Merchants_KYB": "merchants_kyb",
    "Cards": "cards",
}

# Columns that must be cast to a proper date/timestamp type after the naive
# load, because openpyxl/pandas can round-trip Excel dates as text depending
# on cell formatting (documented project pitfall).
DATE_COLUMNS = {
    "transactions": [("txn_timestamp_utc", "timestamptz")],
    "cards": [("open_date", "date")],
    "customers_kyc": [("dob", "date"), ("last_kyc_refresh", "date")],
    "merchants_kyb": [("onboarding_date", "date"), ("last_kyb_refresh", "date")],
}


def pg_url():
    host = os.environ.get("PGHOST", "localhost")
    port = os.environ.get("PGPORT", "5432")
    user = os.environ.get("PGUSER", "postgres")
    pwd = os.environ.get("PGPASSWORD", "postgres")
    db = os.environ.get("PGDATABASE", "postgres")
    return f"postgresql+psycopg2://{user}:{pwd}@{host}:{port}/{db}"


def find_one(pattern, label):
    matches = glob.glob(pattern)
    if not matches:
        print(f"[FATAL] No file found matching '{pattern}' ({label}).")
        sys.exit(1)
    if len(matches) > 1:
        print(f"[WARN] Multiple files match '{pattern}' ({label}); using {matches[0]}")
    return matches[0]


def load_workbook(engine, workbook_path):
    xls = pd.ExcelFile(workbook_path)
    for sheet, table in SHEET_TO_TABLE.items():
        if sheet not in xls.sheet_names:
            print(f"[WARN] Sheet '{sheet}' not found in workbook; skipping table '{table}'.")
            continue
        df = pd.read_excel(xls, sheet_name=sheet)
        df = df.dropna(how="all").reset_index(drop=True)
        for col in df.columns:
            if df[col].dtype == object:
                df[col] = df[col].apply(
                    lambda x: str(x) if not isinstance(x, (str, type(None))) else x
                )
        df.to_sql(table, engine, if_exists="replace", index=False)
        print(f"[OK] Loaded {table}: {df.shape[0]} rows, {df.shape[1]} cols")

    # Fix date/timestamp typing (see DATE_COLUMNS above)
    with engine.begin() as conn:
        for table, cols in DATE_COLUMNS.items():
            for col, pg_type in cols:
                try:
                    conn.execute(text(
                        f'ALTER TABLE {table} ALTER COLUMN "{col}" '
                        f'TYPE {pg_type} USING "{col}"::{pg_type};'
                    ))
                    print(f"[OK] Cast {table}.{col} -> {pg_type}")
                except Exception as e:
                    print(f"[SKIP] Could not cast {table}.{col} -> {pg_type}: {e}")


def split_queries(sql_path):
    with open(sql_path, encoding="utf-8") as f:
        lines = f.readlines()
    markers = []
    for i, l in enumerate(lines):
        m = re.match(r"--\s*QUERY\s+(\d+)\s*—?\s*(.*)", l.strip())
        if m:
            markers.append((i, m.group(1), m.group(2).strip()))
    markers.append((len(lines), None, None))
    queries = []
    for idx in range(len(markers) - 1):
        start, qnum, title = markers[idx]
        end = markers[idx + 1][0]
        queries.append((qnum, title, "".join(lines[start:end])))
    return queries


def run_queries(engine, queries):
    results = []
    with engine.connect() as conn:
        for qnum, title, sql in queries:
            try:
                res = conn.execute(text(sql))
                try:
                    rows = res.fetchall()
                    row_count = len(rows)
                except Exception:
                    row_count = 0
                conn.commit()
                results.append({
                    "query": qnum, "title": title, "status": "PASS",
                    "rows": row_count, "error": None,
                })
                print(f"[PASS] Query {qnum} ({title}) -> {row_count} rows")
            except Exception as e:
                conn.rollback()
                err = str(e).splitlines()[0]
                results.append({
                    "query": qnum, "title": title, "status": "FAIL",
                    "rows": None, "error": err,
                })
                print(f"[FAIL] Query {qnum} ({title}) -> {err}")
    return results


def write_report(results, out_path):
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# SQL QA Report\n\n")
        f.write(f"**{passed}/{total} queries passed**\n\n")
        f.write("| Query | Title | Status | Rows | Error |\n")
        f.write("|---|---|---|---|---|\n")
        for r in results:
            err = (r["error"] or "").replace("|", "\\|")
            f.write(f"| {r['query']} | {r['title']} | {r['status']} | "
                     f"{r['rows'] if r['rows'] is not None else '-'} | {err} |\n")
    print(f"\nReport written to {out_path}")
    return passed, total


def main():
    workbook = find_one(WORKBOOK_GLOB, "AML workbook (.xlsx)")
    sql_file = find_one(SQL_FILE_GLOB, "SQL detection queries file")
    print(f"Workbook: {workbook}")
    print(f"SQL file: {sql_file}")

    engine = create_engine(pg_url())
    load_workbook(engine, workbook)

    queries = split_queries(sql_file)
    print(f"\nFound {len(queries)} queries in {sql_file}\n")

    results = run_queries(engine, queries)

    os.makedirs("qa_reports", exist_ok=True)
    passed, total = write_report(results, "qa_reports/sql_report.md")

    if passed < total:
        print(f"\n{total - passed} quer{'y' if total - passed == 1 else 'ies'} FAILED.")
        sys.exit(1)
    print("\nAll SQL queries passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
