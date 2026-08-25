"""
qa/test_app.py
===============
Launches app.py as a real Streamlit server and drives it with a headless
Chromium browser (Playwright) to confirm:
  1. The page loads (HTTP 200 + health check).
  2. The population-validation guard-rail shows all green.
  3. No tab renders a Python traceback.

Writes a screenshot of each tab to qa_reports/screenshots/ and a pass/fail
summary to qa_reports/app_report.md.
"""
import os
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

APP_DIR = "case_files"
APP_FILE = "app.py"
PORT = 8502
BASE_URL = f"http://localhost:{PORT}"
TABS = ["Portfolio charts", "Entity drill-down", "Alert simulator", "EDD population"]


def start_streamlit():
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", APP_FILE,
         "--server.port", str(PORT), "--server.headless", "true"],
        cwd=APP_DIR,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, text=True,
    )
    return proc


def wait_for_server(timeout=60):
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/_stcore/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def main():
    os.makedirs("qa_reports/screenshots", exist_ok=True)
    report_lines = ["# Streamlit App QA Report\n"]
    overall_ok = True

    proc = start_streamlit()
    try:
        if not wait_for_server():
            report_lines.append("**FAIL** — server did not become healthy within timeout.\n")
            print(proc.stdout.read() if proc.stdout else "")
            write_report(report_lines)
            sys.exit(1)

        report_lines.append("Server started and responded healthy. ✅\n")

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1400, "height": 1200})
            page.goto(BASE_URL, wait_until="networkidle", timeout=60000)
            time.sleep(30)  # allow the 11-typology detection engine to finish computing

            body_text = page.inner_text("body")
            checks = [
                ("Customers: 501 / 501 expected", "Population guard-rail: customers"),
                ("Merchants: 100 / 100 expected", "Population guard-rail: merchants"),
                ("Cards: 630 / 630 expected", "Population guard-rail: cards"),
                ("32,348", "Population guard-rail: transactions"),
            ]
            for needle, label in checks:
                ok = needle in body_text
                overall_ok = overall_ok and ok
                report_lines.append(f"- {'✅' if ok else '❌'} {label} (`{needle}`)\n")

            page.screenshot(path="qa_reports/screenshots/00_initial_load.png", full_page=True)

            for i, tabname in enumerate(TABS, start=1):
                try:
                    page.get_by_text(tabname, exact=False).first.click()
                    time.sleep(4)
                    fname = f"qa_reports/screenshots/{i:02d}_{tabname.replace(' ', '_').replace('/', '-')}.png"
                    page.screenshot(path=fname, full_page=True)
                    traceback_count = page.locator("text=Traceback").count()
                    ok = traceback_count == 0
                    overall_ok = overall_ok and ok
                    report_lines.append(
                        f"- {'✅' if ok else '❌'} Tab '{tabname}' — "
                        f"{traceback_count} traceback(s) found\n"
                    )
                except Exception as e:
                    overall_ok = False
                    report_lines.append(f"- ❌ Tab '{tabname}' — error clicking: {e}\n")

            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    write_report(report_lines)
    if not overall_ok:
        sys.exit(1)


def write_report(lines):
    with open("qa_reports/app_report.md", "w", encoding="utf-8") as f:
        f.writelines(lines)
    print("".join(lines))


if __name__ == "__main__":
    main()
