"""
Формує data/tp_fp_review.csv — розмітка true positive / false positive для
всіх 52 активних знахідок (data/findings.csv, exclude != '1'): чи справді
Semgrep правильно спрацював на цьому фрагменті коду.

Приклад:
    python scripts/build_tp_fp_review.py
"""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

FINDINGS_PATH = ROOT / "data" / "findings.csv"
OUT_PATH = ROOT / "data" / "tp_fp_review.csv"

FIELDS = [
    "finding_id", "rule_id", "cwe", "file", "start_line", "message", "snippet_clean",
    "is_true_positive", "note",
]


def main():
    with open(FINDINGS_PATH, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    active = [r for r in rows if r.get("exclude") != "1"]
    active.sort(key=lambda r: r["id"])
    print(f"[build_tp_fp_review] Активних знахідок (exclude != 1): {len(active)}")

    out_rows = [{
        "finding_id": r["id"],
        "rule_id": r["rule_id"],
        "cwe": r.get("cwe", ""),
        "file": r["file"],
        "start_line": r["start_line"],
        "message": r.get("message", ""),
        "snippet_clean": r.get("snippet_clean", ""),
        "is_true_positive": "",
        "note": "",
    } for r in active]

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig (BOM) — щоб Excel коректно розпізнав кодування українського тексту
    with open(OUT_PATH, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"[build_tp_fp_review] Записано {OUT_PATH} ({len(out_rows)} рядків)")


if __name__ == "__main__":
    main()
