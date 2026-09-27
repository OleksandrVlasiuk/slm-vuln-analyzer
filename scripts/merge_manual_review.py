"""
Підтягує fix_correct/explanation_correct/note з data/manual_review.csv у
results/metrics.csv — щоб не перезапускати evaluate.py заради трьох колонок.

Приєднання — за (finding_id, model) серед рядків із condition="" (база);
finding_id порівнюється як int, бо Excel при збереженні CSV прибирає провідні
нулі ("0001" -> "1"). Перед перезаписом зберігає бекап
results/metrics_pre_manual_merge.csv.

Приклад:
    python scripts/merge_manual_review.py
"""

import csv
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

MANUAL_REVIEW_PATH = ROOT / "data" / "manual_review.csv"
METRICS_PATH = ROOT / "results" / "metrics.csv"
BACKUP_PATH = ROOT / "results" / "metrics_pre_manual_merge.csv"

EXPECTED_PROMPT_VERSION = "V2"
EXPECTED_TEMPERATURE = "0.1"


def norm_finding_id(finding_id):
    """int(finding_id) — Excel звик прибирати провідні нулі при збереженні
    CSV ("0001" -> "1"), тому порівнюємо id як числа, а не рядки."""
    try:
        return int(finding_id)
    except (TypeError, ValueError):
        return finding_id


def load_manual_review():
    with open(MANUAL_REVIEW_PATH, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    by_key = {}
    for r in rows:
        by_key[(norm_finding_id(r["finding_id"]), r["model"])] = {
            "fix_correct": r.get("fix_correct", ""),
            "explanation_correct": r.get("explanation_correct", ""),
            "note": r.get("note", ""),
        }
    return by_key, len(rows)


def main():
    manual_by_key, manual_n = load_manual_review()
    print(f"[merge_manual_review] data/manual_review.csv: {manual_n} рядків")

    shutil.copy(METRICS_PATH, BACKUP_PATH)
    print(f"[merge_manual_review] Бекап: {BACKUP_PATH}")

    with open(METRICS_PATH, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        metrics_rows = list(reader)

    merged = 0
    key_mismatch = 0
    matched_keys = set()

    for row in metrics_rows:
        if (row.get("condition") or "") != "":
            continue  # ключ evaluate.py в'яже manual_review лише на condition=""
        key = (norm_finding_id(row["finding_id"]), row["model"])
        mr = manual_by_key.get(key)
        if mr is None:
            continue

        # Перевірка, що фактичний ключ evaluate.py (finding_id, model,
        # prompt_version, temperature) справді V2/0.1 — тобто той самий
        # запис, з якого manual_review.csv був сформований.
        if row.get("prompt_version") != EXPECTED_PROMPT_VERSION or str(row.get("temperature")) != EXPECTED_TEMPERATURE:
            key_mismatch += 1
            continue

        row["fix_correct"] = mr["fix_correct"]
        row["explanation_correct"] = mr["explanation_correct"]
        row["note"] = mr["note"]
        merged += 1
        matched_keys.add(key)

    unmatched = sorted(set(manual_by_key.keys()) - matched_keys)
    print(f"[merge_manual_review] Злито в metrics.csv: {merged}/{manual_n}")
    if key_mismatch:
        print(f"[merge_manual_review] Увага: {key_mismatch} записів condition='' мали "
              f"prompt_version/temperature != V2/0.1 (ключ evaluate.py не збігся б) — пропущено.")
    if unmatched:
        print(f"[merge_manual_review] Увага: {len(unmatched)} рядків manual_review.csv "
              f"не знайшли пари в metrics.csv: {unmatched}")
    else:
        print("[merge_manual_review] Усі рядки data/manual_review.csv приєднано.")

    with open(METRICS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(metrics_rows)
    print(f"[merge_manual_review] Перезаписано {METRICS_PATH} ({len(metrics_rows)} рядків усього, "
          f"fix_correct/explanation_correct/note оновлено для {merged}); решта колонок незмінні.")


if __name__ == "__main__":
    main()
