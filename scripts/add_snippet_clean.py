"""
Додає колонку snippet_clean у data/findings.csv — сніпет з видаленими
коментарями (кількість/номери рядків збережені). Не чіпає жодних інших
колонок/значень; ідемпотентний (можна перезапускати).

Приклад:
    python scripts/add_snippet_clean.py
"""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from snippet_clean import clean_snippet

FINDINGS_PATH = ROOT / "data" / "findings.csv"


def main():
    with open(FINDINGS_PATH, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)

    if "snippet_clean" not in fieldnames:
        insert_at = fieldnames.index("snippet") + 1
        fieldnames = fieldnames[:insert_at] + ["snippet_clean"] + fieldnames[insert_at:]

    changed = 0
    for row in rows:
        cleaned = clean_snippet(row.get("snippet", ""), row.get("lang", ""))
        if row.get("snippet_clean") != cleaned:
            row["snippet_clean"] = cleaned
            changed += 1

    with open(FINDINGS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[add_snippet_clean] Оброблено {len(rows)} рядків, оновлено snippet_clean у {changed}.")


if __name__ == "__main__":
    main()
