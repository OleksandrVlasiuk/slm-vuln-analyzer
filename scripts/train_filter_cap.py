"""
Кроки 3-4 навчальної вибірки дистиляції: позначає в data/train/findings_train.csv
exclude=1 для перетинів із тестовим набором data/findings.csv (порівняння за
вмістом snippet_clean і за репозиторієм), внутрішніх дублікатів та надлишку
понад MAX_PER_RULE_CAP і MAX_PER_CWE_CAP. Рядки не видаляються фізично — у
колонці comment лишається причина.

Приклад:
    python scripts/train_filter_cap.py
"""

import csv
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS_PATH = ROOT / "data" / "findings.csv"  # лише читання
TRAIN_PATH = ROOT / "data" / "train" / "findings_train.csv"
SEED = 42
MAX_PER_RULE_CAP = 300
MAX_PER_CWE_CAP = 250
MIN_ROWS_WARN = 1500

CSV_HEADER = [
    "id", "repo", "lang", "file", "start_line", "end_line", "rule_id", "cwe", "owasp",
    "severity", "message", "snippet", "snippet_clean", "label", "comment",
    "region_id", "exclude",
]


def load_csv(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def mark_excluded(row, reason):
    if row.get("exclude") == "1":
        return False
    row["exclude"] = "1"
    row["comment"] = row.get("comment") or reason
    return True


def normalize_snippet(text):
    """Прибирає усі пробільні символи (не лише trim/collapse) — щоб різне
    форматування (відступи, перенос рядків) від незалежних прогонів
    Semgrep/snippet_clean не заважало виявити той самий фрагмент коду."""
    return re.sub(r"\s+", "", text or "")


def main():
    train_rows = load_csv(TRAIN_PATH)
    eval_rows = load_csv(FINDINGS_PATH) if FINDINGS_PATH.exists() else []

    eval_snippet_keys = {normalize_snippet(r["snippet_clean"]) for r in eval_rows if r.get("snippet_clean")}
    leaky_repos = {r["repo"] for r in eval_rows if r.get("repo")}

    overlap_removed = 0
    for row in train_rows:
        if row.get("exclude") == "1":
            continue
        is_content_overlap = normalize_snippet(row.get("snippet_clean", "")) in eval_snippet_keys
        is_repo_overlap = row.get("repo") in leaky_repos
        if is_content_overlap or is_repo_overlap:
            if mark_excluded(row, "exclude: перетин із тестовим набором"):
                overlap_removed += 1
    print(f"[train_filter] Перетин із тестовим набором (вміст snippet_clean або репозиторії"
          f"{sorted(leaky_repos)}): {overlap_removed}")

    seen_within = {}
    dup_removed = 0
    for row in train_rows:
        if row.get("exclude") == "1":
            continue
        key = (row["rule_id"], row["snippet_clean"])
        if key in seen_within:
            if mark_excluded(row, f"exclude: дублікат (rule_id, snippet_clean) усередині вибірки, лишено {seen_within[key]}"):
                dup_removed += 1
        else:
            seen_within[key] = row["id"]
    print(f"[train_filter] Внутрішні дублікати (rule_id, snippet_clean): {dup_removed}")

    rng = random.Random(SEED)
    by_rule = defaultdict(list)
    for row in train_rows:
        if row.get("exclude") != "1":
            by_rule[row["rule_id"]].append(row)

    cap_removed = 0
    for rule_id, rows in by_rule.items():
        if len(rows) <= MAX_PER_RULE_CAP:
            continue
        rng.shuffle(rows)
        for row in rows[MAX_PER_RULE_CAP:]:
            if mark_excluded(row, f"exclude: перевищення ліміту {MAX_PER_RULE_CAP}/правило ({rule_id})"):
                cap_removed += 1
    print(f"[train_filter] Понад ліміт {MAX_PER_RULE_CAP}/правило: {cap_removed}")

    rng_cwe = random.Random(SEED)
    by_cwe = defaultdict(list)
    for row in train_rows:
        if row.get("exclude") != "1":
            by_cwe[row["cwe"]].append(row)

    cwe_cap_removed = 0
    for cwe, rows in by_cwe.items():
        if len(rows) <= MAX_PER_CWE_CAP:
            continue
        rng_cwe.shuffle(rows)
        for row in rows[MAX_PER_CWE_CAP:]:
            if mark_excluded(row, f"exclude: перевищення ліміту {MAX_PER_CWE_CAP}/CWE ({cwe})"):
                cwe_cap_removed += 1
    print(f"[train_filter] Понад ліміт {MAX_PER_CWE_CAP}/CWE: {cwe_cap_removed}")

    with open(TRAIN_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for r in train_rows:
            writer.writerow({k: r.get(k, "") for k in CSV_HEADER})

    active = [r for r in train_rows if r.get("exclude") != "1"]
    print(f"\n[train_filter] Лишилось активних рядків: {len(active)} (з {len(train_rows)} усього)")
    if len(active) < MIN_ROWS_WARN:
        print(f"[train_filter] Увага: активних рядків менше {MIN_ROWS_WARN} — вибірка менша за очікувану, "
              f"але генерацію (bench.py) можна запускати як є.")

    lang_counts = Counter(r["lang"] for r in active)
    print("\n[train_filter] Активні — розподіл за мовою:")
    for lang, cnt in lang_counts.most_common():
        print(f"  {lang:<12} {cnt}")

    rule_counts = Counter(r["rule_id"] for r in active)
    print(f"\n[train_filter] Активні — унікальних правил: {len(rule_counts)}, "
          f"найчастіше: {rule_counts.most_common(1)[0] if rule_counts else 'н/д'}")

    cwe_counts = Counter(r["cwe"] for r in active)
    print(f"\n[train_filter] Активні — розподіл за CWE ({len(cwe_counts)} класів):")
    for cwe, cnt in cwe_counts.most_common():
        print(f"  {cwe or '(без CWE)':<12} {cnt}")


if __name__ == "__main__":
    main()
