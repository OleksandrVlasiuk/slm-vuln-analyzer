"""
Зведення ручної розмітки (data/manual_review.csv + data/tp_fp_review.csv):
точність Semgrep, частки fix_correct/explanation_correct по моделях, precision
автоматичного fix_valid відносно експертної оцінки, розрізи за patch_mode і CWE.
Пише results/manual_summary.csv і друкує зведення в консоль; порожні рядки
розмітки ігноруються.

Приклад:
    python scripts/manual_review_summary.py
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

MANUAL_REVIEW_PATH = ROOT / "data" / "manual_review.csv"
TP_FP_PATH = ROOT / "data" / "tp_fp_review.csv"
OUT_PATH = ROOT / "results" / "manual_summary.csv"

OUT_FIELDS = ["category", "key", "value", "positive", "labeled", "note"]


def load_csv(path):
    if not path.exists():
        print(f"[manual_review_summary] Не знайдено {path}.")
        sys.exit(1)
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def is_labeled(value):
    return value is not None and value.strip() != ""


def norm_finding_id(finding_id):
    """int(...) — узгоджує "0001" (manual_review.csv) з "1" (tp_fp_review.csv,
    якщо його теж редагували в Excel) чи навпаки."""
    try:
        return int(finding_id)
    except (TypeError, ValueError):
        return finding_id


def short_rule(rule_id):
    return (rule_id or "").split(".")[-1]


def rate(rows, field, positive="1"):
    """(частка, positives, labeled) серед рядків, де field розмічено (не
    порожнє); рядки без розмітки цього поля ігноруються."""
    labeled = [r for r in rows if is_labeled(r.get(field))]
    if not labeled:
        return None, 0, 0
    positives = sum(1 for r in labeled if r[field].strip() == positive)
    return round(positives / len(labeled), 4), positives, len(labeled)


def group_rate(rows, group_field, value_field, positive="1"):
    """{group_key: (частка, positives, labeled)} — групує rows за
    group_field, рахує rate(value_field) у кожній групі."""
    groups = defaultdict(list)
    for r in rows:
        if not is_labeled(r.get(value_field)):
            continue
        groups[r.get(group_field, "")].append(r)
    return {k: rate(v, value_field, positive) for k, v in groups.items()}


def main():
    manual_rows = load_csv(MANUAL_REVIEW_PATH)
    tp_fp_rows = load_csv(TP_FP_PATH)

    out_rows = []

    def add(category, key, value, positive, labeled, note=""):
        out_rows.append({"category": category, "key": key, "value": value,
                          "positive": positive, "labeled": labeled, "note": note})

    print("[manual_review_summary] === Зведення ручної розмітки ===")
    print(f"  manual_review.csv: {len(manual_rows)} рядків усього")
    print(f"  tp_fp_review.csv : {len(tp_fp_rows)} рядків усього\n")

    # --- 1. fix_correct / explanation_correct по моделях ---
    print("[1] fix_correct / explanation_correct по моделях:")
    for field in ("fix_correct", "explanation_correct"):
        by_model = group_rate(manual_rows, "model", field)
        for model, (v, pos, n) in sorted(by_model.items()):
            print(f"    {field:<22} {model:<55} {v}  ({pos}/{n})")
            add(f"{field}_by_model", model, v, pos, n)

    # --- 2. Точність Semgrep: загалом, за rule_id, список ХП ---
    print("\n[2] Точність Semgrep (is_true_positive=1):")
    tp_rate, tp_pos, tp_n = rate(tp_fp_rows, "is_true_positive")
    print(f"    загалом: {tp_rate}  ({tp_pos}/{tp_n})")
    add("semgrep_precision_overall", "", tp_rate, tp_pos, tp_n)

    by_rule = defaultdict(list)
    for r in tp_fp_rows:
        if is_labeled(r.get("is_true_positive")):
            by_rule[short_rule(r["rule_id"])].append(r)
    print("    за rule_id:")
    for rule, rows in sorted(by_rule.items()):
        v, pos, n = rate(rows, "is_true_positive")
        print(f"      {rule:<55} {v}  ({pos}/{n})")
        add("semgrep_precision_by_rule", rule, v, pos, n)

    false_positives = [r for r in tp_fp_rows if r.get("is_true_positive", "").strip() == "0"]
    print(f"    хибні спрацювання (is_true_positive=0): {len(false_positives)}")
    for r in false_positives:
        note = f"rule_id={r['rule_id']}; file={r['file']}:{r['start_line']}; note={r.get('note', '')}"
        print(f"      {r['finding_id']}: {note}")
        add("false_positive", r["finding_id"], "", "", "", note)

    # --- 3. fix_valid (автоматична метрика) vs fix_correct (експертна розмітка) ---
    # Усі рядки manual_review.csv мають fix_valid=1 за побудовою
    # (build_manual_review.py) — тож це і є precision автоматичного fix_valid=1
    # відносно ручної розмітки: скільки з визнаних валідними виправлень
    # справді правильні.
    fv_rate, fv_pos, fv_n = rate(manual_rows, "fix_correct")
    print(f"\n[3] fix_valid_precision (частка fix_correct=1 серед fix_valid=1): {fv_rate}  ({fv_pos}/{fv_n})")
    add("fix_valid_precision", "", fv_rate, fv_pos, fv_n,
        "усі рядки manual_review.csv мають fix_valid=1 за побудовою — це precision автоматичної метрики")

    # --- 4. fix_correct за patch_mode ---
    print("\n[4] fix_correct за patch_mode:")
    by_patch_mode = group_rate(manual_rows, "patch_mode", "fix_correct")
    for mode, (v, pos, n) in sorted(by_patch_mode.items()):
        print(f"    {mode or '(порожньо)':<15} {v}  ({pos}/{n})")
        add("fix_correct_by_patch_mode", mode, v, pos, n)

    # --- 5. fix_correct за CWE ---
    print("\n[5] fix_correct за CWE:")
    by_cwe = group_rate(manual_rows, "cwe", "fix_correct")
    for cwe, (v, pos, n) in sorted(by_cwe.items()):
        print(f"    {cwe or '(порожньо)':<15} {v}  ({pos}/{n})")
        add("fix_correct_by_cwe", cwe, v, pos, n)

    # --- 6. Наскрізна ефективність: серед TP-знахідок — частка fix_correct=1 ---
    tp_finding_ids = {norm_finding_id(r["finding_id"]) for r in tp_fp_rows
                       if r.get("is_true_positive", "").strip() == "1"}
    tp_manual_rows = [r for r in manual_rows if norm_finding_id(r["finding_id"]) in tp_finding_ids]
    e2e_rate, e2e_pos, e2e_n = rate(tp_manual_rows, "fix_correct")
    print(f"\n[6] Наскрізна ефективність — серед TP-знахідок (is_true_positive=1), частка "
          f"пар (знахідка, модель) з fix_correct=1: {e2e_rate}  ({e2e_pos}/{e2e_n})")
    add("end_to_end_tp_fix_correct", "", e2e_rate, e2e_pos, e2e_n,
        "серед рядків manual_review.csv, чия знахідка позначена is_true_positive=1 в tp_fp_review.csv")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"\n[manual_review_summary] Записано {OUT_PATH} ({len(out_rows)} рядків)")


if __name__ == "__main__":
    main()
