"""
Порівнює донавчену модель з її базою на baseline-умові (condition="", prompt V2,
T=0.1) з results/metrics.csv — парними тестами (Мак-Немар, Вілкоксон), які
імпортуються з compare.py, а не дублюються. Окремим файлом пише звіт про
дублювання коду в секції «Дієвість» та статистику генерації.

Приклад:
    python scripts/compare_distilled.py
    python scripts/compare_distilled.py --model-distilled gemma3-vuln-uk-clean \\
        --out-compare results/distill_compare_clean.csv
"""

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from compare import load_metrics, paired_values, mcnemar_test, wilcoxon_test, to_float  # noqa: E402
from export_train_jsonl import diyevist_code_block, normalize_code  # noqa: E402
from bench import load_findings_from_csv  # noqa: E402

METRICS_PATH = ROOT / "results" / "metrics.csv"
JSONL_PATH = ROOT / "results" / "explanations.jsonl"
FINDINGS_PATH = ROOT / "data" / "findings.csv"
DEFAULT_OUT_COMPARE = ROOT / "results" / "distill_compare.csv"
DEFAULT_OUT_DUP = ROOT / "results" / "distill_code_duplication.csv"

BINARY_METRICS = [
    "structure_ok", "localization_hit", "cwe_keyword_hit", "cwe_ref_rank_hit",
    "off_topic_class", "fix_valid", "fix_syntax_ok", "avoid_hits",
]
NUMERIC_METRICS = ["lt_errors_per_100w", "rep_3gram", "ru_chars"]

DUP_FIELDNAMES = ["model", "n", "has_code_block", "unchanged_vs_snippet",
                   "truncated_length", "median_output_tokens", "median_tokens_per_sec"]


def is_baseline(r):
    return ((r.get("condition") or "") == ""
             and str(r.get("prompt_version")) == "V2"
             and str(r.get("temperature")) == "0.1")


def index_by_model(rows, model):
    return {r["finding_id"]: r for r in rows if r["model"] == model and is_baseline(r)}


def compare_metric(base_idx, distilled_idx, metric):
    base_vals, dist_vals = paired_values(base_idx, distilled_idx, metric)
    n = len(base_vals)
    if n == 0:
        return None
    mean_base = round(sum(base_vals) / n, 4)
    mean_dist = round(sum(dist_vals) / n, 4)
    if metric in BINARY_METRICS:
        p_value = mcnemar_test(base_vals, dist_vals)
        test_name = "mcnemar"
    else:
        p_value = wilcoxon_test(base_vals, dist_vals)
        test_name = "wilcoxon"
    return {
        "metric": metric, "n": n,
        "value_base": mean_base, "value_distilled": mean_dist,
        "diff": round(mean_dist - mean_base, 4),
        "test": test_name, "p_value": "" if p_value is None else p_value,
    }


def load_jsonl():
    with open(JSONL_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def timing_index(records, model):
    out = {}
    for r in records:
        if r.get("model") != model:
            continue
        if (r.get("condition") or "") != "" or str(r.get("prompt_version")) != "V2" \
                or str(r.get("temperature")) != "0.1":
            continue
        fid = r.get("finding_id")
        if fid:
            out[fid] = r
    return out


def paired_jsonl_field(base_idx, distilled_idx, field):
    base_vals, dist_vals = [], []
    for fid in sorted(set(base_idx) & set(distilled_idx)):
        bv = to_float(base_idx[fid].get(field))
        dv = to_float(distilled_idx[fid].get(field))
        if bv is None or dv is None:
            continue
        base_vals.append(bv)
        dist_vals.append(dv)
    return base_vals, dist_vals


def compare_timing(base_idx, distilled_idx, field):
    base_vals, dist_vals = paired_jsonl_field(base_idx, distilled_idx, field)
    n = len(base_vals)
    if n == 0:
        return None
    p_value = wilcoxon_test(base_vals, dist_vals)
    return {
        "metric": field, "n": n,
        "value_base": round(statistics.median(base_vals), 4),
        "value_distilled": round(statistics.median(dist_vals), 4),
        "diff": round(statistics.median(dist_vals) - statistics.median(base_vals), 4),
        "test": "wilcoxon (медіани показано, тест на парних значеннях)",
        "p_value": "" if p_value is None else p_value,
    }


def response_report(model, findings_by_id, jsonl_idx):
    """Одна модель: дублювання вхідного коду в «Дієвість» + обрив на ліміті
    токенів + медіани швидкості — усе з тих самих jsonl-записів."""
    n_matched = 0
    n_has_code = 0
    n_unchanged = 0
    n_truncated = 0
    output_tokens_vals = []
    tokens_per_sec_vals = []
    for fid, rec in jsonl_idx.items():
        finding = findings_by_id.get(fid)
        if finding is None:
            continue
        n_matched += 1
        if rec.get("done_reason") == "length":
            n_truncated += 1
        ot = to_float(rec.get("output_tokens"))
        if ot is not None:
            output_tokens_vals.append(ot)
        tps = to_float(rec.get("tokens_per_sec"))
        if tps is not None:
            tokens_per_sec_vals.append(tps)

        code = diyevist_code_block(rec.get("explanation", ""))
        if not code.strip():
            continue
        n_has_code += 1
        if normalize_code(code) == normalize_code(finding["lines"]):
            n_unchanged += 1
    return {
        "model": model, "n": n_matched,
        "has_code_block": n_has_code,
        "unchanged_vs_snippet": n_unchanged,
        "truncated_length": n_truncated,
        "median_output_tokens": round(statistics.median(output_tokens_vals), 1) if output_tokens_vals else "",
        "median_tokens_per_sec": round(statistics.median(tokens_per_sec_vals), 2) if tokens_per_sec_vals else "",
    }


def upsert_dup_rows(out_path, new_rows):
    """Читає наявний CSV (якщо є), замінює рядки для моделей з new_rows,
    лишає рядки інших моделей (з попередніх запусків для інших донавчених
    моделей) незмінними, пише назад — щоб --out-dup можна було ділити між
    кількома прогонами script'а без втрати історії."""
    existing = {}
    if out_path.exists():
        with open(out_path, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                existing[row["model"]] = row
    for row in new_rows:
        existing[row["model"]] = row
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=DUP_FIELDNAMES)
        writer.writeheader()
        for model in sorted(existing):
            writer.writerow({k: existing[model].get(k, "") for k in DUP_FIELDNAMES})
    return len(existing)


def main():
    parser = argparse.ArgumentParser(description="Порівнює донавчену модель з її базою")
    parser.add_argument("--model-distilled", default="gemma3-vuln-uk")
    parser.add_argument("--model-base", default="gemma3:4b")
    parser.add_argument("--out-compare", default=str(DEFAULT_OUT_COMPARE))
    parser.add_argument("--out-dup", default=str(DEFAULT_OUT_DUP))
    args = parser.parse_args()

    model_distilled = args.model_distilled
    model_base = args.model_base
    out_compare = Path(args.out_compare)
    out_dup = Path(args.out_dup)

    metrics_rows = load_metrics()
    base_idx = index_by_model(metrics_rows, model_base)
    dist_idx = index_by_model(metrics_rows, model_distilled)
    print(f"[compare_distilled] {model_base}: {len(base_idx)} рядків baseline у metrics.csv")
    print(f"[compare_distilled] {model_distilled}: {len(dist_idx)} рядків baseline у metrics.csv")

    out_rows = []
    for metric in BINARY_METRICS + NUMERIC_METRICS:
        r = compare_metric(base_idx, dist_idx, metric)
        if r:
            out_rows.append(r)

    jsonl_records = load_jsonl()
    base_timing = timing_index(jsonl_records, model_base)
    dist_timing = timing_index(jsonl_records, model_distilled)
    for field in ("total_s", "tokens_per_sec"):
        r = compare_timing(base_timing, dist_timing, field)
        if r:
            out_rows.append(r)

    out_compare.parent.mkdir(parents=True, exist_ok=True)
    with open(out_compare, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "n", "value_base", "value_distilled", "diff", "test", "p_value"])
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"\n[compare_distilled] Записано {out_compare} ({len(out_rows)} рядків)")

    print(f"\n[compare_distilled] === {model_distilled} vs {model_base} (baseline, matched finding_id) ===")
    print(f"{'metric':<22} {'n':>4} {'base':>10} {'distilled':>10} {'diff':>10} {'test':<10} {'p_value':>8}")
    for r in out_rows:
        print(f"{r['metric']:<22} {r['n']:>4} {r['value_base']:>10} {r['value_distilled']:>10} "
              f"{r['diff']:>10} {r['test']:<10} {str(r['p_value']):>8}")

    findings = load_findings_from_csv(str(FINDINGS_PATH))
    findings_by_id = {f["id"]: f for f in findings}

    new_dup_rows = [
        response_report(model_base, findings_by_id, base_timing),
        response_report(model_distilled, findings_by_id, dist_timing),
    ]
    total = upsert_dup_rows(out_dup, new_dup_rows)
    print(f"\n[compare_distilled] Записано {out_dup} ({total} рядків усього, upsert за моделлю)")

    print("\n[compare_distilled] === Якість відповідей («Дієвість», обрив, швидкість) ===")
    for r in new_dup_rows:
        print(f"  {r['model']}: n={r['n']}, має блок коду={r['has_code_block']}, "
              f"дослівно повторює snippet_clean={r['unchanged_vs_snippet']}, "
              f"обірвано (done_reason=length)={r['truncated_length']}, "
              f"медіана output_tokens={r['median_output_tokens']}, "
              f"медіана tokens/s={r['median_tokens_per_sec']}")


if __name__ == "__main__":
    main()
