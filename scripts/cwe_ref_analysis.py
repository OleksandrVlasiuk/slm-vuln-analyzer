"""
Аналіз відповідності класу CWE: порівнює ключово-словну метрику
(cwe_keyword_hit, data/cwe_keywords.json) з ембединговою (cwe_ref_rank_hit,
data/cwe_references_uk.json) — results/metrics.csv, results/stage1_summary.csv,
results/stage2_compare.csv, results/embed_cache.json.

Приклад:
    python scripts/cwe_ref_analysis.py
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

import evaluate as ev  # реюзаємо strip_code_blocks/sha256_text/cosine — не дублювати

METRICS_PATH = ROOT / "results" / "metrics.csv"
STAGE1_PATH = ROOT / "results" / "stage1_summary.csv"
STAGE2_PATH = ROOT / "results" / "stage2_compare.csv"
JSONL_PATH = ROOT / "results" / "explanations.jsonl"
FINDINGS_PATH = ROOT / "data" / "findings.csv"


def load_csv(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_float(v):
    try:
        if v in (None, "", "NA"):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def print_table1(stage1_rows):
    print("=== [1] Базова умова — 8 моделей: cwe_keyword_hit vs cwe_ref_rank_hit ===")
    header = f"{'model':<58} {'cwe_keyword_hit':>15} {'cwe_ref_rank_hit':>16} {'cosine_cwe':>10} {'cwe_ref_margin':>14}"
    print(header)
    print("-" * len(header))
    for r in sorted(stage1_rows, key=lambda r: r["model"]):
        print(f"{r['model']:<58} {r['cwe_keyword_hit']:>15} {r['cwe_ref_rank_hit']:>16} "
              f"{r['cosine_cwe']:>10} {r['cwe_ref_margin']:>14}")


def mcc(tp, tn, fp, fn):
    num = tp * tn - fp * fn
    denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    if denom == 0:
        return None
    return num / denom


def compute_mcc_and_mismatches(metrics_rows):
    base_rows = [r for r in metrics_rows if (r.get("condition") or "") == ""]
    tp = tn = fp = fn = 0
    mismatches = []
    for r in base_rows:
        kw = to_float(r.get("cwe_keyword_hit"))
        rk = to_float(r.get("cwe_ref_rank_hit"))
        if kw is None or rk is None:
            continue
        kw, rk = int(kw), int(rk)
        if kw == 1 and rk == 1:
            tp += 1
        elif kw == 0 and rk == 0:
            tn += 1
        elif kw == 1 and rk == 0:
            fp += 1
            mismatches.append((r, "keyword=1,rank=0"))
        else:
            fn += 1
            mismatches.append((r, "keyword=0,rank=1"))
    n = tp + tn + fp + fn
    return {
        "n": n, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "mcc": mcc(tp, tn, fp, fn),
        "disagreement_rate": round((fp + fn) / n, 4) if n else None,
    }, mismatches


def print_mcc(stats):
    print("\n=== [2] MCC(cwe_keyword_hit, cwe_ref_rank_hit) — база, усі моделі ===")
    print(f"n={stats['n']}  tp={stats['tp']}  tn={stats['tn']}  fp={stats['fp']}  fn={stats['fn']}")
    print(f"MCC = {round(stats['mcc'], 4) if stats['mcc'] is not None else None}")
    print(f"Частка розбіжностей = {stats['disagreement_rate']}")


def print_stage2_gemma_e2b(stage2_rows):
    print("\n=== [3] gemma4:e2b — cwe_ref_rank_hit у кожній умові етапу 2 (vs база) ===")
    rows = [r for r in stage2_rows if r["model"] == "gemma4:e2b" and r["metric"] == "cwe_ref_rank_hit"]
    header = f"{'умова':<12} {'база':>8} {'умова':>8} {'diff':>8} {'95% ДІ':>18} {'p':>8}"
    print(header)
    for r in rows:
        ci = f"[{r['ci95_lo']},{r['ci95_hi']}]"
        sig = " *" if to_float(r["p_value"]) is not None and to_float(r["p_value"]) < 0.05 else ""
        print(f"{r['condition']:<12} {r['mean_baseline']:>8} {r['mean_condition']:>8} "
              f"{r['mean_diff']:>8} {ci:>18} {r['p_value']:>8}{sig}")


def load_explanations_by_key():
    """(finding_id, model, condition, prompt_version, temperature) -> explanation."""
    out = {}
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            key = (r.get("finding_id", ""), r.get("model", ""), str(r.get("condition") or ""),
                   str(r.get("prompt_version", "")), str(r.get("temperature", "")))
            out[key] = r.get("explanation", "") or ""
    return out


def build_cwe_ref_embeddings_from_cache(cache):
    cwe_refs = ev.load_cwe_references()
    if not cwe_refs:
        return {}
    embeddings = {}
    for cwe, text in cwe_refs.items():
        key = ev.sha256_text(text)
        if key in cache:
            embeddings[cwe] = cache[key]
    return embeddings


def nearest_cwe(explanation, cache, cwe_ref_embeddings):
    non_code_text = ev.strip_code_blocks(explanation)
    key = ev.sha256_text(non_code_text)
    emb = cache.get(key)
    if emb is None:
        return None, None
    best_cwe, best_sim = None, None
    for cwe, ref_emb in cwe_ref_embeddings.items():
        sim = ev.cosine(emb, ref_emb)
        if sim is not None and (best_sim is None or sim > best_sim):
            best_cwe, best_sim = cwe, sim
    return best_cwe, best_sim


def print_mismatch_list(mismatches):
    print(f"\n=== [4] Знахідки, де метрики розійшлися ({len(mismatches)}) ===")
    if not mismatches:
        return

    findings = {r["id"]: r for r in load_csv(FINDINGS_PATH)}
    explanations = load_explanations_by_key()
    with open(ev.EMBED_CACHE_PATH, "r", encoding="utf-8") as f:
        cache = json.load(f)
    cwe_ref_embeddings = build_cwe_ref_embeddings_from_cache(cache)

    header = f"{'finding_id':<11} {'model':<50} {'тип':<18} {'CWE':<10} {'найближчий клас':<16} {'cos':>7}"
    print(header)
    for r, kind in mismatches:
        key = (r["finding_id"], r["model"], str(r.get("condition") or ""),
               r.get("prompt_version", ""), r.get("temperature", ""))
        explanation = explanations.get(key, "")
        nearest, sim = nearest_cwe(explanation, cache, cwe_ref_embeddings)
        sim_str = f"{sim:.4f}" if sim is not None else "—"
        cwe = findings.get(r["finding_id"], {}).get("cwe", "")
        print(f"{r['finding_id']:<11} {r['model']:<50} {kind:<18} {cwe:<10} "
              f"{nearest or '—':<16} {sim_str:>7}")


def main():
    metrics_rows = load_csv(METRICS_PATH)
    stage1_rows = load_csv(STAGE1_PATH)
    stage2_rows = load_csv(STAGE2_PATH)

    print_table1(stage1_rows)
    stats, mismatches = compute_mcc_and_mismatches(metrics_rows)
    print_mcc(stats)
    print_stage2_gemma_e2b(stage2_rows)
    print_mismatch_list(mismatches)


if __name__ == "__main__":
    main()
