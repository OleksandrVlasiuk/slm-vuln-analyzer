"""
Порівнює кожну умову Stage 2 з baseline (Stage 1, condition="") для кожної
моделі: середні, 95% бутстрап-ДІ різниці, парні тести (Вілкоксон — числові
метрики, точний Мак-Немар — бінарні), matched по finding_id.

Приклад:
    python scripts/compare.py
"""

import csv
from pathlib import Path

import numpy as np
from scipy.stats import wilcoxon, binomtest

ROOT = Path(__file__).resolve().parent.parent
METRICS_PATH = ROOT / "results" / "metrics.csv"
OUT_PATH = ROOT / "results" / "stage2_compare.csv"
FIGURES_DIR = ROOT / "results" / "figures"

MODELS = ["gemma4:e2b", "hf.co/INSAIT-Institute/MamayLM-Gemma-3-4B-IT-v1.0-GGUF:Q4_K_M"]
CONDITIONS = ["temp_0.5", "temp_0.9", "prompt_V0", "prompt_V1", "codeonly", "rag", "think_on"]

BINARY_METRICS = [
    "fix_valid",
    "structure_ok", "localization_hit", "fix_syntax_ok", "fix_sast_pass",
    "cwe_keyword_hit", "off_topic_class", "avoid_hits", "cwe_ref_rank_hit",
]
NUMERIC_METRICS = [
    "lt_errors_per_100w", "ru_chars", "latin_ratio", "rep_3gram", "fix_undefined",
    "cosine_cwe", "cwe_ref_margin",
]
ALL_METRICS = BINARY_METRICS + NUMERIC_METRICS

SEED = 42
N_BOOTSTRAP = 5000
FIGURE_METRICS = ["fix_valid", "fix_sast_pass", "lt_errors_per_100w", "rep_3gram", "avoid_hits"]


def to_float(v):
    try:
        if v in (None, "", "NA"):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def load_metrics():
    with open(METRICS_PATH, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def index_by(rows, model, condition):
    """finding_id -> row, лише для заданих model/condition (condition="" = baseline)."""
    out = {}
    for r in rows:
        if r["model"] != model:
            continue
        if (r.get("condition") or "") != condition:
            continue
        out[r["finding_id"]] = r
    return out


def bootstrap_ci(diffs, n_boot=N_BOOTSTRAP, seed=SEED):
    if not diffs:
        return None, None
    arr = np.array(diffs, dtype=float)
    n = len(arr)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_boot, n))
    means = arr[idx].mean(axis=1)
    means.sort()
    lo = means[int(0.025 * n_boot)]
    hi = means[min(int(0.975 * n_boot), n_boot - 1)]
    return round(float(lo), 4), round(float(hi), 4)


def paired_values(baseline_rows, cond_rows, metric):
    """(baseline_vals, cond_vals) — лише finding_id, присутні в обох, з не-NA
    значенням метрики в обох (McNemar/Wilcoxon потребують парних спостережень)."""
    b_vals, c_vals = [], []
    for fid in sorted(set(baseline_rows) & set(cond_rows)):
        bv = to_float(baseline_rows[fid].get(metric))
        cv = to_float(cond_rows[fid].get(metric))
        if bv is None or cv is None:
            continue
        b_vals.append(bv)
        c_vals.append(cv)
    return b_vals, c_vals


def mcnemar_test(b_vals, c_vals):
    """Точний Мак-Немар: біноміальний тест на дискордантних парах (0/1 -> 1/0)."""
    b_disc = sum(1 for b, c in zip(b_vals, c_vals) if b == 1 and c == 0)
    c_disc = sum(1 for b, c in zip(b_vals, c_vals) if b == 0 and c == 1)
    n_disc = b_disc + c_disc
    if n_disc == 0:
        return None
    return round(binomtest(min(b_disc, c_disc), n_disc, 0.5).pvalue, 4)


def wilcoxon_test(b_vals, c_vals):
    diffs = [c - b for b, c in zip(b_vals, c_vals)]
    if not diffs or all(d == 0 for d in diffs):
        return None
    try:
        _, p = wilcoxon(diffs)
        return round(float(p), 4)
    except ValueError:
        return None


def compare_one(model, condition, baseline_idx, cond_idx, metric):
    b_vals, c_vals = paired_values(baseline_idx, cond_idx, metric)
    n = len(b_vals)
    if n == 0:
        return None
    mean_b = round(sum(b_vals) / n, 4)
    mean_c = round(sum(c_vals) / n, 4)
    diffs = [c - b for b, c in zip(b_vals, c_vals)]
    ci_lo, ci_hi = bootstrap_ci(diffs)
    if metric in BINARY_METRICS:
        p_value = mcnemar_test(b_vals, c_vals)
        test_name = "mcnemar"
    else:
        p_value = wilcoxon_test(b_vals, c_vals)
        test_name = "wilcoxon"
    return {
        "model": model, "condition": condition, "metric": metric, "n": n,
        "mean_baseline": mean_b, "mean_condition": mean_c,
        "mean_diff": round(mean_c - mean_b, 4),
        "ci95_lo": ci_lo, "ci95_hi": ci_hi,
        "test": test_name, "p_value": "" if p_value is None else p_value,
    }


def make_figures(out_rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    by_key = {(r["model"], r["condition"], r["metric"]): r for r in out_rows}

    for metric in FIGURE_METRICS:
        fig, ax = plt.subplots(figsize=(10, 5))
        x = np.arange(len(CONDITIONS))
        width = 0.35
        for i, model in enumerate(MODELS):
            means, err_lo, err_hi = [], [], []
            for cond in CONDITIONS:
                r = by_key.get((model, cond, metric))
                if r is None:
                    means.append(0.0)
                    err_lo.append(0.0)
                    err_hi.append(0.0)
                    continue
                m = r["mean_diff"]
                lo = r["ci95_lo"] if r["ci95_lo"] is not None else m
                hi = r["ci95_hi"] if r["ci95_hi"] is not None else m
                means.append(m)
                err_lo.append(max(0.0, m - lo))
                err_hi.append(max(0.0, hi - m))
            short_model = model.split("/")[-1][:30]
            ax.bar(x + i * width, means, width, yerr=[err_lo, err_hi], capsize=3, label=short_model)
        ax.set_xticks(x + width / 2)
        ax.set_xticklabels(CONDITIONS, rotation=30, ha="right")
        ax.axhline(0, color="black", linewidth=0.8)
        ax.set_ylabel(f"Δ {metric} (умова − baseline)")
        ax.set_title(f"{metric}: умова vs baseline (95% бутстрап-ДІ)")
        ax.legend()
        fig.tight_layout()
        out_path = FIGURES_DIR / f"{metric}.png"
        fig.savefig(out_path, dpi=120)
        plt.close(fig)
        print(f"[compare] Збережено {out_path}")


def main():
    rows = load_metrics()
    out_rows = []
    for model in MODELS:
        baseline_idx = index_by(rows, model, "")
        if not baseline_idx:
            print(f"[compare] Увага: немає baseline (condition='') для моделі {model!r} — пропускаю.")
            continue
        for condition in CONDITIONS:
            cond_idx = index_by(rows, model, condition)
            if not cond_idx:
                print(f"[compare] Увага: немає записів condition={condition!r} для {model!r} — пропускаю.")
                continue
            for metric in ALL_METRICS:
                result = compare_one(model, condition, baseline_idx, cond_idx, metric)
                if result:
                    out_rows.append(result)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["model", "condition", "metric", "n", "mean_baseline", "mean_condition",
                  "mean_diff", "ci95_lo", "ci95_hi", "test", "p_value"]
    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"[compare] Записано {OUT_PATH} ({len(out_rows)} рядків)")

    make_figures(out_rows)


if __name__ == "__main__":
    main()
