"""Агрегує results/metrics.csv (і час/швидкість з explanations.jsonl) у
results/stage1_summary.csv — один рядок на модель, лише базова умова
(condition='', prompt_version=V2, temperature=0.1) — інакше для моделей, що
брали участь у Stage 2 (gemma4:e2b, MamayLM), усереднювались би й
експериментальні умови (temp_0.5, prompt_V0, rag, ...) впереміш з базою."""
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
METRICS_PATH = ROOT / "results" / "metrics.csv"
JSONL_PATH = ROOT / "results" / "explanations.jsonl"
OUT_PATH = ROOT / "results" / "stage1_summary.csv"

AVG_FIELDS = [
    "fix_valid",
    "structure_ok", "localization_hit", "fix_syntax_ok", "fix_sast_pass",
    "fix_undefined", "cwe_keyword_hit", "off_topic_class", "avoid_hits", "rep_3gram",
    "cwe_ref_rank_hit", "cosine_cwe", "cwe_ref_margin",
    "lt_errors_per_100w", "ru_chars", "latin_ratio",
]


def to_float(v):
    try:
        if v in (None, "", "NA"):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def avg(values):
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 4) if vals else None


def is_baseline(r):
    return ((r.get("condition") or "") == ""
             and r.get("prompt_version") == "V2"
             and str(r.get("temperature")) == "0.1")


def load_baseline_timing():
    """model -> {median_total_s, median_tokens_per_sec} лише для базової умови
    (explanations.jsonl — бо metrics.csv не містить часу/швидкості генерації)."""
    timing = defaultdict(lambda: {"total_s": [], "tokens_per_sec": []})
    if not JSONL_PATH.exists():
        return {}
    with open(JSONL_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not is_baseline(r):
                continue
            model = r.get("model")
            ts = to_float(r.get("total_s"))
            tps = to_float(r.get("tokens_per_sec"))
            if ts is not None:
                timing[model]["total_s"].append(ts)
            if tps is not None:
                timing[model]["tokens_per_sec"].append(tps)
    return {
        model: {
            "median_total_s": round(statistics.median(v["total_s"]), 3) if v["total_s"] else None,
            "median_tokens_per_sec": round(statistics.median(v["tokens_per_sec"]), 3) if v["tokens_per_sec"] else None,
        }
        for model, v in timing.items()
    }


def main():
    with open(METRICS_PATH, encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if is_baseline(r)]

    timing = load_baseline_timing()

    groups = defaultdict(list)
    for r in rows:
        groups[(r["model"], r["device"])].append(r)

    out_rows = []
    for (model, device), items in sorted(groups.items()):
        n = len(items)
        row = {"model": model, "device": device, "n": n}
        for field in AVG_FIELDS:
            row[field] = avg([to_float(r[field]) for r in items])
        row["fix_valid_na_count"] = sum(1 for r in items if r.get("fix_valid") == "NA")
        row["fix_sast_pass_na_count"] = sum(1 for r in items if r["fix_sast_pass"] == "NA")
        row["fix_trivial_rate"] = round(sum(1 for r in items if r.get("fix_trivial") == "1") / n, 4) if n else None
        t = timing.get(model, {})
        row["median_total_s"] = t.get("median_total_s")
        row["median_tokens_per_sec"] = t.get("median_tokens_per_sec")
        out_rows.append(row)

    fieldnames = ["model", "device", "n"] + AVG_FIELDS + [
        "fix_valid_na_count", "fix_sast_pass_na_count", "fix_trivial_rate",
        "median_total_s", "median_tokens_per_sec",
    ]
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"Записано {OUT_PATH} ({len(out_rows)} рядків, лише базова умова: condition='', V2, T=0.1)")
    for row in out_rows:
        print(row)


if __name__ == "__main__":
    main()
