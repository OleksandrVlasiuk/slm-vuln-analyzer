"""
Порівнює «сирий» SAST (Semgrep) з поясненнями SLM (gemma4:e2b) за 52 активними
знахідками data/findings.csv. Пише results/sast_vs_slm.csv — один рядок на
джерело, NA там, де критерій до джерела незастосовний.

Приклад:
    python scripts/sast_vs_slm.py
"""

import csv
import glob
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

ROOT = Path(__file__).resolve().parent.parent
FINDINGS_PATH = ROOT / "data" / "findings.csv"
METRICS_PATH = ROOT / "results" / "metrics.csv"
JSONL_PATH = ROOT / "results" / "explanations.jsonl"
OUT_PATH = ROOT / "results" / "sast_vs_slm.csv"

MODEL = "gemma4:e2b"
SLM_CONDITIONS = ["", "codeonly"]
CODE_BLOCK_RE = re.compile(r"```")


def normalize_path(p):
    return p.replace("\\", "/")


def load_active_findings():
    with open(FINDINGS_PATH, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    active = [r for r in rows if r.get("exclude") != "1"]
    print(f"[sast_vs_slm] Активних знахідок (exclude != 1): {len(active)}")
    return active


def load_raw_semgrep_index():
    """(rule_id, normalized_path, start_line) -> сирий результат Semgrep, з усіх
    data/semgrep_raw*.json — та сама схема ключа, що й у build_dataset.py."""
    index = {}
    paths = sorted(glob.glob(str(ROOT / "data" / "semgrep_raw*.json")))
    print(f"[sast_vs_slm] Сирі файли Semgrep: {[Path(p).name for p in paths]}")
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for res in data.get("results", []):
            key = (
                res.get("check_id", ""),
                normalize_path(res.get("path", "")),
                res.get("start", {}).get("line", 1),
            )
            index.setdefault(key, res)
    return index


def semgrep_stats(active_findings, raw_index):
    matched, unmatched = [], 0
    for f in active_findings:
        key = (f["rule_id"], normalize_path(f["file"]), int(f["start_line"]))
        res = raw_index.get(key)
        if res is None:
            unmatched += 1
            continue
        matched.append(res)
    if unmatched:
        print(f"[sast_vs_slm] Увага: {unmatched}/{len(active_findings)} активних знахідок "
              f"не знайдено в сирих semgrep_raw*.json (rule_id/file/start_line не збігся).")

    n = len(matched)
    has_fix = sum(1 for r in matched if "fix" in (r.get("extra") or {}) and r["extra"]["fix"])
    word_counts = [len(((r.get("extra") or {}).get("message", "") or "").split()) for r in matched]
    avg_words = round(sum(word_counts) / n, 2) if n else None

    return {
        "source": "Semgrep (сирий SAST)",
        "n": n,
        "autofix_rate": round(has_fix / n, 4) if n else None,
        "avg_message_words": avg_words,
        "language": "англійська",
        "cwe_keyword_hit": "", "localization_hit": "", "fix_valid": "", "code_block_rate": "",
    }


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


def load_metrics_rows():
    with open(METRICS_PATH, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_explanations_by_key():
    """(finding_id, model, condition) -> explanation text."""
    out = {}
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            key = (r.get("finding_id", ""), r.get("model", ""), r.get("condition", "") or "")
            out[key] = r.get("explanation", "") or ""
    return out


def slm_stats(condition, metrics_rows, explanations_by_key):
    rows = [r for r in metrics_rows if r.get("model") == MODEL and (r.get("condition") or "") == condition]
    n = len(rows)

    code_block_hits = 0
    for r in rows:
        expl = explanations_by_key.get((r.get("finding_id", ""), MODEL, condition), "")
        if CODE_BLOCK_RE.search(expl):
            code_block_hits += 1

    label = "gemma4:e2b (база, V2)" if condition == "" else f"gemma4:e2b ({condition})"
    return {
        "source": label,
        "n": n,
        "autofix_rate": "", "avg_message_words": "", "language": "",
        "cwe_keyword_hit": avg([to_float(r.get("cwe_keyword_hit")) for r in rows]),
        "localization_hit": avg([to_float(r.get("localization_hit")) for r in rows]),
        "fix_valid": avg([to_float(r.get("fix_valid")) for r in rows]),
        "code_block_rate": round(code_block_hits / n, 4) if n else None,
    }


FIELDS = [
    "source", "n", "autofix_rate", "avg_message_words", "language",
    "cwe_keyword_hit", "localization_hit", "fix_valid", "code_block_rate",
]


def main():
    active = load_active_findings()
    raw_index = load_raw_semgrep_index()
    sem_row = semgrep_stats(active, raw_index)

    metrics_rows = load_metrics_rows()
    explanations_by_key = load_explanations_by_key()
    slm_rows = [slm_stats(cond, metrics_rows, explanations_by_key) for cond in SLM_CONDITIONS]

    out_rows = [sem_row] + slm_rows

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"[sast_vs_slm] Записано {OUT_PATH} ({len(out_rows)} рядків)")

    print("\n[sast_vs_slm] === Таблиця джерело x критерій ===")
    header = f"{'джерело':<26} {'n':>4} {'autofix':>9} {'слів/msg':>9} {'мова':>10} {'cwe_hit':>9} {'loc_hit':>9} {'fix_valid':>10} {'code_blk':>9}"
    print(header)
    print("-" * len(header))
    for r in out_rows:
        print(f"{r['source']:<26} {r['n']:>4} {str(r['autofix_rate']):>9} {str(r['avg_message_words']):>9} "
              f"{str(r['language']):>10} {str(r['cwe_keyword_hit']):>9} {str(r['localization_hit']):>9} "
              f"{str(r['fix_valid']):>10} {str(r['code_block_rate']):>9}")


if __name__ == "__main__":
    main()
