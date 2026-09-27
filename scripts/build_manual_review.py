"""
Формує data/manual_review.csv — вибірка для ручної розмітки: усі записи
results/metrics.csv з condition="" (база), model у (gemma4:e2b, MamayLM),
fix_valid=1. fix_correct/explanation_correct/note лишаються порожніми —
для заповнення вручну.

Приклад:
    python scripts/build_manual_review.py
"""

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

METRICS_PATH = ROOT / "results" / "metrics.csv"
FINDINGS_PATH = ROOT / "data" / "findings.csv"
JSONL_PATH = ROOT / "results" / "explanations.jsonl"
OUT_PATH = ROOT / "data" / "manual_review.csv"

MAMAYLM = "hf.co/INSAIT-Institute/MamayLM-Gemma-3-4B-IT-v1.0-GGUF:Q4_K_M"
MODELS = ("gemma4:e2b", MAMAYLM)

CODE_BLOCK_RE = re.compile(r"```(?:\w+)?\n?(.*?)```", re.DOTALL)

FIELDS = [
    "finding_id", "model", "rule_id", "cwe", "file", "start_line", "snippet_clean",
    "fix_code", "explanation_text", "patch_mode", "fix_trivial",
    "fix_correct", "explanation_correct", "note",
]


def load_findings_by_id():
    with open(FINDINGS_PATH, "r", encoding="utf-8", newline="") as f:
        return {r["id"]: r for r in csv.DictReader(f)}


def load_baseline_explanations():
    """(finding_id, model) -> explanation text, лише condition="" (база)."""
    out = {}
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if (r.get("condition") or "") != "":
                continue
            out[(r.get("finding_id", ""), r.get("model", ""))] = r.get("explanation", "") or ""
    return out


def extract_fix_code(explanation):
    """Останній огороджений блок коду в поясненні."""
    blocks = CODE_BLOCK_RE.findall(explanation)
    return blocks[-1].strip() if blocks else ""


def extract_explanation_text(explanation):
    """Пояснення без огороджених блоків коду."""
    text = CODE_BLOCK_RE.sub("", explanation)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def main():
    with open(METRICS_PATH, "r", encoding="utf-8", newline="") as f:
        metrics_rows = list(csv.DictReader(f))

    selected = [
        r for r in metrics_rows
        if (r.get("condition") or "") == "" and r.get("model") in MODELS and r.get("fix_valid") == "1"
    ]
    print(f"[build_manual_review] Відібрано записів (condition='', model in "
          f"{MODELS}, fix_valid=1): {len(selected)}")

    findings = load_findings_by_id()
    explanations = load_baseline_explanations()

    out_rows = []
    missing_finding = missing_expl = 0
    for r in selected:
        finding_id = r["finding_id"]
        finding = findings.get(finding_id)
        if not finding:
            missing_finding += 1
            continue
        explanation = explanations.get((finding_id, r["model"]))
        if explanation is None:
            missing_expl += 1
            explanation = ""

        out_rows.append({
            "finding_id": finding_id,
            "model": r["model"],
            "rule_id": r.get("rule_id", finding.get("rule_id", "")),
            "cwe": finding.get("cwe", ""),
            "file": finding.get("file", ""),
            "start_line": finding.get("start_line", ""),
            "snippet_clean": finding.get("snippet_clean", ""),
            "fix_code": extract_fix_code(explanation),
            "explanation_text": extract_explanation_text(explanation),
            "patch_mode": r.get("patch_mode", ""),
            "fix_trivial": r.get("fix_trivial", ""),
            "fix_correct": "",
            "explanation_correct": "",
            "note": "",
        })

    out_rows.sort(key=lambda row: row["finding_id"])

    if missing_finding:
        print(f"[build_manual_review] Увага: {missing_finding} записів без відповідної знахідки в findings.csv")
    if missing_expl:
        print(f"[build_manual_review] Увага: {missing_expl} записів без пояснення в explanations.jsonl (condition='')")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig (BOM) — щоб Excel коректно розпізнав кодування українського тексту
    with open(OUT_PATH, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"[build_manual_review] Записано {OUT_PATH} ({len(out_rows)} рядків)")


if __name__ == "__main__":
    main()
