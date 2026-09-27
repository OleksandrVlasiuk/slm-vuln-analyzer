"""
Експорт навчальної вибірки для дистиляції у формат {"messages": [...]}
(system/user/assistant) — data/train/distill_train.jsonl + distill_val.jsonl.

Бере якісні пояснення учителя з data/train/teacher.jsonl (фільтр за
cwe_keyword_hit / off_topic_class / avoid_hits / structure_ok у
data/train/metrics_train.csv). User-блок формує
ollama_client.build_chat_messages() — та сама функція, що й у продукті, щоб
формат не розходився з тим, що модель бачить у роботі.

Приклад:
    python scripts/export_train_jsonl.py
"""

import csv
import json
import random
import sys
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ollama_client  # noqa: E402
from bench import load_findings_from_csv  # noqa: E402
from evaluate import find_sections, section_slice, CODE_BLOCK_RE  # noqa: E402 (той самий парсер секцій/коду, що й evaluate.py)

METRICS_PATH = ROOT / "data" / "train" / "metrics_train.csv"
FINDINGS_PATH = ROOT / "data" / "train" / "findings_train.csv"
JSONL_PATH = ROOT / "data" / "train" / "teacher.jsonl"
TRAIN_OUT = ROOT / "data" / "train" / "distill_train.jsonl"
VAL_OUT = ROOT / "data" / "train" / "distill_val.jsonl"

SEED = 42
VAL_FRACTION = 0.05
PROMPT_VERSION = "V2"
MIN_CODE_LEN = 20


def to01(v):
    v = (v or "").strip()
    if v in ("1", "1.0", "True", "true"):
        return 1
    if v in ("0", "0.0", "False", "false"):
        return 0
    return None


def passes_filter(row):
    return (to01(row.get("cwe_keyword_hit")) == 1
            and to01(row.get("off_topic_class")) == 0
            and to01(row.get("avoid_hits")) == 0
            and to01(row.get("structure_ok")) == 1)


def load_metrics():
    with open(METRICS_PATH, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_explanations():
    """finding_id -> текст пояснення з data/train/teacher.jsonl (той самий файл,
    що читає evaluate.py); останній запис перемагає при дублікаті finding_id."""
    out = {}
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            fid = rec.get("finding_id", "")
            if fid:
                out[fid] = rec.get("explanation", "")
    return out


def diyevist_code_block(explanation):
    """Перший огороджений блок коду (dedent) із секції «Дієвість»; "" якщо секції
    чи блоку немає — так само знаходить секцію, що й evaluate.py::extract_fix_code,
    але без фолбеку на "найдовший рядок з відступом" (тут навпаки, відсутність
    блоку — привід відкинути запис, а не вгадувати код)."""
    idx = find_sections(explanation)
    if idx.get("diev") is None:
        return ""
    diev_text = section_slice(explanation, idx, "diev")
    blocks = CODE_BLOCK_RE.findall(diev_text)
    if not blocks:
        return ""
    return textwrap.dedent(blocks[0]).strip("\n")


def normalize_code(code):
    """Прибирає пробіли по краях кожного рядка й порожні рядки — для порівняння
    "чи модель просто повернула той самий код", ігноруючи форматування."""
    lines = [line.strip() for line in (code or "").splitlines()]
    return "\n".join(line for line in lines if line)


def quality_gate(explanation, snippet_clean):
    """Три перевірки якості «Дієвість»-блоку (у заданому порядку, перша, що не
    проходить, і є причиною відхилення): (1) є огороджений блок коду, (2) код не
    збігається з вихідним snippet_clean (модель не просто повернула той самий
    код), (3) блок коду не коротший за MIN_CODE_LEN символів.
    Повертає (ok: bool, reason: str|None)."""
    code = diyevist_code_block(explanation)
    if not code.strip():
        return False, "no_code_block"
    if normalize_code(code) == normalize_code(snippet_clean):
        return False, "unchanged_code"
    if len(code.strip()) < MIN_CODE_LEN:
        return False, "too_short"
    return True, None


def token_estimate(text):
    """Оцінка кількості токенів = кількість слів * 1.5 (без токенізатора)."""
    return len((text or "").split()) * 1.5


def stratified_split(records, seed, val_fraction):
    """95/5 train/val, random.Random(seed), стратифіковано за CWE — кожен
    CWE-клас ділиться окремо (округлення до найближчого цілого), щоб частка
    val була сумірна в усіх класах, а не лише в найчастіших."""
    rng = random.Random(seed)
    train, val = [], []
    by_cwe = defaultdict(list)
    for rec in records:
        by_cwe[rec["cwe"]].append(rec)
    for cwe in sorted(by_cwe):
        items = by_cwe[cwe][:]
        rng.shuffle(items)
        n_val = round(len(items) * val_fraction)
        val.extend(items[:n_val])
        train.extend(items[n_val:])
    return train, val


def write_jsonl(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for rec in items:
            f.write(json.dumps({"messages": rec["messages"]}, ensure_ascii=False) + "\n")


def content_by_role(rec, role):
    return next(m["content"] for m in rec["messages"] if m["role"] == role)


def report_stats(name, items):
    n = len(items)
    print(f"\n[export] {name}: n={n}")
    if not n:
        return
    req_tokens = [token_estimate(content_by_role(r, "system")) + token_estimate(content_by_role(r, "user"))
                  for r in items]
    resp_tokens = [token_estimate(content_by_role(r, "assistant")) for r in items]
    print(f"  середня довжина запиту (system+user), токенів (слів х 1.5): {sum(req_tokens) / n:.1f}")
    print(f"  середня довжина відповіді (assistant), токенів (слів х 1.5): {sum(resp_tokens) / n:.1f}")


def main():
    metrics = load_metrics()
    filtered = [r for r in metrics if passes_filter(r)]
    print(f"[export] {METRICS_PATH.relative_to(ROOT)}: {len(metrics)} рядків, "
          f"{len(filtered)} проходять фільтр якості")

    findings = load_findings_from_csv(str(FINDINGS_PATH))
    findings_by_id = {f["id"]: f for f in findings}
    explanations = load_explanations()

    records = []
    skipped_no_finding = 0
    skipped_no_explanation = 0
    quality_rejects = Counter()
    for row in filtered:
        fid = row["finding_id"]
        finding = findings_by_id.get(fid)
        if finding is None:
            skipped_no_finding += 1
            continue
        explanation = explanations.get(fid)
        if not explanation:
            skipped_no_explanation += 1
            continue

        ok, reason = quality_gate(explanation, finding["lines"])
        if not ok:
            quality_rejects[reason] += 1
            continue

        system_content, user_content = ollama_client.build_chat_messages(
            PROMPT_VERSION, finding["rule_id"], finding["message"], finding["lines"],
            cwe=finding.get("cwe"))

        records.append({
            "cwe": finding.get("cwe") or "",
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": explanation},
            ],
        })

    if skipped_no_finding:
        print(f"[export] Пропущено {skipped_no_finding} рядків без активної (exclude!=1) "
              f"знахідки у {FINDINGS_PATH.name} (капи per-rule/per-CWE)")
    if skipped_no_explanation:
        print(f"[export] Пропущено {skipped_no_explanation} рядків без пояснення в {JSONL_PATH.name}")

    print("\n[export] Перевірка якості «Дієвість»-блоку:")
    print(f"  немає блоку коду (```...```): {quality_rejects['no_code_block']}")
    print(f"  код збігається зі snippet_clean (незмінений): {quality_rejects['unchanged_code']}")
    print(f"  блок коду коротший за {MIN_CODE_LEN} символів: {quality_rejects['too_short']}")
    print(f"  разом відсіяно: {sum(quality_rejects.values())}")
    print(f"  лишилось після перевірки якості: {len(records)}")

    train, val = stratified_split(records, SEED, VAL_FRACTION)
    write_jsonl(TRAIN_OUT, train)
    write_jsonl(VAL_OUT, val)

    print(f"\n[export] Записано {TRAIN_OUT.relative_to(ROOT)}: {len(train)} записів")
    print(f"[export] Записано {VAL_OUT.relative_to(ROOT)}: {len(val)} записів")

    report_stats("train", train)
    report_stats("val", val)

    if records:
        print("\n[export] Приклад запису:")
        print(json.dumps({"messages": records[0]["messages"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
