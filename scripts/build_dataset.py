"""
Формує data/findings.csv зі стратифікованою вибіркою знахідок Semgrep
(data/semgrep_raw.json) для Python та JS/TS.

Приклад:
    python scripts/build_dataset.py
"""

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parent.parent
RAW_PATH = ROOT / "data" / "semgrep_raw.json"
RAW_PY_PATH = ROOT / "data" / "semgrep_raw_py.json"
OUT_PATH = ROOT / "data" / "findings.csv"

SAMPLE_SIZE = 80
PY_TARGET_MIN = 25
PY_TARGET_MAX = 30
MAX_PER_RULE = 5
CONTEXT = 5
SEED = 42
MINIFIED_LINE_LEN = 500

TEST_PATH_PATTERNS = [
    "/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
    "test_", "_test.", ".test.", ".spec.",
]
EXCLUDE_PATH_PATTERNS = [
    "node_modules/", "/dist/", "/build/", ".min.js", ".min.css",
]

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def normalize_path(p):
    return p.replace("\\", "/")


def is_excluded_path(path):
    p = normalize_path(path).lower()
    return any(pat in p for pat in TEST_PATH_PATTERNS) or any(pat in p for pat in EXCLUDE_PATH_PATTERNS)


def is_minified(full_path):
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                if len(line) > MINIFIED_LINE_LEN:
                    return True
    except Exception:
        return False
    return False


def get_repo(path, corpus_marker="corpus"):
    parts = normalize_path(path).split("/")
    if corpus_marker in parts:
        idx = parts.index(corpus_marker)
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "unknown"


def get_lang(path):
    ext = Path(path).suffix.lower()
    return LANG_BY_EXT.get(ext, ext.lstrip(".") or "unknown")


def get_lang_bucket(lang):
    return "python" if lang == "python" else "jsts"


def extract_cwe(metadata):
    cwe = metadata.get("cwe")
    if not cwe:
        return ""
    if isinstance(cwe, str):
        cwe = [cwe]
    codes = []
    for c in cwe:
        m = re.match(r"(CWE-\d+)", c)
        codes.append(m.group(1) if m else c)
    return "; ".join(sorted(set(codes)))


def extract_owasp(metadata):
    owasp = metadata.get("owasp")
    if not owasp:
        return ""
    if isinstance(owasp, str):
        owasp = [owasp]
    return "; ".join(owasp)


def get_snippet(full_path, start_line, end_line, context=CONTEXT):
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return f"Помилка читання коду: {e}"
    start = max(0, (start_line - 1) - context)
    end = min(len(lines), end_line + context)
    return "".join(lines[start:end])


def load_results(path):
    if not path.exists():
        print(f"[build_dataset] Не знайдено {path}. Спершу запустіть Semgrep.")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)
    return report.get("results", [])


def build_rows(results, corpus_marker="corpus"):
    rows = []
    seen = set()
    for res in results:
        path = res.get("path", "")
        if not path or is_excluded_path(path):
            continue

        lang = get_lang(path)
        if lang not in ("python", "javascript", "typescript"):
            continue

        rule_id = res.get("check_id", "Unknown")
        start_line = res.get("start", {}).get("line", 1)
        end_line = res.get("end", {}).get("line", start_line)

        dup_key = (rule_id, normalize_path(path), start_line)
        if dup_key in seen:
            continue
        seen.add(dup_key)

        full_path = ROOT / path
        if not full_path.exists():
            full_path = Path(path)
        if is_minified(full_path):
            continue

        metadata = (res.get("extra", {}) or {}).get("metadata", {}) or {}

        rows.append({
            "repo": get_repo(path, corpus_marker),
            "lang": lang,
            "lang_bucket": get_lang_bucket(lang),
            "file": normalize_path(path),
            "start_line": start_line,
            "end_line": end_line,
            "rule_id": rule_id,
            "cwe": extract_cwe(metadata),
            "owasp": extract_owasp(metadata),
            "severity": (res.get("extra", {}) or {}).get("severity", ""),
            "message": ((res.get("extra", {}) or {}).get("message", "") or "").strip().replace("\n", " "),
            "snippet": get_snippet(full_path, start_line, end_line),
        })
    return rows


def stratified_pick(pool, target_n, rule_counts, rng):
    """Round-robin по групах CWE (максимізує різноманіття CWE), з обмеженням MAX_PER_RULE на правило."""
    by_cwe = defaultdict(list)
    for f in pool:
        by_cwe[f["cwe"] or "UNKNOWN"].append(f)
    for v in by_cwe.values():
        rng.shuffle(v)
    cwe_keys = list(by_cwe.keys())
    rng.shuffle(cwe_keys)

    idx = {k: 0 for k in cwe_keys}
    selected = []
    progressed = True
    while len(selected) < target_n and progressed:
        progressed = False
        for cwe in cwe_keys:
            if len(selected) >= target_n:
                break
            lst = by_cwe[cwe]
            i = idx[cwe]
            while i < len(lst) and rule_counts[lst[i]["rule_id"]] >= MAX_PER_RULE:
                i += 1
            if i < len(lst):
                item = lst[i]
                selected.append(item)
                rule_counts[item["rule_id"]] += 1
                idx[cwe] = i + 1
                progressed = True
            else:
                idx[cwe] = i
    return selected


def stratified_sample(rows, target_n):
    rng = random.Random(SEED)
    python_pool = [r for r in rows if r["lang_bucket"] == "python"]
    jsts_pool = [r for r in rows if r["lang_bucket"] == "jsts"]

    rule_counts = Counter()
    target_python = target_n // 2
    target_jsts = target_n - target_python

    selected = stratified_pick(python_pool, target_python, rule_counts, rng)
    selected += stratified_pick(jsts_pool, target_jsts, rule_counts, rng)

    deficit = target_n - len(selected)
    if deficit > 0:
        chosen_keys = {(r["file"], r["start_line"], r["rule_id"]) for r in selected}
        leftover = [
            r for r in python_pool + jsts_pool
            if (r["file"], r["start_line"], r["rule_id"]) not in chosen_keys
        ]
        selected += stratified_pick(leftover, deficit, rule_counts, rng)

    rng.shuffle(selected)
    return selected[:target_n]


CSV_HEADER = [
    "id", "repo", "lang", "file", "start_line", "end_line",
    "rule_id", "cwe", "owasp", "severity", "message", "snippet", "label", "comment",
]


def read_existing():
    if not OUT_PATH.exists():
        return []
    with open(OUT_PATH, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(rows):
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in CSV_HEADER})


def format_new_row(new_id, r):
    return {
        "id": new_id, "repo": r["repo"], "lang": r["lang"], "file": r["file"],
        "start_line": r["start_line"], "end_line": r["end_line"], "rule_id": r["rule_id"],
        "cwe": r["cwe"], "owasp": r["owasp"], "severity": r["severity"],
        "message": r["message"], "snippet": r["snippet"], "label": "", "comment": "",
    }


def build_fresh(target_n=SAMPLE_SIZE):
    """Формує data/findings.csv з нуля (data/semgrep_raw.json)."""
    results = load_results(RAW_PATH)
    print(f"[build_dataset] Сирих знахідок від Semgrep: {len(results)}")

    rows = build_rows(results)
    print(f"[build_dataset] Після фільтрації (тести/node_modules/dist/мінімізовані/дублікати): {len(rows)}")

    sample = stratified_sample(rows, target_n)
    print(f"[build_dataset] У фінальній вибірці: {len(sample)}")

    out_rows = [format_new_row(f"{i:04d}", r) for i, r in enumerate(sample, start=1)]
    write_csv(out_rows)
    print(f"[build_dataset] Записано {OUT_PATH}")
    return out_rows


def extend_python():
    """Дописує Python-знахідки з data/semgrep_raw_py.json до наявного findings.csv,
    не змінюючи вже наявні рядки (лише додає нові id в кінець)."""
    existing_rows = read_existing()
    if not existing_rows:
        print("[build_dataset] findings.csv порожній/відсутній — виконую повну побудову замість розширення.")
        return build_fresh()

    existing_python = [r for r in existing_rows if r["lang"] == "python"]
    current_py_count = len(existing_python)
    print(f"[build_dataset] Наявних рядків у findings.csv: {len(existing_rows)} (з них python: {current_py_count})")

    deficit = PY_TARGET_MAX - current_py_count
    if deficit <= 0:
        print(f"[build_dataset] Python вже на цільовому рівні ({current_py_count} >= {PY_TARGET_MAX}), нічого не додаю.")
        return existing_rows

    results = load_results(RAW_PY_PATH)
    print(f"[build_dataset] Сирих знахідок від Semgrep (Python: django/flask/python/owasp-top-ten): {len(results)}")

    rows = build_rows(results)
    print(f"[build_dataset] Після фільтрації (тести/node_modules/dist/мінімізовані/дублікати): {len(rows)}")

    existing_keys = {(r["rule_id"], r["file"], str(r["start_line"])) for r in existing_rows}
    candidates = [
        r for r in rows
        if r["lang"] == "python" and (r["rule_id"], r["file"], str(r["start_line"])) not in existing_keys
    ]
    print(f"[build_dataset] Нових python-кандидатів (без дублікатів із наявними 50): {len(candidates)}")

    rule_counts = Counter(r["rule_id"] for r in existing_rows)
    rng = random.Random(SEED)
    new_selected = stratified_pick(candidates, deficit, rule_counts, rng)
    print(f"[build_dataset] Додаю нових python-знахідок: {len(new_selected)}")

    start_id = max(int(r["id"]) for r in existing_rows) + 1
    new_rows = [format_new_row(f"{start_id + i:04d}", r) for i, r in enumerate(new_selected)]

    combined = existing_rows + new_rows
    write_csv(combined)
    print(f"[build_dataset] Записано {OUT_PATH} (усього рядків: {len(combined)})")

    total_py = current_py_count + len(new_selected)
    if total_py < PY_TARGET_MIN:
        print(f"[build_dataset] Увага: python-знахідок після розширення {total_py} "
              f"< цільового мінімуму {PY_TARGET_MIN} — бракує кандидатів у пулі за обмеження "
              f"'не більше {MAX_PER_RULE} на правило'.")

    return combined


def report(rows):
    lang_counts = Counter(r["lang"] for r in rows)
    cwe_counts = Counter(r["cwe"] or "UNKNOWN" for r in rows)

    print(f"\n[build_dataset] Усього рядків у findings.csv: {len(rows)}")

    print("\n[build_dataset] Розподіл за мовою:")
    for lang, cnt in lang_counts.most_common():
        print(f"  {lang:<12} {cnt}")

    print("\n[build_dataset] Розподіл за CWE:")
    for cwe, cnt in cwe_counts.most_common():
        print(f"  {cwe:<15} {cnt}")


def main():
    if OUT_PATH.exists():
        rows = extend_python()
    else:
        rows = build_fresh()
    report(rows)


if __name__ == "__main__":
    main()
