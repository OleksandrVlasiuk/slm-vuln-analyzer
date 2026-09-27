"""
Майже-дублікати: групує знахідки одного файлу з перетином ±5-рядкових
фрагментів у "регіони" (region_id), лишає не більше 2 активних на регіон
(пріоритет — різні CWE, потім вища severity), решту позначає exclude=1
з причиною в comment. Існуючі id та рядки не змінюються й не видаляються.

Далі добирає нові регіони (знахідки, що не перетинаються з жодним існуючим)
з data/semgrep_raw*.json і дописує їх у кінець з новими id.

Приклад:
    python scripts/dedupe_regions.py
"""

import csv
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_dataset import (
    build_rows, load_results, stratified_pick, normalize_path, SEED,
)
from snippet_clean import clean_snippet

FINDINGS_PATH = ROOT / "data" / "findings.csv"
CSV_HEADER = [
    "id", "repo", "lang", "file", "start_line", "end_line", "rule_id", "cwe", "owasp",
    "severity", "message", "snippet", "snippet_clean", "label", "comment",
    "region_id", "exclude",
]
SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}
NEW_REGION_TARGET_MAX = 25  # верхня межа кількості нових регіонів, які добираємо за раз


def window(row, context=5):
    return max(1, int(row["start_line"]) - context), int(row["end_line"]) + context


def overlaps(a, b):
    return a[0] <= b[1] and a[1] >= b[0]


class UnionFind:
    def __init__(self, keys):
        self.parent = {k: k for k in keys}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def compute_regions(rows_by_id, extra_windows=None):
    """rows_by_id: {id: {'file':.., 'start_line':.., 'end_line':..}}.
    Повертає {root_id: [member ids]} — знахідки одного файлу, чиї ±5-вікна перетинаються
    (транзитивно, через union-find)."""
    by_file = defaultdict(list)
    for rid, r in rows_by_id.items():
        by_file[r["file"]].append((rid, window(r)))

    uf = UnionFind(rows_by_id.keys())
    for file, members in by_file.items():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                if overlaps(members[i][1], members[j][1]):
                    uf.union(members[i][0], members[j][0])

    groups = defaultdict(list)
    for rid in rows_by_id:
        groups[uf.find(rid)].append(rid)
    return groups


def pick_keepers(member_ids, rows_by_id):
    if len(member_ids) <= 2:
        return set(member_ids)

    by_cwe = defaultdict(list)
    for rid in member_ids:
        by_cwe[rows_by_id[rid]["cwe"]].append(rid)
    for ids in by_cwe.values():
        ids.sort(key=lambda rid: (-SEVERITY_RANK.get(rows_by_id[rid]["severity"], 0), rid))

    cwe_keys = list(by_cwe.keys())
    if len(cwe_keys) >= 2:
        cwe_keys.sort(key=lambda c: (
            -SEVERITY_RANK.get(rows_by_id[by_cwe[c][0]]["severity"], 0), c
        ))
        return {by_cwe[cwe_keys[0]][0], by_cwe[cwe_keys[1]][0]}

    pool = by_cwe[cwe_keys[0]]
    return {pool[0], pool[1]}


def assign_regions_and_exclude(rows):
    """rows: список dict-рядків findings.csv (мутуються на місці: region_id, exclude, comment)."""
    rows_by_id = {r["id"]: r for r in rows}
    groups = compute_regions(rows_by_id)

    # детерміноване іменування регіонів: сортуємо групи за мінімальним id
    ordered = sorted(groups.items(), key=lambda kv: min(kv[1]))

    excluded_count = 0
    for i, (_root, member_ids) in enumerate(ordered, start=1):
        region_id = f"R{i:04d}"
        keepers = pick_keepers(member_ids, rows_by_id)
        for rid in member_ids:
            row = rows_by_id[rid]
            row["region_id"] = region_id
            if rid in keepers or len(member_ids) <= 2:
                row["exclude"] = "0"
            else:
                row["exclude"] = "1"
                kept_str = ",".join(sorted(keepers))
                row["comment"] = (row.get("comment") or "") or (
                    f"exclude: майже-дублікат регіону {region_id} "
                    f"(перетин ±5 рядків із {kept_str}; пріоритет — різні CWE, вища severity)"
                )
                excluded_count += 1
    return excluded_count


def mine_new_regions(existing_rows, target_n):
    """Добирає нові знахідки з data/semgrep_raw*.json, що не перетинаються з жодним
    наявним регіоном (і одна з одною — теж підлягають ліміту 2/регіон)."""
    existing_keys = {(r["rule_id"], normalize_path(r["file"]), r["start_line"]) for r in existing_rows}
    existing_windows_by_file = defaultdict(list)
    for r in existing_rows:
        existing_windows_by_file[normalize_path(r["file"])].append(window(r))

    all_results = []
    for path in sorted((ROOT / "data").glob("semgrep_raw*.json")):
        all_results.extend(load_results(path))

    candidate_rows = build_rows(all_results)  # той самий фільтр, що й build_dataset.py

    fresh = []
    for r in candidate_rows:
        key = (r["rule_id"], normalize_path(r["file"]), str(r["start_line"]))
        if key in existing_keys:
            continue
        w = window(r)
        if any(overlaps(w, ew) for ew in existing_windows_by_file[normalize_path(r["file"])]):
            continue  # перетинається з наявним регіоном — не нова область коду
        fresh.append(r)

    if not fresh:
        return []

    # регіони серед самих кандидатів (щоб теж не мати >2 на одну область коду)
    tmp_ids = {f"tmp{i}": {"file": r["file"], "start_line": r["start_line"], "end_line": r["end_line"]}
               for i, r in enumerate(fresh)}
    groups = compute_regions(tmp_ids)
    tmp_by_id = {f"tmp{i}": r for i, r in enumerate(fresh)}

    rule_counts = Counter(r["rule_id"] for r in existing_rows if r.get("exclude") != "1")
    rng = random.Random(SEED)

    selected_candidates = []
    for _root, member_ids in groups.items():
        pool = [tmp_by_id[mid] for mid in member_ids]
        keep_n = min(2, len(pool))
        picked = stratified_pick(pool, keep_n, Counter(), rng)  # локальна різноманітність усередині регіону
        selected_candidates.extend(picked)

    final = stratified_pick(selected_candidates, target_n, rule_counts, rng)
    return final


def format_new_row(new_id, r):
    lang = r["lang"]
    snippet = r["snippet"]
    return {
        "id": new_id, "repo": r["repo"], "lang": lang, "file": r["file"],
        "start_line": r["start_line"], "end_line": r["end_line"], "rule_id": r["rule_id"],
        "cwe": r["cwe"], "owasp": r["owasp"], "severity": r["severity"],
        "message": r["message"], "snippet": snippet,
        "snippet_clean": clean_snippet(snippet, lang),
        "label": "", "comment": "",
    }


def main():
    with open(FINDINGS_PATH, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    excluded_count = assign_regions_and_exclude(rows)
    print(f"[dedupe_regions] Регіонів: {len(set(r['region_id'] for r in rows))}, "
          f"позначено exclude=1: {excluded_count}")

    new_candidates = mine_new_regions(rows, target_n=min(NEW_REGION_TARGET_MAX, excluded_count) or 0)
    print(f"[dedupe_regions] Нових регіонів/знахідок додано: {len(new_candidates)}")

    start_id = max(int(r["id"]) for r in rows) + 1
    new_rows = []
    for i, cand in enumerate(new_candidates):
        new_id = f"{start_id + i:04d}"
        row = format_new_row(new_id, cand)
        row["region_id"] = ""  # призначимо разом з рештою нижче
        row["exclude"] = "0"
        new_rows.append(row)

    all_rows = rows + new_rows
    # перерахувати регіони для нових рядків (вони вже гарантовано не перетинаються зі старими,
    # але можуть перетинатись одне з одним — assign_regions_and_exclude це врахує)
    # Присвоюємо region_id лише новим (старі вже мають коректний region_id/exclude).
    new_rows_by_id = {r["id"]: r for r in new_rows}
    if new_rows_by_id:
        groups = compute_regions(new_rows_by_id)
        existing_max_region = max(
            (int(r["region_id"][1:]) for r in rows if r.get("region_id", "").startswith("R")),
            default=0,
        )
        ordered = sorted(groups.items(), key=lambda kv: min(kv[1]))
        for i, (_root, member_ids) in enumerate(ordered, start=existing_max_region + 1):
            region_id = f"R{i:04d}"
            for rid in member_ids:
                new_rows_by_id[rid]["region_id"] = region_id
                new_rows_by_id[rid]["exclude"] = "0"  # вже відфільтровано до max 2/регіон у mine_new_regions

    with open(FINDINGS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for r in all_rows:
            writer.writerow({k: r.get(k, "") for k in CSV_HEADER})

    active = [r for r in all_rows if r.get("exclude") != "1"]
    lang_counts = Counter(r["lang"] for r in active)
    cwe_counts = Counter(r["cwe"] or "UNKNOWN" for r in active)

    print(f"\n[dedupe_regions] Записано {FINDINGS_PATH}: усього {len(all_rows)} рядків, "
          f"активних (exclude!=1): {len(active)}")
    print("\n[dedupe_regions] Активні — розподіл за мовою:")
    for lang, cnt in lang_counts.most_common():
        print(f"  {lang:<12} {cnt}")
    print("\n[dedupe_regions] Активні — розподіл за CWE:")
    for cwe, cnt in cwe_counts.most_common():
        print(f"  {cwe:<15} {cnt}")


if __name__ == "__main__":
    main()
