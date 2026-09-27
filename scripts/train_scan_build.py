"""
Навчальна вибірка дистиляції: клонує репозиторії зі списку REPOS, сканує їх
Semgrep і будує data/train/findings_train.csv. Кожен репозиторій проходить
повний цикл окремо (клон -> скан підтеками -> видобування рядків, поки файли
на диску -> видалення), а проміжні результати кешуються в data/train/raw/ для
відновлення після переривання.

Приклад:
    python scripts/train_scan_build.py
"""

import csv
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from build_dataset import build_rows  # той самий фільтр, що й data/findings.csv
from dedupe_regions import assign_regions_and_exclude  # той самий region_id/exclude
from snippet_clean import clean_snippet

CORPUS_DIR = ROOT / "train_corpus"
RAW_DIR = ROOT / "data" / "train" / "raw"
OUT_PATH = ROOT / "data" / "train" / "findings_train.csv"
SOURCES_PATH = ROOT / "data" / "train" / "SOURCES.md"

SOURCES_HEADER = """# Джерела train_corpus/

Репозиторії, з яких побудовано навчальну вибірку для дистиляції
(`data/train/findings_train.csv`). Для кожного вказано коміт, зафіксований на
момент сканування. У таблиці лише успішно оброблені джерела: репозиторії, які
не вдалося клонувати, у вибірку не входять.

| Репозиторій | Коміт | Статус |
|---|---|---|
"""

# Окремий набір правил лише для навчальної вибірки — SEMGREP_CONFIG з .env
# (дослідницький/продуктовий) цей скрипт не читає і не чіпає.
TRAIN_SEMGREP_CONFIG = [
    "p/default", "p/secrets", "p/django", "p/flask", "p/react", "p/nodejs",
    "p/javascript", "p/typescript", "p/python", "p/owasp-top-ten",
]
# p/express у реєстрі Semgrep не існує ("Failed to download configuration
# from https://semgrep.dev/p/express HTTP 404"). Semgrep падає з exit 7 і
# 0 результатів, якщо хоч один --config невалідний — саме через це перший
# прогін з повним списком віддав 0 знахідок для всіх репозиторіїв одразу.
# Express-специфічні правила (javascript.express.*) вже входять до
# p/javascript і p/nodejs.

CHUNK_TIMEOUT_SECONDS = 40 * 60
MAX_FILES_PER_CHUNK = 2000
CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
SKIP_DIR_NAMES = {
    "tests", "test", "node_modules", "docs", "examples", "fixtures",
    "migrations", "locale", "translations",
}
MIN_FREE_GB_TO_CLONE = 8

# (тека_у_train_corpus, github_slug) — у порядку: Python, потім JS/TS,
# потім навмисно вразливі демо.
REPOS = [
    # Перших 31 не переставляти й не вставляти нове посередині: main()
    # призначає id послідовно за порядком REPOS/all_rows, тож уже
    # згенеровані data/train/teacher.csv (за старими id) розсинхронились би
    # з findings_train.csv, якби рядки, що йдуть перед ними в цьому списку,
    # змінились. Нове — лише дописувати в кінець.
    ("zulip", "zulip/zulip"),
    ("edx-platform", "openedx/edx-platform"),
    ("weblate", "WeblateOrg/weblate"),
    ("redash", "getredash/redash"),
    ("superset", "apache/superset"),
    ("wagtail", "wagtail/wagtail"),
    ("django-oscar", "django-oscar/django-oscar"),
    ("dispatch", "Netflix/dispatch"),
    ("addons-server", "mozilla/addons-server"),
    ("pretalx", "pretalx/pretalx"),
    ("airflow", "apache/airflow"),
    ("saleor", "saleor/saleor"),
    ("celery", "celery/celery"),
    ("scrapy", "scrapy/scrapy"),
    ("nocodb", "nocodb/nocodb"),
    ("appsmith", "appsmithorg/appsmith"),
    ("Ghost", "TryGhost/Ghost"),
    ("strapi", "strapi/strapi"),
    ("directus", "directus/directus"),
    ("n8n", "n8n-io/n8n"),
    ("parse-server", "parse-community/parse-server"),
    ("keystone", "keystonejs/keystone"),
    ("payload", "payloadcms/payload"),
    ("medusa", "medusajs/medusa"),
    ("twenty", "twentyhq/twenty"),
    ("formbricks", "formbricks/formbricks"),
    ("pygoat", "adeyosemanputra/pygoat"),
    ("Vulnerable-Flask-App", "we45/Vulnerable-Flask-App"),
    ("dvna", "appsecco/dvna"),
    ("dvws-node", "snoopysecurity/dvws-node"),
    ("NodeGoat", "OWASP/NodeGoat"),
    # --- додано на прохання "доскануй ще репозиторіїв" (ціль 5000+) ---
    ("treeherder", "mozilla/treeherder"),
    ("pulpcore", "pulp/pulpcore"),
    ("awx", "ansible/awx"),
    ("securedrop", "freedomofpress/securedrop"),
    ("kolibri", "learningequality/kolibri"),
    ("InvenTree", "inventree/InvenTree"),
    ("OpenSlides", "OpenSlides/OpenSlides"),
    ("ArchiveBox", "ArchiveBox/ArchiveBox"),
    ("integrations-core", "DataDog/integrations-core"),
    ("prefect", "PrefectHQ/prefect"),
    ("Kiwi", "kiwitcms/Kiwi"),
    ("django-cms", "django-cms/django-cms"),
    ("ComfyUI", "comfyanonymous/ComfyUI"),
    ("outline", "outline/outline"),
    ("tinacms", "tinacms/tinacms"),
    ("Rocket.Chat", "RocketChat/Rocket.Chat"),
    ("mattermost", "mattermost/mattermost"),
    ("kibana", "elastic/kibana"),
    ("grafana", "grafana/grafana"),
    ("novu", "novuhq/novu"),
    ("immich", "immich-app/immich"),
]

CSV_HEADER = [
    "id", "repo", "lang", "file", "start_line", "end_line", "rule_id", "cwe", "owasp",
    "severity", "message", "snippet", "snippet_clean", "label", "comment",
    "region_id", "exclude",
]


def free_gb():
    return shutil.disk_usage(ROOT).free / (1024 ** 3)


def _clear_readonly_and_retry(func, path, exc_info):
    """shutil.rmtree onerror: git позначає файли в .git/objects як
    read-only на Windows — звичайний rmtree(ignore_errors=True) на це
    мовчки провалюється, і репозиторій лишається на диску (саме так
    сталось із перших 9 репо цього прогону — свобода диска не
    звільнялась, хоча скрипт друкував "видалено")."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def safe_rmtree(path: Path, label: str):
    shutil.rmtree(path, onerror=_clear_readonly_and_retry)
    if path.exists():
        # shutil.rmtree (Win32 API, MAX_PATH=260) не бере глибокі шляхи
        # (напр. kibana/x-pack/solutions/.../historical_results_list) —
        # `rm -rf` з Git Bash/MSYS бере такі шляхи там, де shutil не бере.
        subprocess.run(["rm", "-rf", str(path)], capture_output=True)
    if path.exists():
        print(f"[train_scan] {label}: Увага — не вдалося повністю видалити {path} "
              f"(лишились файли з блокуванням) — місце на диску не звільнено повністю", flush=True)
    else:
        print(f"[train_scan] {label}: репозиторій видалено з диска", flush=True)


def clone_repo(name: str, slug: str, dest: Path):
    # core.longpaths=true завжди, не лише як fallback: git без нього іноді
    # "успішно" (код виходу 0) клонує репо, тихо не матеріалізувавши
    # найглибші шляхи (>260 символів) — kibana (x-pack/solutions/security/
    # .../historical_results_list) саме так один раз завалила весь скрипт
    # (FileNotFoundError у os.walk), а не помилкою клонування.
    url = f"https://github.com/{slug}.git"
    result = subprocess.run(
        ["git", "-c", "core.longpaths=true", "clone", "--depth", "1", url, str(dest)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        err = result.stderr.strip().splitlines()[-1] if result.stderr else "помилка"
        return None, err
    rev = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    return rev, None


def source_already_logged(slug: str) -> bool:
    """Чи вже є рядок цього репозиторію в SOURCES.md. Порівняння з завершальним
    "|" — щоб zulip/zulip не збігся з zulip/zulip-mobile."""
    if not SOURCES_PATH.exists():
        return False
    marker = f"| {slug} |"
    with open(SOURCES_PATH, "r", encoding="utf-8") as f:
        return any(line.startswith(marker) for line in f)


def log_source(slug: str, rev: str):
    """Дописує в SOURCES.md рядок успішно клонованого репозиторію — три колонки
    (репозиторій, коміт, статус) під заголовок таблиці. Невдалі клони в таблицю
    не потрапляють (лише в консоль): таблиця документує склад вибірки, а
    репозиторій, який не вдалося клонувати, у вибірку не входить. Повторний
    запис того самого репозиторію пропускається, тож перезапуск скрипта після
    переривання не дублює рядки."""
    if source_already_logged(slug):
        return
    SOURCES_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not SOURCES_PATH.exists():
        SOURCES_PATH.write_text(SOURCES_HEADER, encoding="utf-8")
    with open(SOURCES_PATH, "a", encoding="utf-8") as f:
        f.write(f"| {slug} | `{rev}` | OK |\n")


def _walk_files(path: Path):
    """os.walk (не pathlib.rglob) з onerror, що ігнорує помилку замість
    падіння всього обходу — деякі підтеки (напр. kibana/x-pack/... з
    Windows-шляхом > 260 символів) git клонує "успішно" (код виходу 0),
    але git.longpaths не завжди рятує всі такі шляхи; pathlib.rglob() на
    таких падає FileNotFoundError і валить увесь скрипт замість одного
    репозиторію."""
    for dirpath, dirnames, filenames in os.walk(path, onerror=lambda e: None):
        for fname in filenames:
            yield Path(dirpath) / fname


def count_code_files(path: Path) -> int:
    count = 0
    for p in _walk_files(path):
        if p.suffix.lower() in CODE_EXTENSIONS:
            count += 1
    return count


def dir_stats(path: Path):
    """(кількість файлів, розмір у МБ) — для повідомлень про помилку."""
    file_count = 0
    total_bytes = 0
    for p in _walk_files(path):
        file_count += 1
        try:
            total_bytes += p.stat().st_size
        except OSError:
            pass
    return file_count, total_bytes / (1024 * 1024)


def list_targets(repo_dir: Path):
    """Директорії для сканування: топ-рівневі підтеки (без SKIP_DIR_NAMES),
    з підтеками другого рівня замість тих, що мають > MAX_FILES_PER_CHUNK
    python/js/ts-файлів. Файли (на будь-якому з цих двох рівнів) не
    включаються — лише директорії."""
    targets = []
    for entry in sorted(repo_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_dir() or entry.name == ".git" or entry.name.lower() in SKIP_DIR_NAMES:
            continue
        file_count = count_code_files(entry)
        if file_count == 0:
            continue
        if file_count > MAX_FILES_PER_CHUNK:
            subdirs = [
                s for s in sorted(entry.iterdir(), key=lambda p: p.name)
                if s.is_dir() and s.name.lower() not in SKIP_DIR_NAMES
            ]
            if subdirs:
                targets.extend(subdirs)
            else:
                targets.append(entry)  # немає куди ділити далі — доведеться сканувати як є
        else:
            targets.append(entry)
    return targets


def semgrep_cmd(target: Path):
    # --jobs 1 --max-memory 800 обмежують пікову пам'ять одного процесу
    # Semgrep — на цій машині лише ~4 ГБ вільно з 16 ГБ, дефолтна
    # паралельність один раз уже OOM'нула систему.
    cmd = ["semgrep", "scan", "--no-git-ignore", "--metrics=off", "--json",
           "--jobs", "1", "--max-memory", "800"]
    for config in TRAIN_SEMGREP_CONFIG:
        cmd += ["--config", config]
    cmd += [str(target)]
    return cmd


def run_semgrep(target: Path):
    """Повертає (results, None) на успіх або (None, причина) на невдачу —
    ніколи не повертає [] мовчки замість помилки."""
    try:
        result = subprocess.run(
            semgrep_cmd(target), capture_output=True, text=True, encoding="utf-8",
            timeout=CHUNK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return None, f"ТАЙМАУТ (> {CHUNK_TIMEOUT_SECONDS // 60} хв)"
    if result.returncode != 0:
        # Semgrep пише деталі помилки (напр. "invalid configuration file",
        # "Failed to download ... HTTP 404") у JSON-полі "errors" у stdout,
        # а не в stderr — stderr часто містить лише службові WARNING-рядки.
        json_errors = None
        try:
            json_errors = json.loads(result.stdout).get("errors")
        except (json.JSONDecodeError, AttributeError):
            pass
        detail = f"errors: {json_errors}" if json_errors else f"stderr: {result.stderr[-400:]!r}"
        return None, f"код виходу {result.returncode}, {detail}"
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, f"некоректний JSON, stderr: {result.stderr[-400:]!r}"
    return data.get("results", []), None


def scan_repo_raw(name: str, repo_dir: Path):
    """Повертає сирі результати Semgrep усіх чанків репозиторію (кешованих
    по чанку в data/train/raw/<repo>__<чанк>.json)."""
    targets = list_targets(repo_dir)
    results = []
    failed = []
    for target in targets:
        rel = target.relative_to(repo_dir)
        chunk_cache = RAW_DIR / f"{name}__{str(rel).replace(os.sep, '_')}.json"
        if chunk_cache.exists():
            with open(chunk_cache, "r", encoding="utf-8") as f:
                chunk_results = json.load(f)
            print(f"[train_scan]   {name}/{rel}: кешовано ({len(chunk_results)})", flush=True)
            results.extend(chunk_results)
            continue

        t0 = time.time()
        chunk_results, error = run_semgrep(target)
        elapsed = time.time() - t0
        if error is not None:
            file_count, size_mb = dir_stats(target)
            print(f"[train_scan]   Помилка {name}/{rel}: {error} "
                  f"(за {elapsed:.0f}с; підтека: {file_count} файлів, {size_mb:.1f} МБ) — "
                  f"не кешую, буде повторено наступного запуску", flush=True)
            failed.append(str(rel))
            continue

        with open(chunk_cache, "w", encoding="utf-8") as f:
            json.dump(chunk_results, f)
        print(f"[train_scan]   {name}/{rel}: {len(chunk_results)} за {elapsed:.0f}с", flush=True)
        results.extend(chunk_results)

    if failed:
        print(f"[train_scan] {name}: невдалих підтек: {len(failed)} ({', '.join(failed)})", flush=True)
    return results


def build_repo_rows(name: str, raw_results: list):
    """build_rows() читає код із файлів на диску — має викликатись, поки
    репозиторій ще існує (до видалення)."""
    filtered = build_rows(raw_results, corpus_marker="train_corpus")
    rows = []
    for r in filtered:
        lang = r["lang"]
        snippet = r["snippet"]
        rows.append({
            "repo": r["repo"], "lang": lang, "file": r["file"],
            "start_line": r["start_line"], "end_line": r["end_line"], "rule_id": r["rule_id"],
            "cwe": r["cwe"], "owasp": r["owasp"], "severity": r["severity"],
            "message": r["message"], "snippet": snippet,
            "snippet_clean": clean_snippet(snippet, lang),
        })
    return rows


def process_repo(name: str, slug: str):
    rows_cache = RAW_DIR / f"{name}_rows.json"
    if rows_cache.exists():
        with open(rows_cache, "r", encoding="utf-8") as f:
            rows = json.load(f)
        print(f"[train_scan] {name}: беру кешовані рядки ({len(rows)}) — репозиторій уже оброблено раніше", flush=True)
        return rows

    repo_dir = CORPUS_DIR / name
    if not repo_dir.exists():
        free = free_gb()
        if free < MIN_FREE_GB_TO_CLONE:
            print(f"[train_scan] Зупинка: вільно лише {free:.1f} ГБ (< {MIN_FREE_GB_TO_CLONE} ГБ) "
                  f"перед клонуванням {slug}.", flush=True)
            return None
        print(f"[train_scan] {name}: клоную {slug}...", flush=True)
        rev, err = clone_repo(name, slug, repo_dir)
        if err is not None:
            print(f"[train_scan] {name}: недоступний ({err}) — пропускаю", flush=True)
            return []
        log_source(slug, rev)
    else:
        print(f"[train_scan] {name}: уже клоновано (з попереднього запуску)", flush=True)

    t0 = time.time()
    raw_results = scan_repo_raw(name, repo_dir)
    rows = build_repo_rows(name, raw_results)
    elapsed = time.time() - t0
    print(f"[train_scan] {name}: {len(raw_results)} сирих -> {len(rows)} після фільтрації "
          f"(мова/тести/node_modules/dist/мінімізовані) за {elapsed:.0f}с", flush=True)

    with open(rows_cache, "w", encoding="utf-8") as f:
        json.dump(rows, f)

    safe_rmtree(repo_dir, name)
    return rows


RAW_STOP_THRESHOLD = 6500
PROGRESS_PRINT_EVERY = 5


def main():
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    all_rows = []
    cumulative_raw = 0

    for i, (name, slug) in enumerate(REPOS, start=1):
        rows = process_repo(name, slug)
        if rows is None:
            print("[train_scan] Зупинено через брак місця на диску — решту репозиторіїв не обробляю.", flush=True)
            break
        all_rows.extend(rows)
        cumulative_raw += len(rows)

        if i % PROGRESS_PRINT_EVERY == 0:
            print(f"[train_scan] Накопичено рядків (після фільтрації) після {i} репозиторіїв: {cumulative_raw}", flush=True)

        if cumulative_raw > RAW_STOP_THRESHOLD:
            print(f"[train_scan] Накопичена кількість перевалила за {RAW_STOP_THRESHOLD} "
                  f"({cumulative_raw}) — решту репозиторіїв не сканую.", flush=True)
            break

    print(f"[train_scan] Усього рядків (після фільтрації, до дедупу регіонів): {len(all_rows)}", flush=True)

    out_rows = []
    for i, r in enumerate(all_rows, start=1):
        row = dict(r)
        row["id"] = f"T{i:05d}"
        row["label"] = ""
        row["comment"] = ""
        out_rows.append(row)

    excluded = assign_regions_and_exclude(out_rows)
    region_count = len(set(r["region_id"] for r in out_rows))
    print(f"[train_scan] Регіонів (±5 рядків): {region_count}, позначено exclude=1 "
          f"(майже-дублікат регіону, лишається max 2 на регіон): {excluded}", flush=True)

    with open(OUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for r in out_rows:
            writer.writerow({k: r.get(k, "") for k in CSV_HEADER})
    print(f"[train_scan] Записано {OUT_PATH}: {len(out_rows)} рядків "
          f"(активних exclude!=1: {sum(1 for r in out_rows if r['exclude'] != '1')})", flush=True)


if __name__ == "__main__":
    main()
