"""
Автоматична оцінка пояснень SLM (results/explanations.jsonl) відносно
data/findings.csv. Пише results/metrics.csv (рядок на кожне пояснення)
і друкує зведення, згруповане за model/device/prompt_version/temperature.

Приклад:
    python scripts/evaluate.py
"""

import argparse
import ast
import csv
import difflib
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass  # старіші Python без reconfigure — консоль (напр. cp1251) інколи не може

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv()

from snippet_clean import clean_snippet  # той самий чистильник, що бачить модель (main.py, bench.py)


def apply_java_home():
    """Якщо в .env задано JAVA_HOME (напр. портативний JDK 17 для LanguageTool),
    додає <JAVA_HOME>/bin на початок PATH цього процесу — без потреби вручну
    префіксувати команду при кожному запуску."""
    java_home = os.getenv("JAVA_HOME")
    if not java_home:
        return
    java_bin = Path(java_home) / "bin"
    if not java_bin.exists():
        print(f"[evaluate] Увага: JAVA_HOME={java_home!r}, але {java_bin} не існує.")
        return
    os.environ["PATH"] = str(java_bin) + os.pathsep + os.environ.get("PATH", "")


apply_java_home()

JSONL_PATH = ROOT / "results" / "explanations.jsonl"
FINDINGS_PATH = ROOT / "data" / "findings.csv"
REFERENCES_PATH = ROOT / "data" / "references.csv"
CWE_KEYWORDS_PATH = ROOT / "data" / "cwe_keywords.json"
GLOSSARY_PATH = ROOT / "data" / "glossary_uk.json"
CWE_REFERENCES_PATH = ROOT / "data" / "cwe_references_uk.json"
EMBED_CACHE_PATH = ROOT / "results" / "embed_cache.json"
MANUAL_REVIEW_PATH = ROOT / "data" / "manual_review.csv"
METRICS_PATH = ROOT / "results" / "metrics.csv"
AVOID_TOP_PATH = ROOT / "results" / "avoid_top.csv"
FIX_PASS_CACHE_PATH = ROOT / "results" / "fix_pass_cache.json"
TS_CHECK_SCRIPT = ROOT / "scripts" / "ts_check.js"

CONTEXT = 5  # має збігатись із ±5 рядків у build_dataset.py / main.py
MIN_JAVA_MAJOR = 17
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
EMBED_MODEL = "bge-m3"
TRIVIAL_RATIO = 0.3
ALIGN_MATCH_THRESHOLD = 0.6  # поріг difflib для вирівнювання патча в build_patched_lines

# Ключі кешу fix_pass_cache.json префіксуються версією логіки патчингу/сканування
# нижче — зміна build_patched_lines чи run_semgrep_multi без бампу версії
# призведе до читання застарілих (несумісних) закешованих результатів.
CACHE_VERSION = "v3"

LATIN_WHITELIST = {
    "SQL", "XSS", "HTTP", "HTTPS", "HTML", "JSON", "API", "URL", "CSRF", "JWT", "CWE", "OWASP",
}

STOPWORD_IDENTIFIERS = {
    "if", "else", "elif", "for", "while", "def", "function", "return", "import", "from",
    "class", "const", "let", "var", "this", "self", "true", "false", "null", "none",
    "and", "or", "not", "in", "is", "try", "except", "catch", "throw", "new",
    "public", "private", "static", "void", "async", "await", "export", "default", "require",
}

SECTION_ORDER = ("prozorist", "obgrunt", "diev")
SECTION_PATTERNS = {
    "prozorist": re.compile(r"прозор", re.IGNORECASE),
    "obgrunt": re.compile(r"обґрунт|обгрунт", re.IGNORECASE),
    "diev": re.compile(r"дієв", re.IGNORECASE),
}

CODE_BLOCK_RE = re.compile(r"```(?:\w+)?\n?(.*?)```", re.DOTALL)
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
RU_ONLY_CHARS_RE = re.compile(r"[ыэъёЫЭЪЁ]")

MD_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s*", re.MULTILINE)
MD_LIST_NUM_RE = re.compile(r"^\s*\d+[.)]\s*", re.MULTILINE)
MD_LIST_BULLET_RE = re.compile(r"^\s*[-*+]\s+", re.MULTILINE)
PUNCT_SPACE_RE = re.compile(r"[ \t]+([,.)\:;])")
MULTI_SPACE_RE = re.compile(r"[ \t]+")

# LanguageTool: ці правила систематично спрацьовують як артефакт вирізання
# коду/markdown (зайві/бракуючі пробіли навколо видаленого тексту), а не як
# реальні мовні помилки — вимикаємо. short_vs_long_dash/типографські —
# теж не про якість пояснення. Константа, щоб легко переглянути список.
DISABLED_LT_RULE_IDS = {
    "WHITESPACE_RULE",
    "COMMA_PARENTHESIS_WHITESPACE",
    "short_vs_long_dash",
}
DISABLED_LT_CATEGORIES = {"TYPOGRAPHY"}  # захисна сітка: лапки/тире/апострофи й под.


# --- Java / LanguageTool ---------------------------------------------------

def check_java():
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        print(f"[evaluate] Java не знайдено в PATH. lt_errors_per_100w вимагає Java >= {MIN_JAVA_MAJOR}.")
        print("[evaluate] Зупиняюсь — встановіть Java (або вкажіть JAVA_HOME в .env) і повторіть запуск.")
        sys.exit(1)

    version_output = result.stderr or result.stdout
    m = re.search(r'version "(\d+)', version_output)
    if not m:
        print(f"[evaluate] Не вдалося визначити версію Java з виводу: {version_output!r}")
        print("[evaluate] Зупиняюсь.")
        sys.exit(1)

    major = int(m.group(1))
    if major < MIN_JAVA_MAJOR:
        print(f"[evaluate] Знайдено Java {major}, але LanguageTool вимагає >= {MIN_JAVA_MAJOR}.")
        print("[evaluate] Зупиняюсь — оновіть Java (або JAVA_HOME в .env) і повторіть запуск.")
        sys.exit(1)

    print(f"[evaluate] Java {major} — OK для LanguageTool.")


_lt_tool = None
LT_MATCH_LOG = []  # [(rule_id, example_text), ...] — для топ-15 наприкінці


def get_lt_tool():
    global _lt_tool
    if _lt_tool is None:
        import language_tool_python
        _lt_tool = language_tool_python.LanguageTool("uk-UA")
        _lt_tool.disabled_rules = set(DISABLED_LT_RULE_IDS)
    return _lt_tool


def lt_errors_per_100w(text):
    words = WORD_RE.findall(text)
    if not words:
        return None
    tool = get_lt_tool()
    matches = [
        m for m in tool.check(text)
        if m.rule_id not in DISABLED_LT_RULE_IDS
        and getattr(m, "category", None) not in DISABLED_LT_CATEGORIES
    ]
    for m in matches:
        example = (getattr(m, "context", "") or "").strip()
        if not example:
            start = max(0, m.offset - 25)
            example = text[start:m.offset + m.error_length + 25].strip()
        LT_MATCH_LOG.append((m.rule_id, example))
    return round(len(matches) / len(words) * 100, 2)


def print_lt_top15():
    print("\n[evaluate] === Топ-15 правил LanguageTool (за кількістю спрацювань) ===")
    if not LT_MATCH_LOG:
        print("  (жодного спрацювання)")
        return
    counts = Counter(rid for rid, _ in LT_MATCH_LOG)
    examples = defaultdict(list)
    for rid, ex in LT_MATCH_LOG:
        if ex not in examples[rid] and len(examples[rid]) < 2:
            examples[rid].append(ex)
    for rid, cnt in counts.most_common(15):
        print(f"\n{rid}  (спрацювань: {cnt})")
        for ex in examples[rid]:
            print(f"    напр.: {ex}")


# --- Текстові метрики -------------------------------------------------------

def strip_code_blocks(text):
    """Прибирає і огороджені блоки коду, і inline-код перед мовними метриками
    (LanguageTool, ru_chars, latin_ratio), щоб код не спотворював статистику."""
    text = CODE_BLOCK_RE.sub(" ", text or "")
    text = INLINE_CODE_RE.sub(" ", text)
    return text


def strip_fenced_blocks_only(text):
    """Прибирає лише огороджені блоки коду (inline-код лишається) — для
    cwe_keyword_hit/off_topic_class, де inline-згадки термінів важливі."""
    return CODE_BLOCK_RE.sub(" ", text or "")


def strip_markdown(text):
    """Прибирає markdown-розмітку (заголовки, жирний шрифт, нумеровані й
    марковані списки), яку LanguageTool інакше сприймає як звичайний текст
    і хибно валить."""
    text = MD_HEADING_RE.sub("", text)
    text = text.replace("**", "").replace("__", "")
    text = MD_LIST_NUM_RE.sub("", text)
    text = MD_LIST_BULLET_RE.sub("", text)
    return text


def prepare_text_for_lt(explanation):
    """Повний препроцесинг тексту перед LanguageTool: прибрати код (огороджені
    блоки й inline), markdown, зайві пробіли — включно з пробілами перед
    , . ) : ;, які лишає по собі саме вирізання inline-коду."""
    text = strip_code_blocks(explanation)
    text = strip_markdown(text)
    text = MULTI_SPACE_RE.sub(" ", text)
    text = PUNCT_SPACE_RE.sub(r"\1", text)
    return text


def find_sections(text):
    idx = {}
    for key, pattern in SECTION_PATTERNS.items():
        m = pattern.search(text or "")
        idx[key] = m.start() if m else None
    return idx


def structure_ok(idx):
    if any(idx.get(k) is None for k in SECTION_ORDER):
        return False
    return idx["prozorist"] < idx["obgrunt"] < idx["diev"]


def section_slice(text, idx, key):
    text = text or ""
    start = idx.get(key)
    if start is None:
        return text
    pos = SECTION_ORDER.index(key)
    end = None
    for nxt in SECTION_ORDER[pos + 1:]:
        if idx.get(nxt) is not None:
            end = idx[nxt]
            break
    return text[start:end]


def extract_target_lines(snippet, start_line, end_line, context=CONTEXT):
    lines = snippet.splitlines()
    prefix = min(context, max(0, start_line - 1))
    n = max(1, end_line - start_line + 1)
    return lines[prefix: prefix + n]


def extract_identifiers(code_lines, min_len=3):
    text = "\n".join(code_lines)
    idents = set(IDENT_RE.findall(text))
    return {i for i in idents if len(i) >= min_len and i.lower() not in STOPWORD_IDENTIFIERS}


def localization_hit(explanation, idx, snippet, start_line, end_line):
    target_lines = extract_target_lines(snippet, start_line, end_line)
    idents = extract_identifiers(target_lines)
    if not idents:
        return None
    section_text = section_slice(explanation, idx, "prozorist") if idx.get("prozorist") is not None else explanation
    for ident in idents:
        if re.search(r"\b" + re.escape(ident) + r"\b", section_text):
            return True
    return False


INDENTED_LINE_RE = re.compile(r"^(?: {4,}|\t)(.*)$")


def extract_indented_block(text):
    """Фолбек, коли в «Дієвість» немає огородженого блоку: бере найдовший суцільний
    прогін рядків з відступом 4+ пробіли (або таб) як блок коду."""
    lines = text.splitlines()
    best, current = [], []
    for line in lines:
        if INDENTED_LINE_RE.match(line) or (line.strip() == "" and current):
            current.append(line)
        else:
            if len(current) > len(best):
                best = current
            current = []
    if len(current) > len(best):
        best = current
    while best and best[-1].strip() == "":
        best.pop()
    if not best:
        return ""
    return textwrap.dedent("\n".join(best)).strip("\n")


def extract_fix_code(explanation, idx):
    text = section_slice(explanation, idx, "diev") if idx.get("diev") is not None else explanation
    blocks = CODE_BLOCK_RE.findall(text)
    if blocks:
        # Блоки коду часто йдуть відступом як частина нумерованого/маркованого
        # списку в Markdown — dedent прибирає цей "візуальний" відступ, щоб
        # ast.parse/node --check не хибно валили синтаксично коректний код.
        cleaned = [textwrap.dedent(b).strip("\n") for b in blocks]
        return "\n".join(cleaned).strip()
    return extract_indented_block(text)


def node_check(code):
    fd, path = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        result = subprocess.run(["node", "--check", path], capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except Exception:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def ts_check(code, tsx=False):
    """Синтаксична перевірка TS/TSX через parseDiagnostics пакета "typescript"
    (scripts/ts_check.js, той самий пакет, що й strip_ts_comments.js) —
    True/False, або None при збої node/скрипта (тоді метрика -> NA)."""
    fd, path = tempfile.mkstemp(suffix=".tsx" if tsx else ".ts")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        result = subprocess.run(
            ["node", str(TS_CHECK_SCRIPT), path], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        return bool(data.get("ok"))
    except Exception:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def compute_fix_syntax_ok(lang, abs_path, snippet_start, snippet_end, fix_code, clean_window_text=None):
    """Синтаксична коректність пропатченого повного файлу (а не ізольованого
    fix_code) — Python: ast.parse; JS: node --check; TS/TSX: parseDiagnostics
    пакета "typescript" (scripts/ts_check.js). Повертає (fix_syntax_ok, patch_mode)."""
    if not (fix_code or "").strip():
        return 0, ""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            orig_lines = f.readlines()
    except Exception:
        return "", ""
    patched_lines, _, _, patch_mode = build_patched_lines(
        orig_lines, snippet_start, snippet_end, fix_code, lang, clean_window_text)
    patched_text = "".join(patched_lines)
    if lang == "python":
        try:
            ast.parse(patched_text)
            return 1, patch_mode
        except SyntaxError:
            return 0, patch_mode
    if lang == "javascript":
        result = node_check(patched_text)
        return ("" if result is None else (1 if result else 0)), patch_mode
    if lang == "typescript":
        result = ts_check(patched_text, tsx=Path(abs_path).suffix.lower() == ".tsx")
        return ("" if result is None else (1 if result else 0)), patch_mode
    return "", patch_mode


def ru_chars(text):
    return len(RU_ONLY_CHARS_RE.findall(text or ""))


def latin_ratio(text, snippet_identifiers):
    words = WORD_RE.findall(text or "")
    if not words:
        return None
    excluded = {w.lower() for w in snippet_identifiers}
    count = 0
    for w in words:
        if re.fullmatch(r"[A-Za-z]+", w):
            if w.upper() in LATIN_WHITELIST or w.lower() in excluded:
                continue
            count += 1
    return round(count / len(words), 4)


# --- cwe_keyword_hit / off_topic_class (data/cwe_keywords.json) ------------

def load_cwe_keywords():
    if not CWE_KEYWORDS_PATH.exists():
        print(f"[evaluate] Увага: {CWE_KEYWORDS_PATH} відсутній — "
              f"cwe_keyword_hit/off_topic_class будуть NA для всіх рядків.")
        return None
    with open(CWE_KEYWORDS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def split_cwes(cwe_field):
    return [c.strip() for c in (cwe_field or "").split(";") if c.strip()]


def cwe_keyword_hit(cwe_field, text, cwe_keywords):
    """1/0, якщо текст (без коду) збігається з cwe[<CWE>].expected; "" (NA),
    якщо жоден із CWE знахідки не описаний у cwe_keywords.json."""
    if not cwe_keywords:
        return ""
    defs = [cwe_keywords.get("cwe", {})[c] for c in split_cwes(cwe_field) if c in cwe_keywords.get("cwe", {})]
    if not defs:
        return ""
    for d in defs:
        pattern = d.get("expected")
        if pattern and re.search(pattern, text, re.IGNORECASE):
            return 1
    return 0


def off_topic_class(cwe_field, text, cwe_keywords):
    """1, якщо в тексті (без коду) згадано клас вразливості з classes, що не
    входить у related для жодного CWE цієї знахідки (тобто явно не по темі)."""
    if not cwe_keywords:
        return ""
    classes = cwe_keywords.get("classes", {})
    if not classes:
        return ""
    related = set()
    for c in split_cwes(cwe_field):
        d = cwe_keywords.get("cwe", {}).get(c)
        if d:
            related.update(d.get("related", []))
    for class_key, pattern in classes.items():
        if class_key in related:
            continue
        if pattern and re.search(pattern, text, re.IGNORECASE):
            return 1
    return 0


# --- rep_3gram / avoid_hits (data/glossary_uk.json) -------------------------

def rep_3gram(text):
    """1 − унікальні/усі 3-грами слів у тексті — міра повторюваності (0=без
    повторів, ближче до 1 = багато однакових трислівних фраз)."""
    words = [w.lower() for w in WORD_RE.findall(text or "")]
    if len(words) < 3:
        return ""
    grams = list(zip(words, words[1:], words[2:]))
    if not grams:
        return ""
    return round(1 - len(set(grams)) / len(grams), 4)


def load_glossary():
    if not GLOSSARY_PATH.exists():
        print(f"[evaluate] Увага: {GLOSSARY_PATH} відсутній — avoid_hits буде NA для всіх рядків.")
        return None
    with open(GLOSSARY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def build_avoid_patterns(glossary):
    """terms[].avoid і avoid_global[].pattern — обидва вже регулярні вирази
    (не буквальні підрядки — re.escape тут ламає їх, напр. "злоумы?шленник\\w*"
    перетворюється на пошук цього буквального тексту й ніколи не збігається).
    Повертає [(pattern_str, compiled_regex), ...] — pattern_str потрібен для
    results/avoid_top.csv."""
    patterns = []
    for term in glossary.get("terms", []):
        for a in term.get("avoid", []):
            if not a:
                continue
            try:
                patterns.append((a, re.compile(a, re.IGNORECASE)))
            except re.error as e:
                print(f"[evaluate] Некоректний regex у terms[].avoid ({a!r}): {e}")
    for g in glossary.get("avoid_global", []):
        pat = g.get("pattern")
        if pat:
            try:
                patterns.append((pat, re.compile(pat, re.IGNORECASE)))
            except re.error as e:
                print(f"[evaluate] Некоректний regex у avoid_global ({pat!r}): {e}")
    return patterns


def avoid_hits(text, avoid_patterns):
    """1, якщо в тексті (без коду) є бодай один збіг з avoid_patterns; 0 —
    жодного; "" (NA) — глосарій відсутній."""
    if avoid_patterns is None:
        return ""
    return 1 if any(rx.search(text or "") for _, rx in avoid_patterns) else 0


def matched_avoid_patterns(text, avoid_patterns):
    """Список pattern_str з avoid_patterns, що знайдені (re.search) у тексті —
    для агрегації results/avoid_top.csv."""
    if avoid_patterns is None:
        return []
    return [pat_str for pat_str, rx in avoid_patterns if rx.search(text or "")]


# --- fix_undefined (Python, pyflakes) ---------------------------------------

def pyflakes_undefined_names(code):
    import io
    from pyflakes.api import check as pyflakes_check
    from pyflakes.reporter import Reporter
    out, err = io.StringIO(), io.StringIO()
    try:
        pyflakes_check(code, "snippet.py", Reporter(out, err))
    except Exception:
        return set()
    return set(re.findall(r"undefined name '([^']+)'", out.getvalue()))


def line_indent(line):
    return line[:len(line) - len(line.lstrip(" \t"))]


def strip_blank_edges(fix_code):
    """3а: обрізає порожні рядки на початку й у кінці fix_code (артефакт
    0029 — фікс, що закінчувався порожнім рядком, «зіставлявся» нею з
    порожнім рядком на початку вікна)."""
    lines = (fix_code or "").splitlines()
    start = 0
    while start < len(lines) and lines[start].strip() == "":
        start += 1
    end = len(lines)
    while end > start and lines[end - 1].strip() == "":
        end -= 1
    return "\n".join(lines[start:end])


IMPORT_RE_PY = re.compile(r"^(import\s+\S|from\s+\S+\s+import\b)")
IMPORT_RE_JS = re.compile(r"^(import\b|(?:const|let|var)\s+\S.*=\s*require\()")


def is_import_line(line, lang):
    s = (line or "").strip()
    if not s:
        return False
    if lang == "python":
        return bool(IMPORT_RE_PY.match(s))
    if lang in ("javascript", "typescript"):
        return bool(IMPORT_RE_JS.match(s))
    return False


def split_leading_imports(body_lines, lang):
    """3б: провідні import-рядки fix_code (від самого початку, порожні рядки
    між ними допускаються) — окремо від решти тіла фіксу."""
    if lang not in ("python", "javascript", "typescript"):
        return [], body_lines
    imports = []
    i, n = 0, len(body_lines)
    while i < n:
        line = body_lines[i]
        if is_import_line(line, lang):
            imports.append(line)
            i += 1
            continue
        if line.strip() == "":
            j = i
            while j < n and body_lines[j].strip() == "":
                j += 1
            if j < n and is_import_line(body_lines[j], lang):
                i = j
                continue
        break
    if imports:
        # блок порожніх рядків, що відділяв імпорти від тіла, — не частина тіла
        while i < n and body_lines[i].strip() == "":
            i += 1
    return imports, body_lines[i:]


def hoist_imports(lines, snippet_start, snippet_end, import_lines, lang):
    """3б: вставляє нові import-рядки фіксу перед першим наявним імпортом
    файлу (або в рядок 1, якщо імпортів немає); не дублює вже наявні (ні між
    собою, ні з файлом); зсуває snippet_start/snippet_end на кількість
    вставлених рядків."""
    if not import_lines:
        return lines, snippet_start, snippet_end
    existing = {l.strip() for l in lines if l.strip()}
    seen, dedup_new = set(), []
    for l in import_lines:
        key = l.strip()
        if key and key not in existing and key not in seen:
            seen.add(key)
            dedup_new.append(l)
    if not dedup_new:
        return lines, snippet_start, snippet_end
    insert_at = next((i for i, l in enumerate(lines) if is_import_line(l, lang)), 0)
    insert_block = [(l if l.endswith("\n") else l + "\n") for l in dedup_new]
    new_lines = lines[:insert_at] + insert_block + lines[insert_at:]
    shift = len(insert_block)
    return new_lines, snippet_start + shift, snippet_end + shift


def best_line_match(candidate_lines, target_line, min_idx=0):
    """Індекс (у candidate_lines, з позиції >= min_idx) рядка, що найкраще
    збігається з target_line за difflib.SequenceMatcher.ratio() по
    strip-рядках, і сам ratio. Порожні кандидати й порожній target — не
    якорі: (None, 0.0)."""
    target = (target_line or "").strip()
    if not target:
        return None, 0.0
    best_idx, best_ratio = None, 0.0
    for i in range(min_idx, len(candidate_lines)):
        cand = candidate_lines[i].strip()
        if not cand:
            continue
        ratio = difflib.SequenceMatcher(None, cand, target).ratio()
        if ratio > best_ratio:
            best_idx, best_ratio = i, ratio
    return best_idx, best_ratio


def build_patched_lines(lines, snippet_start, snippet_end, fix_code, lang="", clean_window_text=None):
    """Патчить lines (readlines() повного файлу, 1-індексація) кодом fix_code.
    Повертає (patched_lines, patched_start, patched_end, patch_mode), де
    patch_mode — "aligned" або "fallback".

    Спочатку обрізає порожні рядки на краях fix_code (3а) і виносить провідні
    import-рядки фіксу на початок файлу без дублювання, зсуваючи вікно (3б).
    Далі вирівнює решту фіксу (3в): шукає кандидатів для першого й останнього
    рядка фіксу серед рядків, які бачила модель (findings.csv::snippet_clean;
    якщо його довжина не збігається з вікном — свіжий clean_snippet() на вікні
    файлу), а не серед сирих рядків з коментарями. Порожні рядки не кандидати,
    останній рядок шукається лише з індексу першого. Збіг дає заміну
    піддіапазону з відступом відповідного рядка оригіналу; без збігу — фолбек:
    заміна всього вікна з відступом першого непорожнього рядка (3г)."""
    fix_code = strip_blank_edges(fix_code)
    fix_lines_all = fix_code.splitlines()

    import_lines, body_lines = split_leading_imports(fix_lines_all, lang)
    lines, snippet_start, snippet_end = hoist_imports(lines, snippet_start, snippet_end, import_lines, lang)

    if not body_lines:
        # фікс складався лише з імпортів (уже винесені нагору) — вікно прибирається
        patched = lines[:snippet_start - 1] + ["\n"] + lines[snippet_end:]
        return patched, snippet_start, snippet_start, "fallback"

    window_size = snippet_end - snippet_start + 1
    raw_window_lines = lines[snippet_start - 1:snippet_end]

    match_candidates = None
    if clean_window_text is not None:
        cand = clean_window_text.splitlines()
        if len(cand) == window_size:
            match_candidates = cand
    if match_candidates is None:
        raw_window_text = "".join(raw_window_lines)
        cleaned = clean_snippet(raw_window_text, lang).splitlines() if lang else []
        match_candidates = cleaned if len(cleaned) == window_size else [l.rstrip("\n") for l in raw_window_lines]

    aligned_start = aligned_end = None
    if match_candidates and body_lines:
        first_idx, first_ratio = best_line_match(match_candidates, body_lines[0])
        last_idx, last_ratio = best_line_match(
            match_candidates, body_lines[-1], min_idx=first_idx if first_idx is not None else 0)
        if (first_idx is not None and first_ratio >= ALIGN_MATCH_THRESHOLD
                and last_idx is not None and last_ratio >= ALIGN_MATCH_THRESHOLD):
            aligned_start = snippet_start + first_idx
            aligned_end = snippet_start + last_idx

    if aligned_start is not None:
        replace_start, replace_end = aligned_start, aligned_end
        orig_indent = line_indent(lines[replace_start - 1])
        patch_mode = "aligned"
    else:
        replace_start, replace_end = snippet_start, snippet_end
        first_nonblank = next((l for l in raw_window_lines if l.strip()), "")
        orig_indent = line_indent(first_nonblank)
        patch_mode = "fallback"

    dedented = textwrap.dedent("\n".join(body_lines)).splitlines()
    fix_lines = [(orig_indent + l if l.strip() else l) + "\n" for l in dedented]
    if not fix_lines:
        fix_lines = ["\n"]

    patched = lines[:replace_start - 1] + fix_lines + lines[replace_end:]
    patched_start = replace_start
    patched_end = replace_start + len(fix_lines) - 1
    return patched, patched_start, patched_end, patch_mode


def compute_fix_undefined(lang, abs_path, snippet_start, snippet_end, fix_code, clean_window_text=None):
    """Кількість нових undefined name (pyflakes) у пропатченій копії порівняно
    з оригіналом. Лише Python — JS/TS повертає "" (NA)."""
    if lang != "python":
        return ""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            orig_lines = f.readlines()
    except Exception:
        return ""
    patched_lines, _, _, _ = build_patched_lines(
        orig_lines, snippet_start, snippet_end, fix_code, lang, clean_window_text)
    try:
        orig_undef = pyflakes_undefined_names("".join(orig_lines))
        patched_undef = pyflakes_undefined_names("".join(patched_lines))
    except Exception as e:
        print(f"[evaluate] pyflakes помилка для {abs_path}: {e}")
        return ""
    return len(patched_undef - orig_undef)


# --- fix_pass / fix_trivial: повний файл з corpus/, патч у копії --------------
#
# Для кожного правила (rule_id):
#   1. Один виклик semgrep на всі оригінальні файли, що зустрічаються серед
#      знахідок з цим rule_id (кешується за (rule_id, file, sha256(file))).
#   2. Для кожного запису: чи перетинається якесь спрацювання оригіналу з
#      [snippet_start, snippet_end] цього запису. Якщо ні — NA.
#   3. Для решти — патчимо копію файлу (рядки snippet_start..snippet_end
#      замінюються на fix_code), копії з одним rule_id складаються в одну
#      тимчасову папку і скануються одним викликом semgrep.
#   4. fix_pass = 1, якщо в патченій копії немає спрацювань, що перетинаються
#      з новим діапазоном фрагмента; fix_trivial=1 (виправлення просто
#      видалило код) — такі випадки в pass не зараховуються.

def load_fix_pass_cache():
    if FIX_PASS_CACHE_PATH.exists():
        with open(FIX_PASS_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("original", {}), data.get("fix", {})
    return {}, {}


def save_fix_pass_cache(cache_original, cache_fix):
    FIX_PASS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(FIX_PASS_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump({"original": cache_original, "fix": cache_fix}, f, ensure_ascii=False, indent=2)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()[:16]


def sha256_text(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def safe_dirname(rule_id):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", rule_id)[:80]


def norm_abs(p):
    try:
        return str(Path(p).resolve()).replace("\\", "/").lower()
    except OSError:
        return str(p).replace("\\", "/").lower()


def overlaps(a_start, a_end, b_start, b_end):
    return a_start <= b_end and a_end >= b_start


def run_semgrep_multi(rule_id, targets, timeout=180):
    """Один виклик semgrep на кілька файлів/папок.
    Повертає (results, errors); (None, None) при помилці Semgrep."""
    if not targets:
        return [], []
    cmd = ["semgrep", "scan", "--config", f"r/{rule_id}", "--metrics=off", "--json", *[str(t) for t in targets]]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        data = json.loads(result.stdout)
        return data.get("results", []), data.get("errors", [])
    except Exception as e:
        print(f"[evaluate] Semgrep помилка (r/{rule_id}): {e}")
        return None, None


def results_by_file(results):
    m = defaultdict(list)
    for r in results:
        path = r.get("path", "")
        st = r.get("start", {}).get("line", 1)
        en = r.get("end", {}).get("line", st)
        m[norm_abs(path)].append((st, en))
    return m


def error_paths(errors):
    """Множина norm_abs-шляхів файлів, для яких semgrep повернув помилку
    парсингу (errors[].path у JSON-виводі semgrep scan)."""
    return {norm_abs(e["path"]) for e in (errors or []) if e.get("path")}


def compute_fix_trivial(abs_path, snippet_start, snippet_end, fix_code):
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        original_fragment = "".join(lines[snippet_start - 1:snippet_end])
    except Exception:
        return ""
    orig_len = len(re.sub(r"\s+", "", original_fragment))
    fix_len = len(re.sub(r"\s+", "", fix_code or ""))
    if orig_len == 0:
        return ""
    return 1 if fix_len < TRIVIAL_RATIO * orig_len else 0


def make_patched_copy(tmpdir, abs_path, snippet_start, snippet_end, fix_code, idx, lang="", clean_window_text=None):
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[evaluate] Не вдалося прочитати {abs_path}: {e}")
        return None, None, None

    patched, patched_start, patched_end, _ = build_patched_lines(
        lines, snippet_start, snippet_end, fix_code, lang, clean_window_text)

    ext = Path(abs_path).suffix or ".txt"
    copy_path = tmpdir / f"{idx:04d}_{Path(abs_path).stem}{ext}"
    with open(copy_path, "w", encoding="utf-8") as f:
        f.writelines(patched)
    return copy_path, patched_start, patched_end


def compute_fix_sast_batch(items, cache_original, cache_fix):
    """
    items: список dict з ключами:
        rule_id, lang, abs_path, snippet_start, snippet_end, fix_code
    Заповнює на місці item["fix_sast_pass"] (1 | 0 | "NA"), item["fix_trivial"]
    (1|0|"") і item["fix_undefined"] (Python: int нових undefined name; JS/TS: "").
    Групує роботу по rule_id — по одному виклику semgrep на "оригінали" і
    один на "патчені копії" для кожного правила.
    """
    by_rule = defaultdict(list)
    for it in items:
        by_rule[it["rule_id"]].append(it)

    for rule_id, group in by_rule.items():
        # --- 1. Оригінали: один semgrep-виклик на всі унікальні файли ---
        file_hashes = {}
        for it in group:
            fp = it["abs_path"]
            if fp not in file_hashes and os.path.exists(fp):
                file_hashes[fp] = sha256_file(fp)

        need_scan = [fp for fp, h in file_hashes.items()
                     if f"{CACHE_VERSION}::{rule_id}::{fp}::{h}" not in cache_original]
        if need_scan:
            results, _errors = run_semgrep_multi(rule_id, need_scan)
            by_file = results_by_file(results if results is not None else [])
            for fp in need_scan:
                ranges = by_file.get(norm_abs(fp), [])
                cache_original[f"{CACHE_VERSION}::{rule_id}::{fp}::{file_hashes[fp]}"] = (
                    ranges if results is not None else None)

        for it in group:
            fp = it["abs_path"]
            if fp not in file_hashes:
                it["_original_fires"] = None  # файл недоступний
                it["fix_trivial"] = ""
                it["fix_undefined"] = ""
                it["fix_syntax_ok"] = ""
                it["patch_mode"] = ""
                continue
            ranges = cache_original.get(f"{CACHE_VERSION}::{rule_id}::{fp}::{file_hashes[fp]}")
            if ranges is None:
                it["_original_fires"] = None
            else:
                it["_original_fires"] = any(
                    overlaps(s, e, it["snippet_start"], it["snippet_end"]) for s, e in ranges
                )
            it["fix_trivial"] = compute_fix_trivial(fp, it["snippet_start"], it["snippet_end"], it["fix_code"])
            it["fix_undefined"] = compute_fix_undefined(
                it.get("lang"), fp, it["snippet_start"], it["snippet_end"], it["fix_code"], it.get("clean_window_text"))
            it["fix_syntax_ok"], it["patch_mode"] = compute_fix_syntax_ok(
                it.get("lang"), fp, it["snippet_start"], it["snippet_end"], it["fix_code"], it.get("clean_window_text"))

        needs_patch = [it for it in group if it.get("_original_fires")]
        if needs_patch:
            tmpdir = Path(tempfile.mkdtemp(prefix=f"fixpass_{safe_dirname(rule_id)}_"))
            to_scan_meta = {}  # copy_path.name -> (item, cache_key)
            for i, it in enumerate(needs_patch):
                fkey = f"{CACHE_VERSION}::{sha256_text(rule_id, it['abs_path'], it['snippet_start'], it['snippet_end'], it['fix_code'])}"
                if fkey in cache_fix:
                    cached = cache_fix[fkey]
                    it["_fix_fires"] = cached.get("fired")
                    it["_fix_parse_error"] = cached.get("parse_error")
                    continue
                copy_path, p_start, p_end = make_patched_copy(
                    tmpdir, it["abs_path"], it["snippet_start"], it["snippet_end"], it["fix_code"], i,
                    it.get("lang"), it.get("clean_window_text"))
                if copy_path is None:
                    it["_fix_fires"] = None
                    it["_fix_parse_error"] = None
                    continue
                it["_patched_start"], it["_patched_end"] = p_start, p_end
                to_scan_meta[copy_path.name] = (it, fkey)

            if to_scan_meta:
                results, errors = run_semgrep_multi(rule_id, [tmpdir])
                by_file = results_by_file(results if results is not None else [])
                err_files = error_paths(errors) if results is not None else set()
                for copy_name, (it, fkey) in to_scan_meta.items():
                    if results is None:
                        it["_fix_fires"] = None
                        it["_fix_parse_error"] = None
                        continue
                    copy_abs = norm_abs(tmpdir / copy_name)
                    ranges = by_file.get(copy_abs, [])
                    fired = any(overlaps(s, e, it["_patched_start"], it["_patched_end"]) for s, e in ranges)
                    parse_error = copy_abs in err_files
                    it["_fix_fires"] = fired
                    it["_fix_parse_error"] = parse_error
                    cache_fix[fkey] = {"fired": fired, "parse_error": parse_error}

            shutil.rmtree(tmpdir, ignore_errors=True)

        for it in group:
            if not it.get("_original_fires"):
                it["fix_sast_pass"] = "NA"
                it["fix_valid"] = "NA"
                continue
            fix_fires = it.get("_fix_fires")
            if fix_fires is None:
                it["fix_sast_pass"] = "NA"
                it["fix_valid"] = "NA"
                continue
            passed = not fix_fires
            if it.get("fix_trivial") == 1:
                passed = False
            it["fix_sast_pass"] = 1 if passed else 0

            # fix_valid: синтаксично коректний повний файл + semgrep не впав
            # на парсингу копії + правило більше не спрацьовує.
            syntax_ok = it.get("fix_syntax_ok")
            parse_error = it.get("_fix_parse_error")
            if syntax_ok in ("", None) or parse_error is None:
                it["fix_valid"] = "NA"
            else:
                it["fix_valid"] = 1 if (syntax_ok == 1 and not parse_error and not fix_fires) else 0


# --- cosine_ref / chrf_ref (опційно, лише якщо є data/references.csv) ------

def load_references():
    if not REFERENCES_PATH.exists():
        return {}
    with open(REFERENCES_PATH, "r", encoding="utf-8", newline="") as f:
        return {row["id"]: row["reference"] for row in csv.DictReader(f)}


def get_embedding(text):
    import requests
    resp = requests.post(f"{OLLAMA_HOST}/api/embed", json={"model": EMBED_MODEL, "input": text}, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    embeddings = data.get("embeddings") or []
    if not embeddings:
        raise ValueError(f"Порожня відповідь /api/embed: {data}")
    return embeddings[0]


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return None
    return dot / (na * nb)


# --- cosine_cwe / cwe_ref_rank_hit / cwe_ref_margin (data/cwe_references_uk.json) ---
#
# На відміну від cosine_ref/chrf_ref (порівняння з еталонним поясненням цієї
# конкретної знахідки, data/references.csv — файл відсутній у проєкті), тут
# порівнюємо з канонічним описом класу CWE (те саме для всіх знахідок цього
# CWE) — перевірка релевантності теми, а не текстової схожості з еталоном.

def load_embed_cache():
    if EMBED_CACHE_PATH.exists():
        with open(EMBED_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_embed_cache(cache):
    EMBED_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(EMBED_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False)


def get_embedding_cached(text, cache):
    """sha256(text) -> вектор, results/embed_cache.json — щоб не рахувати
    той самий ембединг повторно (15 описів CWE + до ~1100 пояснень)."""
    key = sha256_text(text)
    if key in cache:
        return cache[key]
    emb = get_embedding(text)
    cache[key] = emb
    return emb


def load_cwe_references():
    if not CWE_REFERENCES_PATH.exists():
        print(f"[evaluate] Увага: {CWE_REFERENCES_PATH} відсутній — "
              f"cosine_cwe/cwe_ref_rank_hit/cwe_ref_margin будуть NA для всіх рядків.")
        return None
    with open(CWE_REFERENCES_PATH, "r", encoding="utf-8") as f:
        return json.load(f).get("cwe", {})


def build_cwe_ref_embeddings(cwe_refs, cache):
    """{CWE: вектор} для всіх описів у cwe_refs, або None, якщо Ollama
    недоступна (тоді метрики NA для всіх рядків, а не помилка на кожному)."""
    if not cwe_refs:
        return None
    embeddings = {}
    try:
        for cwe, text in cwe_refs.items():
            embeddings[cwe] = get_embedding_cached(text, cache)
    except Exception as e:
        print(f"[evaluate] Увага: не вдалося порахувати ембединги data/cwe_references_uk.json "
              f"({e}) — cosine_cwe/cwe_ref_rank_hit/cwe_ref_margin будуть NA для всіх рядків.")
        return None
    return embeddings


def compute_cwe_ref_metrics(cwe_field, non_code_text, cwe_ref_embeddings, cache):
    """(cosine_cwe, cwe_ref_rank_hit, cwe_ref_margin) — усі "" (NA), якщо
    ембединги CWE недоступні, знахідка не має CWE з довідника, чи текст
    пояснення порожній/embed впав."""
    na = ("", "", "")
    if not cwe_ref_embeddings:
        return na
    cwes = split_cwes(cwe_field)
    correct_cwe = next((c for c in cwes if c in cwe_ref_embeddings), None)
    if correct_cwe is None or not (non_code_text or "").strip():
        return na

    try:
        expl_emb = get_embedding_cached(non_code_text, cache)
    except Exception:
        return na

    sims = {}
    for cwe, emb in cwe_ref_embeddings.items():
        c = cosine(expl_emb, emb)
        if c is not None:
            sims[cwe] = c
    if correct_cwe not in sims:
        return na

    cosine_cwe = sims[correct_cwe]
    others = [v for k, v in sims.items() if k != correct_cwe]
    if not others:
        return round(cosine_cwe, 4), "", ""

    best_other = max(others)
    rank_hit = 1 if cosine_cwe >= best_other else 0
    margin = cosine_cwe - best_other
    return round(cosine_cwe, 4), rank_hit, round(margin, 4)


# --- data/manual_review.csv (опційно) ---------------------------------------

def load_manual_review():
    """finding_id, model, prompt_version, temperature, fix_correct,
    explanation_correct, note -> підтягуємо в metrics.csv, якщо файл є."""
    if not MANUAL_REVIEW_PATH.exists():
        return {}
    result = {}
    with open(MANUAL_REVIEW_PATH, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            key = (
                row.get("finding_id", ""), row.get("model", ""),
                row.get("prompt_version", ""), row.get("temperature", ""),
            )
            result[key] = {
                "fix_correct": row.get("fix_correct", ""),
                "explanation_correct": row.get("explanation_correct", ""),
                "note": row.get("note", ""),
            }
    return result


# --- I/O ---------------------------------------------------------------------

def load_findings_by_id():
    if not FINDINGS_PATH.exists():
        print(f"[evaluate] Не знайдено {FINDINGS_PATH}.")
        sys.exit(1)
    with open(FINDINGS_PATH, "r", encoding="utf-8", newline="") as f:
        return {row["id"]: row for row in csv.DictReader(f)}


def verify_snippet_clean_windows(findings):
    """3в: snippet_clean має ту саму кількість рядків, що й snippet (обидва —
    вікно snippet_start..snippet_end) для кожної знахідки — інакше
    build_patched_lines не може індекс у snippet_clean напряму зіставити з
    рядком оригінального файлу. Лише діагностика: для невідповідних записів
    build_patched_lines сам підстрахується свіжим clean_snippet() на вікні."""
    bad = []
    for fid, row in findings.items():
        clean = row.get("snippet_clean", "")
        snippet = row.get("snippet", "")
        if not clean:
            continue
        if len(clean.splitlines()) != len(snippet.splitlines()):
            bad.append(fid)
    if bad:
        shown = ", ".join(bad[:10]) + ("…" if len(bad) > 10 else "")
        print(f"[evaluate] Увага: snippet_clean не збігається за кількістю рядків зі snippet "
              f"для {len(bad)}/{len(findings)} знахідок ({shown}) — build_patched_lines для них "
              f"використає власний clean_snippet() на вікні файлу замість CSV.")
    else:
        print(f"[evaluate] snippet_clean/snippet: кількість рядків збігається для всіх {len(findings)} знахідок.")


def load_explanations():
    if not JSONL_PATH.exists():
        print(f"[evaluate] Не знайдено {JSONL_PATH}. Спершу запустіть bench.py.")
        sys.exit(1)
    records = []
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


METRICS_FIELDS = [
    "finding_id", "model", "device", "prompt_version", "temperature", "condition", "lang", "rule_id",
    "fix_valid",
    "structure_ok", "localization_hit", "fix_syntax_ok", "patch_mode",
    "fix_sast_pass", "fix_trivial", "fix_undefined",
    "cwe_keyword_hit", "off_topic_class", "rep_3gram", "avoid_hits",
    "lt_errors_per_100w", "ru_chars", "latin_ratio", "cosine_ref", "chrf_ref",
    "cosine_cwe", "cwe_ref_rank_hit", "cwe_ref_margin",
    "fix_correct", "explanation_correct", "note",
]


def to_float(v):
    try:
        if v in (None, "", "NA"):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def print_summary(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["model"], r["device"], r["prompt_version"], r["temperature"], r.get("condition", ""))].append(r)

    def avg(values):
        vals = [v for v in values if v is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    print("\n[evaluate] === Зведення (model | device | prompt_version | temperature | condition) ===")
    for key, items in sorted(groups.items()):
        model, device, pv, temp, condition = key
        n = len(items)
        na_fix_sast = sum(1 for r in items if r["fix_sast_pass"] == "NA")
        trivial_count = sum(1 for r in items if r.get("fix_trivial") == 1)
        manual_n = sum(1 for r in items if r.get("fix_correct") not in (None, "") or r.get("explanation_correct") not in (None, ""))
        na_fix_valid = sum(1 for r in items if r["fix_valid"] == "NA")
        print(f"\n{model} | device={device} | prompt={pv} | temp={temp} | condition={condition or 'baseline'} | n={n}")
        print(f"  fix_valid           : {avg([to_float(r['fix_valid']) for r in items])} (NA: {na_fix_valid}/{n})")
        print(f"  structure_ok        : {avg([to_float(r['structure_ok']) for r in items])}")
        print(f"  localization_hit    : {avg([to_float(r['localization_hit']) for r in items])}")
        print(f"  fix_syntax_ok       : {avg([to_float(r['fix_syntax_ok']) for r in items])}")
        print(f"  fix_sast_pass       : {avg([to_float(r['fix_sast_pass']) for r in items])} (NA: {na_fix_sast}/{n})")
        print(f"  fix_trivial         : {trivial_count}/{n}")
        print(f"  fix_undefined (сер.): {avg([to_float(r['fix_undefined']) for r in items])}")
        print(f"  cwe_keyword_hit     : {avg([to_float(r['cwe_keyword_hit']) for r in items])}")
        print(f"  off_topic_class     : {avg([to_float(r['off_topic_class']) for r in items])}")
        print(f"  rep_3gram           : {avg([to_float(r['rep_3gram']) for r in items])}")
        print(f"  avoid_hits (сер.)   : {avg([to_float(r['avoid_hits']) for r in items])}")
        print(f"  lt_errors_per_100w  : {avg([to_float(r['lt_errors_per_100w']) for r in items])}")
        print(f"  ru_chars (сер.)     : {avg([to_float(r['ru_chars']) for r in items])}")
        print(f"  latin_ratio         : {avg([to_float(r['latin_ratio']) for r in items])}")
        cos_avg = avg([to_float(r["cosine_ref"]) for r in items])
        chrf_avg = avg([to_float(r["chrf_ref"]) for r in items])
        if cos_avg is not None or chrf_avg is not None:
            print(f"  cosine_ref          : {cos_avg}")
            print(f"  chrf_ref            : {chrf_avg}")
        cwe_ref_avg = avg([to_float(r["cosine_cwe"]) for r in items])
        rank_hit_avg = avg([to_float(r["cwe_ref_rank_hit"]) for r in items])
        margin_avg = avg([to_float(r["cwe_ref_margin"]) for r in items])
        if cwe_ref_avg is not None:
            print(f"  cosine_cwe          : {cwe_ref_avg}")
            print(f"  cwe_ref_rank_hit    : {rank_hit_avg}")
            print(f"  cwe_ref_margin      : {margin_avg}")
        if manual_n:
            fix_correct_avg = avg([to_float(r["fix_correct"]) for r in items])
            expl_correct_avg = avg([to_float(r["explanation_correct"]) for r in items])
            print(f"  manual review       : {manual_n}/{n} перевірено вручну "
                  f"(fix_correct={fix_correct_avg}, explanation_correct={expl_correct_avg})")


def main():
    global FINDINGS_PATH, JSONL_PATH, METRICS_PATH, AVOID_TOP_PATH, EMBED_CACHE_PATH, FIX_PASS_CACHE_PATH

    parser = argparse.ArgumentParser(description="Оцінка пояснень SLM відносно findings.csv")
    parser.add_argument("--findings", default=None, help=f"Перевизначає {FINDINGS_PATH}")
    parser.add_argument("--jsonl", default=None, help=f"Перевизначає {JSONL_PATH}")
    parser.add_argument("--out", default=None, help=f"Перевизначає {METRICS_PATH}")
    parser.add_argument("--avoid-out", default=None, help=f"Перевизначає {AVOID_TOP_PATH}")
    parser.add_argument("--embed-cache", default=None, help=f"Перевизначає {EMBED_CACHE_PATH}")
    parser.add_argument("--fix-cache", default=None, help=f"Перевизначає {FIX_PASS_CACHE_PATH}")
    args = parser.parse_args()

    if args.findings:
        FINDINGS_PATH = Path(args.findings)
    if args.jsonl:
        JSONL_PATH = Path(args.jsonl)
    if args.out:
        METRICS_PATH = Path(args.out)
    if args.avoid_out:
        AVOID_TOP_PATH = Path(args.avoid_out)
    if args.embed_cache:
        EMBED_CACHE_PATH = Path(args.embed_cache)
    if args.fix_cache:
        FIX_PASS_CACHE_PATH = Path(args.fix_cache)

    check_java()

    findings = load_findings_by_id()
    verify_snippet_clean_windows(findings)
    explanations = load_explanations()
    references = load_references()
    cwe_keywords = load_cwe_keywords()
    glossary = load_glossary()
    avoid_patterns = build_avoid_patterns(glossary) if glossary else None
    manual_review = load_manual_review()
    has_refs = bool(references)
    if has_refs:
        print(f"[evaluate] Знайдено data/references.csv ({len(references)} еталонів) — рахую cosine_ref/chrf_ref.")
    else:
        print("[evaluate] data/references.csv відсутній — cosine_ref/chrf_ref пропущено.")
    if manual_review:
        print(f"[evaluate] Знайдено data/manual_review.csv ({len(manual_review)} записів) — підтягую в metrics.csv.")

    cwe_refs = load_cwe_references()
    embed_cache = load_embed_cache()
    cwe_ref_embeddings = build_cwe_ref_embeddings(cwe_refs, embed_cache) if cwe_refs else None
    if cwe_ref_embeddings:
        print(f"[evaluate] data/cwe_references_uk.json: {len(cwe_ref_embeddings)} описів CWE — "
              f"рахую cosine_cwe/cwe_ref_rank_hit/cwe_ref_margin.")
        save_embed_cache(embed_cache)  # одразу зберігаємо 15 ембедингів довідника

    cache_original, cache_fix = load_fix_pass_cache()

    out_rows = []
    fix_pass_items = []  # окремо збираємо для пакетної обробки fix_sast_pass/fix_trivial/fix_undefined
    avoid_top_counts = defaultdict(int)  # (model, condition, pattern) -> кількість пояснень зі збігом
    skipped = 0

    excluded_skipped = 0
    for rec in explanations:
        finding_id = rec.get("finding_id", "")
        finding = findings.get(finding_id)
        if not finding:
            skipped += 1
            continue
        if finding.get("exclude") == "1":
            excluded_skipped += 1
            continue

        explanation = rec.get("explanation", "") or ""
        lang = finding["lang"]
        snippet = finding["snippet"]
        start_line = int(finding["start_line"])
        end_line = int(finding["end_line"])
        rule_id = finding["rule_id"]
        cwe_field = finding.get("cwe", "")
        file_rel = finding["file"]
        abs_path = str((ROOT / file_rel).resolve()) if not os.path.isabs(file_rel) else file_rel

        snippet_start = int(rec.get("snippet_start") or max(1, start_line - CONTEXT))
        snippet_end = int(rec.get("snippet_end") or (end_line + CONTEXT))

        idx = find_sections(explanation)
        s_ok = structure_ok(idx)
        loc_hit = localization_hit(explanation, idx, snippet, start_line, end_line)
        fix_code = extract_fix_code(explanation, idx)

        non_code_text = strip_code_blocks(explanation)  # без ```блоків``` і без inline
        keep_inline_text = strip_fenced_blocks_only(explanation)  # без ```блоків```, inline лишається
        lt_text = prepare_text_for_lt(explanation)
        lt_rate = lt_errors_per_100w(lt_text)
        ru = ru_chars(non_code_text)
        snippet_idents = extract_identifiers(snippet.splitlines())
        lat_ratio = latin_ratio(non_code_text, snippet_idents)
        ck_hit = cwe_keyword_hit(cwe_field, keep_inline_text, cwe_keywords)
        ot_class = off_topic_class(cwe_field, keep_inline_text, cwe_keywords)
        rep3 = rep_3gram(non_code_text)
        avoid_n = avoid_hits(non_code_text, avoid_patterns)
        for pat_str in matched_avoid_patterns(non_code_text, avoid_patterns):
            avoid_top_counts[(str(rec.get("model", "")), str(rec.get("condition", "") or ""), pat_str)] += 1

        cos_ref, chrf_ref = "", ""
        if has_refs and finding_id in references:
            ref_text = references[finding_id]
            try:
                emb_a = get_embedding(explanation)
                emb_b = get_embedding(ref_text)
                cos_ref = cosine(emb_a, emb_b)
            except Exception as e:
                print(f"[evaluate] Помилка embed ({finding_id}): {e}")
            try:
                from sacrebleu.metrics import CHRF
                chrf_ref = CHRF().sentence_score(explanation, [ref_text]).score
            except Exception as e:
                print(f"[evaluate] Помилка chrF ({finding_id}): {e}")

        cosine_cwe, cwe_ref_rank_hit, cwe_ref_margin = compute_cwe_ref_metrics(
            cwe_field, non_code_text, cwe_ref_embeddings, embed_cache)

        mr_key = (finding_id, str(rec.get("model", "")), str(rec.get("prompt_version", "")), str(rec.get("temperature", "")))
        mr = manual_review.get(mr_key, {})

        row = {
            "finding_id": finding_id, "model": rec.get("model"), "device": rec.get("device"),
            "prompt_version": rec.get("prompt_version"), "temperature": rec.get("temperature"),
            "condition": rec.get("condition", ""),
            "lang": lang, "rule_id": rule_id,
            "fix_valid": "NA",  # заповнюється нижче — залежить від fix_syntax_ok/помилки парсингу/спрацювання
            "structure_ok": int(s_ok),
            "localization_hit": "" if loc_hit is None else int(loc_hit),
            "fix_syntax_ok": "",  # заповнюється нижче — на пропатченому повному файлі
            "patch_mode": "",  # заповнюється нижче — aligned | fallback (build_patched_lines)
            "fix_sast_pass": "NA", "fix_trivial": "", "fix_undefined": "",
            "cwe_keyword_hit": ck_hit, "off_topic_class": ot_class,
            "rep_3gram": rep3, "avoid_hits": avoid_n,
            "lt_errors_per_100w": "" if lt_rate is None else lt_rate,
            "ru_chars": ru,
            "latin_ratio": "" if lat_ratio is None else lat_ratio,
            "cosine_ref": cos_ref, "chrf_ref": chrf_ref,
            "cosine_cwe": cosine_cwe, "cwe_ref_rank_hit": cwe_ref_rank_hit, "cwe_ref_margin": cwe_ref_margin,
            "fix_correct": mr.get("fix_correct", ""),
            "explanation_correct": mr.get("explanation_correct", ""),
            "note": mr.get("note", ""),
        }
        out_rows.append(row)
        fix_pass_items.append({
            "row": row, "rule_id": rule_id, "lang": lang, "abs_path": abs_path,
            "snippet_start": snippet_start, "snippet_end": snippet_end, "fix_code": fix_code,
            "clean_window_text": finding.get("snippet_clean", ""),
        })

    print(f"[evaluate] Обчислюю fix_syntax_ok/fix_sast_pass/fix_trivial/fix_undefined для {len(fix_pass_items)} "
          f"записів (групування по rule_id, повний файл з corpus/)...")
    compute_fix_sast_batch(fix_pass_items, cache_original, cache_fix)
    for it in fix_pass_items:
        it["row"]["fix_sast_pass"] = it.get("fix_sast_pass", "NA")
        it["row"]["fix_trivial"] = it.get("fix_trivial", "")
        it["row"]["fix_undefined"] = it.get("fix_undefined", "")
        it["row"]["fix_syntax_ok"] = it.get("fix_syntax_ok", "")
        it["row"]["patch_mode"] = it.get("patch_mode", "")
        it["row"]["fix_valid"] = it.get("fix_valid", "NA")

    save_fix_pass_cache(cache_original, cache_fix)
    if cwe_ref_embeddings:
        save_embed_cache(embed_cache)

    if skipped:
        print(f"[evaluate] Пропущено {skipped} записів без відповідної знахідки в findings.csv "
              f"(напр. finding_id порожній — Semgrep-режим bench.py без --findings).")
    if excluded_skipped:
        print(f"[evaluate] Пропущено {excluded_skipped} записів для знахідок з exclude=1 "
              f"(майже-дублікати / витік підказки в сніпеті).")

    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=METRICS_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"[evaluate] Записано {METRICS_PATH} ({len(out_rows)} рядків)")

    avoid_top_rows = sorted(
        ({"model": m, "condition": c, "pattern": p, "count": n}
         for (m, c, p), n in avoid_top_counts.items()),
        key=lambda r: r["count"], reverse=True,
    )
    with open(AVOID_TOP_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["model", "condition", "pattern", "count"])
        writer.writeheader()
        writer.writerows(avoid_top_rows)
    print(f"[evaluate] Записано {AVOID_TOP_PATH} ({len(avoid_top_rows)} рядків)")

    print_summary(out_rows)
    print_lt_top15()

    if _lt_tool is not None:
        _lt_tool.close()


if __name__ == "__main__":
    main()
