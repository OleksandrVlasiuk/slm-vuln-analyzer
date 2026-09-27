"""
Видалення коментарів зі сніпетів коду зі збереженням кількості та номерів
рядків (коментар замінюється пробілами, а не вирізається як рядок).

Python — стандартний модуль tokenize (COMMENT-токени).
JS/TS  — сканер з пакета "typescript" (frontend/node_modules) через
         допоміжний Node-скрипт scripts/strip_ts_comments.js.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRIP_TS_SCRIPT = Path(__file__).resolve().parent / "strip_ts_comments.js"


def clean_python(code):
    """Замінює вміст усіх # коментарів пробілами. Рядки/номери рядків не змінюються.

    Наші сніпети — довільні ±5-рядкові вікна з файлу, часто без валідної
    структури відступів (можуть починатись/закінчуватись всередині блоку) —
    стандартний tokenize на таких фрагментах часто падає з IndentationError.
    Тому використовуємо власний посимвольний сканер: відстежує лише стан
    рядкових літералів (щоб не чіпати '#' усередині рядка) і не залежить
    від коректності відступів.
    """
    result = []
    i = 0
    n = len(code)
    in_string = None  # None | "'" | '"' | "'''" | '"""'
    while i < n:
        ch = code[i]

        if in_string:
            if code.startswith(in_string, i):
                result.append(in_string)
                i += len(in_string)
                in_string = None
                continue
            if ch == "\\" and i + 1 < n and len(in_string) == 1:
                result.append(code[i:i + 2])
                i += 2
                continue
            result.append(ch)
            i += 1
            continue

        if code.startswith("'''", i) or code.startswith('"""', i):
            in_string = code[i:i + 3]
            result.append(in_string)
            i += 3
            continue
        if ch in ("'", '"'):
            in_string = ch
            result.append(ch)
            i += 1
            continue
        if ch == "#":
            while i < n and code[i] not in ("\n", "\r"):
                result.append(" ")
                i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def clean_js_ts(code):
    """Викликає scripts/strip_ts_comments.js (сканер пакета typescript)."""
    try:
        result = subprocess.run(
            ["node", str(STRIP_TS_SCRIPT)],
            input=code, capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        if result.returncode != 0:
            print(f"[snippet_clean] node strip_ts_comments.js помилка: {result.stderr[:300]}", file=sys.stderr)
            return code
        return result.stdout
    except Exception as e:
        print(f"[snippet_clean] Не вдалося запустити strip_ts_comments.js: {e}", file=sys.stderr)
        return code


def clean_snippet(code, lang):
    if lang == "python":
        return clean_python(code)
    if lang in ("javascript", "typescript"):
        return clean_js_ts(code)
    return code
