"""Версії промптів для аналізу вразливостей через SLM."""

import json
from pathlib import Path

_GLOSSARY_PATH = Path(__file__).resolve().parent / "data" / "glossary_uk.json"
_glossary_cache = None

# --- V0: оригінальний промпт з analyzer.py (без змін) ---
PROMPT_V0 = """
    Ти експерт з кібербезпеки (Explainable AI). Проаналізуй наступну вразливість:

    Вразливість: {rule_id}
    Опис: {message}
    Код:
    {lines}

    Поясни коротко і чітко:
    1. Чому цей код небезпечний (механіка експлуатації).
    2. Як його виправити безпечним способом.
    """

# --- V1: поточний промпт з main.py::ask_slm (без змін) ---
PROMPT_V1 = """
        Ти — Senior AppSec Engineer (Експерт з кібербезпеки). Твоє завдання — проаналізувати звіт статичного аналізатора (SAST).
        ЗАБОРОНЕНО вигадувати неіснуючі функції, файли чи вразливості (жодних галюцинацій).
        Твоя відповідь має бути ВИКЛЮЧНО українською мовою і СУВОРО відповідати такій Markdown-структурі:

        1. Прозорість: (Вкажи, де саме знаходиться проблема в наданому коді).
        2. Обґрунтування: (Поясни механіку атаки та чому це небезпечно).
        3. Дієвість: (Напиши виправлений, безпечний варіант коду).

        Вразливість (Rule ID): {rule_id}
        Опис (Raw Message): {message}
        Код (Snippet):
        {lines}
        """

# --- V2: V1, розділений на system/user для /api/chat ---
PROMPT_V2_SYSTEM = """Ти — Senior AppSec Engineer (Експерт з кібербезпеки). Твоє завдання — проаналізувати звіт статичного аналізатора (SAST).
ЗАБОРОНЕНО вигадувати неіснуючі функції, файли чи вразливості (жодних галюцинацій).
Твоя відповідь має бути ВИКЛЮЧНО українською мовою і СУВОРО відповідати такій Markdown-структурі:

1. Прозорість: (Вкажи, де саме знаходиться проблема в наданому коді). Максимум 4 речення.
2. Обґрунтування: (Поясни механіку атаки та чому це небезпечно). Максимум 4 речення.
3. Дієвість: (Напиши виправлений, безпечний варіант коду). Наведи повністю виправлений фрагмент — усі рядки наданого коду з тими самими відступами, одним блоком коду. Максимум 4 речення пояснення до коду."""

PROMPT_V2_USER = """Вразливість (Rule ID): {rule_id}
Опис (Raw Message): {message}
Код (Snippet):
{lines}"""

# --- V2_CODEONLY: той самий system, що й V2; у user лише код, без Rule ID й опису ---
PROMPT_V2_CODEONLY_USER = """Код (Snippet):
{lines}"""

# --- V4_RAG: V2 + блок «Термінологічний довідник» у system ---
PROMPT_V4_RAG_SYSTEM = PROMPT_V2_SYSTEM + """

Термінологічний довідник (використовуй саме ці українські відповідники):
{glossary_block}"""


def _load_glossary():
    global _glossary_cache
    if _glossary_cache is None:
        try:
            with open(_GLOSSARY_PATH, "r", encoding="utf-8") as f:
                _glossary_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _glossary_cache = {"terms": []}
    return _glossary_cache


def build_glossary_block(cwe_field):
    """Формує текст блоку «Термінологічний довідник» для PROMPT_V4_RAG:
    терміни (en → uk, з «не …» формами з avoid_display) для CWE знахідки або
    cwe='*', плюс глобальні мовні норми (avoid_global[].use/display). Сирі
    регекси (terms[].avoid / avoid_global[].pattern) — лише для метрики
    avoid_hits (evaluate.py), у промпт не потрапляють — модель бачить
    виключно читабельні avoid_display/display."""
    glossary = _load_glossary()
    cwes = {c.strip() for c in (cwe_field or "").split(";") if c.strip()}

    term_lines = []
    for term in glossary.get("terms", []):
        t_cwe = term.get("cwe", ["*"])
        t_cwe = t_cwe if isinstance(t_cwe, list) else [t_cwe]
        if "*" in t_cwe or (cwes & set(t_cwe)):
            en = term.get("en", "")
            uk = term.get("uk", "")
            line = f"- {en} → {uk}"
            avoid_display = term.get("avoid_display", [])
            if avoid_display:
                line += " (не " + ", ".join(f"«{a}»" for a in avoid_display) + ")"
            term_lines.append(line)

    norm_parts = [
        f"«{g['use']}» (не «{g['display']}»)"
        for g in glossary.get("avoid_global", [])
        if g.get("use") and g.get("display")
    ]

    parts = [
        "\n".join(term_lines) if term_lines
        else "(специфічних термінів для цього CWE немає — покладайся на загальну термінологію SAST)"
    ]
    if norm_parts:
        parts.append("Мовні норми: " + "; ".join(norm_parts) + ".")
    return "\n".join(parts)
