"""Клієнт для звернень до Ollama (/api/generate, /api/chat, /api/ps)."""

import os
import time
import logging

import requests
from dotenv import load_dotenv

from prompts import (
    PROMPT_V0, PROMPT_V1, PROMPT_V2_SYSTEM, PROMPT_V2_USER,
    PROMPT_V2_CODEONLY_USER, PROMPT_V4_RAG_SYSTEM, build_glossary_block,
)

load_dotenv()

logger = logging.getLogger("ollama_client")
if not logger.handlers and not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
TIMEOUT_S = 600

_PROMPT_TEMPLATES = {"V0": PROMPT_V0, "V1": PROMPT_V1}


def unload_model(model_name):
    """Вивантажує модель з пам'яті Ollama (keep_alive=0), щоб наступний виклик
    завантажив її заново з актуальними options (зокрема num_gpu/device)."""
    if ":" not in model_name:
        model_name = f"{model_name}:latest"
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/generate", json={"model": model_name, "keep_alive": 0}, timeout=60)
        resp.raise_for_status()
        logger.info("Вивантажено модель %s", model_name)
    except Exception as e:
        logger.warning("Не вдалося вивантажити модель %s: %s", model_name, e)


def _resolve_device_options():
    """DEVICE з .env: auto -> num_gpu не передається, cpu -> 0, число -> N шарів на GPU."""
    device = os.getenv("DEVICE", "auto").strip().lower()
    if device == "auto":
        return {}, "auto"
    if device == "cpu":
        return {"num_gpu": 0}, "cpu"
    try:
        n = int(device)
        return {"num_gpu": n}, str(n)
    except ValueError:
        logger.warning("Невідоме значення DEVICE=%r, використовую auto", device)
        return {}, "auto"


def _resolve_sampling_options():
    temperature = float(os.getenv("TEMPERATURE", "0.1"))
    top_p = float(os.getenv("TOP_P", "0.9"))
    return temperature, top_p


def _get_gpu_share(model_name):
    """Частка моделі, завантаженої в GPU: size_vram/size з /api/ps."""
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/ps", timeout=10)
        resp.raise_for_status()
        for m in resp.json().get("models", []):
            if m.get("model") == model_name or m.get("name") == model_name:
                size = m.get("size") or 0
                size_vram = m.get("size_vram") or 0
                return round(size_vram / size, 4) if size else None
    except Exception as e:
        logger.warning("Не вдалося отримати gpu_share для %s: %s", model_name, e)
    return None


def _error_result(device, temperature, top_p, message):
    return {
        "explanation": message,
        "device": device,
        "temperature": temperature,
        "top_p": top_p,
        "load_duration_s": None,
        "prompt_tokens": None,
        "prompt_eval_s": None,
        "output_tokens": None,
        "eval_s": None,
        "tokens_per_sec": None,
        "total_s": None,
        "gpu_share": None,
        "done_reason": None,
    }


def build_chat_messages(prompt_version, rule_id, message, lines, cwe=None):
    """Формує (system_content, user_content) для /api/chat (V2/V2_CODEONLY/V4_RAG) —
    спільне для generate_explanation (продукт/bench.py) і
    scripts/export_train_jsonl.py (датасет дистиляції), щоб user-блок не
    розходився з тим, що модель бачить у роботі."""
    if prompt_version == "V2_CODEONLY":
        system_content = PROMPT_V2_SYSTEM
        user_content = PROMPT_V2_CODEONLY_USER.format(lines=lines)
    elif prompt_version == "V4_RAG":
        system_content = PROMPT_V4_RAG_SYSTEM.format(glossary_block=build_glossary_block(cwe))
        user_content = PROMPT_V2_USER.format(rule_id=rule_id, message=message, lines=lines)
    else:
        system_content = PROMPT_V2_SYSTEM
        user_content = PROMPT_V2_USER.format(rule_id=rule_id, message=message, lines=lines)
    return system_content, user_content


def generate_explanation(model_name, prompt_version, rule_id, message, lines, cwe=None,
                          think=None, num_predict=None):
    """
    Викликає Ollama для пояснення вразливості.

    prompt_version: "V0" | "V1" (через /api/generate) | "V2" | "V2_CODEONLY" | "V4_RAG"
    (через /api/chat). "cwe" використовується лише для V4_RAG (добір термінів
    з data/glossary_uk.json). "think" (True/False/None) — примусово вмикає/
    вимикає режим "мислення" (gemma4 thinking); None — стара поведінка
    (gemma4: think=False за замовчуванням, інші моделі: параметр не
    передається). "num_predict" перевизначає NUM_PREDICT з .env (напр. для
    think=True зазвичай потрібно більше токенів). Повертає dict з поясненням
    і метриками генерації; при помилці/таймауті поле "explanation" містить
    опис помилки, а числові метрики — None.
    """
    if ":" not in model_name:
        model_name = f"{model_name}:latest"

    device_options, device = _resolve_device_options()
    temperature, top_p = _resolve_sampling_options()

    options = {
        **device_options,
        "temperature": temperature,
        "top_p": top_p,
        "num_ctx": 4096,
        "num_predict": num_predict if num_predict is not None else int(os.getenv("NUM_PREDICT", "500")),
    }

    payload = {
        "model": model_name,
        "stream": False,
        "options": options,
        "keep_alive": "30m",
    }
    if think is not None:
        payload["think"] = think
    elif model_name.lower().startswith("gemma4"):
        payload["think"] = False

    if prompt_version in ("V2", "V2_CODEONLY", "V4_RAG"):
        url = f"{OLLAMA_HOST}/api/chat"
        system_content, user_content = build_chat_messages(prompt_version, rule_id, message, lines, cwe=cwe)
        payload["messages"] = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ]
    else:
        template = _PROMPT_TEMPLATES.get(prompt_version, PROMPT_V1)
        url = f"{OLLAMA_HOST}/api/generate"
        payload["prompt"] = template.format(rule_id=rule_id, message=message, lines=lines)

    start_time = time.time()
    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT_S)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        logger.error("Таймаут (%ss) при виклику Ollama, модель=%s", TIMEOUT_S, model_name)
        return _error_result(device, temperature, top_p, f"Помилка: таймаут генерації ({TIMEOUT_S}с)")
    except Exception as e:
        logger.error("Помилка виклику Ollama, модель=%s: %s", model_name, e)
        return _error_result(device, temperature, top_p, f"Помилка генерації: {e}")

    total_s = time.time() - start_time

    if "error" in data:
        logger.error("Ollama повернула помилку, модель=%s: %s", model_name, data["error"])
        return _error_result(device, temperature, top_p, f"Помилка від Ollama: {data['error']}")

    if prompt_version in ("V2", "V2_CODEONLY", "V4_RAG"):
        explanation = data.get("message", {}).get("content", "Порожня відповідь")
    else:
        explanation = data.get("response", "Порожня відповідь")

    load_duration_s = data.get("load_duration", 0) / 1e9 if data.get("load_duration") else None
    prompt_tokens = data.get("prompt_eval_count")
    prompt_eval_s = data.get("prompt_eval_duration", 0) / 1e9 if data.get("prompt_eval_duration") else None
    output_tokens = data.get("eval_count")
    eval_s = data.get("eval_duration", 0) / 1e9 if data.get("eval_duration") else None
    tokens_per_sec = round(output_tokens / eval_s, 2) if output_tokens and eval_s else None
    done_reason = data.get("done_reason")

    return {
        "explanation": explanation,
        "device": device,
        "temperature": temperature,
        "top_p": top_p,
        "load_duration_s": load_duration_s,
        "prompt_tokens": prompt_tokens,
        "prompt_eval_s": prompt_eval_s,
        "output_tokens": output_tokens,
        "eval_s": eval_s,
        "done_reason": done_reason,
        "tokens_per_sec": tokens_per_sec,
        "total_s": round(total_s, 3),
        "gpu_share": _get_gpu_share(model_name),
    }
