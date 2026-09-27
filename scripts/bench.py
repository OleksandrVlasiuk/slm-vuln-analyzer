"""
Бенчмарк моделей Ollama на вразливостях, знайдених Semgrep.

Приклад:
    python scripts/bench.py --models qwen2.5:1.5b phi3:latest --limit 5 --device auto
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv()

import ollama_client
from database import SessionLocal, ScanSession, Vulnerability, AIExplanation, engine, Base

Base.metadata.create_all(bind=engine)

CSV_FIELDS = [
    "model", "device", "prompt_version", "temperature", "top_p", "condition",
    "finding_id", "file", "rule_id", "line", "end_line",
    "output_tokens", "prompt_tokens", "tokens_per_sec", "total_s",
    "load_duration_s", "prompt_eval_s", "eval_s", "gpu_share", "done_reason", "error",
]

JSONL_PATH = ROOT / "results" / "explanations.jsonl"

# auto-конфіг Semgrep несумісний з --metrics=off (вимагає мережевого визначення
# правил) — використовуємо ті самі набори, що й продукт (main.py::SEMGREP_CONFIG).
SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG", "p/python p/javascript p/typescript p/owasp-top-ten").split()


def run_semgrep(target_path):
    cmd = ["semgrep", "scan", "--metrics=off"]
    for config in SEMGREP_CONFIG:
        cmd += ["--config", config]
    cmd += ["--json", target_path]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    try:
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[bench] Помилка Semgrep: {e}")
        return None


def get_code_snippet(file_path, start_line, end_line=None, context=5):
    if end_line is None or end_line < start_line:
        end_line = start_line
    try:
        if not os.path.exists(file_path):
            return "Файл не знайдено"
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        start = max(0, (start_line - 1) - context)
        end = min(len(lines), end_line + context)
        return "".join(lines[start:end])
    except Exception as e:
        return f"Помилка читання коду: {e}"


def snippet_line_bounds(file_path, start_line, end_line, context=5):
    """Фактичні межі рядків файлу (1-indexed, включно), що потрапили у сніпет —
    потрібні evaluate.py для патчингу повного файлу при перевірці fix_pass."""
    snippet_start = max(1, start_line - context)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            n_lines = sum(1 for _ in f)
        snippet_end = min(n_lines, end_line + context)
    except Exception:
        snippet_end = end_line + context
    return snippet_start, snippet_end


def parse_deadline(deadline_str):
    """"HH:MM" (локальний час) -> найближчий datetime у майбутньому з цим
    часом (сьогодні, або завтра, якщо цей час сьогодні вже минув). None,
    якщо --deadline не задано."""
    if not deadline_str:
        return None
    hh, mm = (int(x) for x in deadline_str.split(":"))
    now = datetime.now()
    deadline = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if deadline <= now:
        deadline += timedelta(days=1)
    return deadline


def make_key(model, finding_id, rule_id, file_path, line, prompt_version, device, temperature, condition=""):
    return (model, finding_id, rule_id, file_path, str(line), prompt_version, device, str(temperature),
            condition or "")


def load_existing(out_path):
    if not os.path.exists(out_path):
        return []
    with open(out_path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def semgrep_result_to_finding(res):
    """Перетворює сирий результат Semgrep на уніфіковане представлення знахідки."""
    file_path = res.get("path", "Unknown")
    start_line = res.get("start", {}).get("line", 1)
    end_line = res.get("end", {}).get("line", start_line)
    if file_path and os.path.exists(file_path):
        lines = get_code_snippet(file_path, start_line, end_line)
        snippet_start, snippet_end = snippet_line_bounds(file_path, start_line, end_line)
    else:
        lines = res.get("extra", {}).get("lines", "")
        snippet_start, snippet_end = start_line, end_line
    return {
        "id": "",
        "rule_id": res.get("check_id", "Unknown"),
        "file": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "snippet_start": snippet_start,
        "snippet_end": snippet_end,
        "message": res.get("extra", {}).get("message", ""),
        "lines": lines,
        "cwe": "",
    }


def load_findings_from_csv(path):
    """Завантажує знахідки з data/findings.csv (id, rule_id, file, start/end_line,
    message, snippet_clean) — без запуску Semgrep, уже з готовим фрагментом коду.

    Моделі показується лише snippet_clean (без коментарів — щоб коментарі на
    кшталт "# Vulnerable: ..." не підказували відповідь). Рядки з exclude=1
    (майже-дублікати з dedupe_regions.py) пропускаються."""
    findings = []
    skipped_excluded = 0
    with open(path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("exclude") == "1":
                skipped_excluded += 1
                continue
            start_line = int(row.get("start_line") or 1)
            end_line = int(row.get("end_line") or start_line)
            file_path = row.get("file", "Unknown")
            if file_path and os.path.exists(file_path):
                snippet_start, snippet_end = snippet_line_bounds(file_path, start_line, end_line)
            else:
                snippet_start, snippet_end = max(1, start_line - 5), end_line + 5
            lines = row.get("snippet_clean") or row.get("snippet", "")
            findings.append({
                "id": row.get("id", ""),
                "rule_id": row.get("rule_id", "Unknown"),
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "snippet_start": snippet_start,
                "snippet_end": snippet_end,
                "message": row.get("message", ""),
                "lines": lines,
                "cwe": row.get("cwe", ""),
            })
    if skipped_excluded:
        print(f"[bench] Пропущено {skipped_excluded} знахідок з exclude=1 (майже-дублікати)")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Бенчмарк моделей Ollama на знахідках Semgrep")
    parser.add_argument("--models", required=True, nargs="+",
                         help="Моделі через пробіл і/або кому, напр. qwen2.5:1.5b gemma3:4b")
    parser.add_argument("--input", default="dataset", help="Файл або папка для сканування (default: dataset)")
    parser.add_argument("--findings", default=None,
                         help="CSV зі знахідками (напр. data/findings.csv) замість запуску Semgrep; "
                              "перевизначає --input")
    parser.add_argument("--limit", type=int, default=None, help="Максимум знахідок на модель (без розігріву)")
    parser.add_argument("--device", default=None, help="auto | cpu | число — перевизначає DEVICE з .env")
    parser.add_argument("--prompt-version", default=None, help="V0 | V1 | V2 — перевизначає PROMPT_VERSION з .env")
    parser.add_argument("--temperature", type=float, default=None, help="Перевизначає TEMPERATURE з .env")
    parser.add_argument("--condition", default="",
                         help="Мітка умови експерименту (напр. temp_0.5, prompt_V0, codeonly, rag, think_on) — "
                              "пишеться в CSV/jsonl і входить у ключ кешу")
    parser.add_argument("--think", default=None, choices=["true", "false"],
                         help="true|false — примусово увімкнути/вимкнути режим 'мислення' моделі "
                              "(gemma4 thinking); за замовчуванням не передається (крім gemma4, де думання вимкнене)")
    parser.add_argument("--num-predict", type=int, default=None,
                         help="Перевизначає NUM_PREDICT з .env (макс. токенів генерації); "
                              "з --think true зазвичай треба більше (думання рахується в ці токени)")
    parser.add_argument("--out", default="results.csv", help="Шлях до CSV з результатами")
    parser.add_argument("--deadline", default=None,
                         help='"HH:MM" за локальним часом — зупиняє генерацію ПІСЛЯ поточного запису '
                              "(наступний findings уже не почнеться); кеш --out/jsonl дозволяє "
                              "продовжити з місця зупинки повторним запуском тієї самої команди")
    parser.add_argument("--jsonl", default=str(JSONL_PATH),
                         help="Шлях до .jsonl з поясненнями (за замовчуванням results/explanations.jsonl); "
                              "перевизнач для окремих вибірок (напр. data/train/), щоб не змішувати з дослідницьким run'ом")
    args = parser.parse_args()

    think = None if args.think is None else (args.think == "true")
    deadline = parse_deadline(args.deadline)
    if deadline:
        print(f"[bench] Дедлайн: {deadline.strftime('%Y-%m-%d %H:%M')}")

    if args.device:
        os.environ["DEVICE"] = args.device
    device_label = os.getenv("DEVICE", "auto").strip().lower()
    if device_label not in ("auto", "cpu"):
        try:
            device_label = str(int(device_label))
        except ValueError:
            device_label = "auto"

    if args.temperature is not None:
        os.environ["TEMPERATURE"] = str(args.temperature)

    prompt_version = args.prompt_version or os.getenv("PROMPT_VERSION", "V1")
    temperature = float(os.getenv("TEMPERATURE", "0.1"))
    condition = args.condition or ""

    models = [m.strip() for group in args.models for m in group.split(",") if m.strip()]
    if not models:
        print("[bench] Не вказано жодної моделі (--models)")
        return

    if args.findings:
        print(f"[bench] Завантажуємо знахідки з: {args.findings}")
        findings = load_findings_from_csv(args.findings)
        if not findings:
            print("[bench] У CSV немає знахідок")
            return
    else:
        print(f"[bench] Запускаємо Semgrep на: {args.input}")
        report = run_semgrep(args.input)
        if not report or "results" not in report or not report["results"]:
            print("[bench] Вразливостей не знайдено або Semgrep не спрацював")
            return
        findings = [semgrep_result_to_finding(r) for r in report["results"]]

    if args.limit:
        findings = findings[: args.limit]
    print(f"[bench] Знахідок для обробки на модель: {len(findings)}")

    existing_rows = load_existing(args.out)
    seen = {
        make_key(r["model"], r.get("finding_id", ""), r["rule_id"], r["file"], r["line"],
                 r["prompt_version"], r["device"], r["temperature"], r.get("condition", ""))
        for r in existing_rows
    }
    all_rows = list(existing_rows)

    file_has_content = os.path.exists(args.out) and os.path.getsize(args.out) > 0
    out_f = open(args.out, "a", encoding="utf-8", newline="")
    writer = csv.DictWriter(out_f, fieldnames=CSV_FIELDS)
    if not file_has_content:
        writer.writeheader()

    jsonl_path = Path(args.jsonl)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_f = open(jsonl_path, "a", encoding="utf-8")

    db = SessionLocal()
    session_db = ScanSession(scan_type="bench", user_id=1)
    db.add(session_db)
    db.commit()
    db.refresh(session_db)

    try:
        deadline_hit = False
        for model in models:
            if deadline_hit:
                break
            print(f"\n[bench] === Модель: {model} (device={device_label}) ===")

            print(f"[bench] Вивантажуємо {model} перед перемиканням device...")
            ollama_client.unload_model(model)

            if findings:
                warm = findings[0]
                print(f"[bench] Розігрів моделі {model}...")
                warm_stats = ollama_client.generate_explanation(
                    model, prompt_version, warm["rule_id"], warm["message"], warm["lines"], cwe=warm.get("cwe"),
                    think=think, num_predict=args.num_predict)

                warm_gpu_share = warm_stats.get("gpu_share")
                if device_label == "auto" and (warm_gpu_share is None or warm_gpu_share < 1.0):
                    print(f"[bench] Увага: device=auto, але gpu_share={warm_gpu_share} для {model} "
                          f"— модель виконується НЕ повністю на GPU")
                elif device_label == "cpu" and warm_gpu_share is not None and warm_gpu_share > 0:
                    print(f"[bench] Увага: device=cpu, але gpu_share={warm_gpu_share} для {model} "
                          f"— модель частково виконується на GPU")

            for finding in findings:
                if deadline is not None and datetime.now() >= deadline:
                    print(f"[bench] Дедлайн {deadline.strftime('%Y-%m-%d %H:%M')} досягнуто — "
                          f"зупиняю генерацію (наступні знахідки лишаться необробленими; "
                          f"повторний запуск тієї самої команди продовжить з кешу).")
                    deadline_hit = True
                    break

                finding_id = finding["id"]
                rule_id = finding["rule_id"]
                message = finding["message"]
                file_path = finding["file"]
                start_line = finding["start_line"]
                end_line = finding["end_line"]
                snippet_start = finding["snippet_start"]
                snippet_end = finding["snippet_end"]
                lines = finding["lines"]

                key = make_key(model, finding_id, rule_id, file_path, start_line,
                                prompt_version, device_label, temperature, condition)
                if key in seen:
                    print(f"[bench] Пропускаємо (кеш): {model} {finding_id or ''} {rule_id} {file_path}:{start_line}")
                    continue

                print(f"[bench] {model} -> {rule_id} ({file_path}:{start_line})")
                stats = ollama_client.generate_explanation(
                    model, prompt_version, rule_id, message, lines, cwe=finding.get("cwe"),
                    think=think, num_predict=args.num_predict)

                vuln_db = Vulnerability(
                    session_id=session_db.id,
                    file_path=file_path,
                    rule_id=rule_id,
                    code_snippet=lines,
                )
                db.add(vuln_db)
                db.commit()
                db.refresh(vuln_db)

                db.add(AIExplanation(
                    vulnerability_id=vuln_db.id,
                    model_name=model,
                    explanation_text=stats["explanation"],
                    inference_time=stats.get("total_s"),
                    prompt_version=prompt_version,
                    device=stats.get("device"),
                    temperature=stats.get("temperature"),
                    top_p=stats.get("top_p"),
                    load_duration_s=stats.get("load_duration_s"),
                    prompt_tokens=stats.get("prompt_tokens"),
                    prompt_eval_s=stats.get("prompt_eval_s"),
                    output_tokens=stats.get("output_tokens"),
                    eval_s=stats.get("eval_s"),
                    tokens_per_sec=stats.get("tokens_per_sec"),
                    total_s=stats.get("total_s"),
                    gpu_share=stats.get("gpu_share"),
                    done_reason=stats.get("done_reason"),
                ))
                db.commit()

                row = {
                    "model": model,
                    "device": stats.get("device"),
                    "prompt_version": prompt_version,
                    "temperature": stats.get("temperature"),
                    "top_p": stats.get("top_p"),
                    "condition": condition,
                    "finding_id": finding_id,
                    "file": file_path,
                    "rule_id": rule_id,
                    "line": start_line,
                    "end_line": end_line,
                    "output_tokens": stats.get("output_tokens"),
                    "prompt_tokens": stats.get("prompt_tokens"),
                    "tokens_per_sec": stats.get("tokens_per_sec"),
                    "total_s": stats.get("total_s"),
                    "load_duration_s": stats.get("load_duration_s"),
                    "prompt_eval_s": stats.get("prompt_eval_s"),
                    "eval_s": stats.get("eval_s"),
                    "gpu_share": stats.get("gpu_share"),
                    "done_reason": stats.get("done_reason"),
                    "error": "" if stats.get("total_s") is not None else stats.get("explanation", ""),
                }
                row = {k: ("" if v is None else v) for k, v in row.items()}
                writer.writerow(row)
                out_f.flush()

                jsonl_record = dict(row)
                jsonl_record["explanation"] = stats.get("explanation", "")
                jsonl_record["snippet_start"] = snippet_start
                jsonl_record["snippet_end"] = snippet_end
                jsonl_f.write(json.dumps(jsonl_record, ensure_ascii=False) + "\n")
                jsonl_f.flush()

                seen.add(key)
                all_rows.append({k: str(v) for k, v in row.items()})
    finally:
        out_f.close()
        jsonl_f.close()
        db.close()

    print_summary(all_rows)


def print_summary(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["model"], r["device"], r.get("condition", ""))].append(r)

    def avg(values):
        values = [float(v) for v in values if v not in (None, "")]
        return round(sum(values) / len(values), 3) if values else None

    print("\n[bench] === Підсумок ===")
    header = (f"{'model':<22} {'device':<8} {'condition':<12} {'avg total_s':>12} {'avg tok/s':>10} "
              f"{'avg out_tok':>12} {'gpu_share':>10} {'truncated':>10}")
    print(header)
    print("-" * len(header))
    for (model, device, condition), items in sorted(groups.items()):
        avg_total_s = avg([r.get("total_s") for r in items])
        avg_tps = avg([r.get("tokens_per_sec") for r in items])
        avg_out_tok = avg([r.get("output_tokens") for r in items])
        avg_gpu = avg([r.get("gpu_share") for r in items])
        truncated = sum(1 for r in items if r.get("done_reason") == "length")
        print(f"{model:<22} {device:<8} {(condition or 'baseline'):<12} {str(avg_total_s):>12} {str(avg_tps):>10} "
              f"{str(avg_out_tok):>12} {str(avg_gpu):>10} {truncated:>10}")


if __name__ == "__main__":
    main()
