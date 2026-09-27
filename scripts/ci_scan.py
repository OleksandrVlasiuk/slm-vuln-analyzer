"""
CI/CD-скан: Semgrep (SARIF) + XAI-пояснення від локальної SLM (Ollama) —
рівно той самий конвеєр, що й продукт (main.py::ask_slm): SEMGREP_CONFIG з
.env, ±5 рядків контексту (main.py::get_code_snippet), очищення коментарів
(scripts/snippet_clean.py) і ollama_client.generate_explanation (V2,
TEMPERATURE з .env). Призначений для запуску в CI на self-hosted runner
(Ollama працює локально — код і пояснення не залишають мережу).

Приклад:
    python scripts/ci_scan.py --path . --model gemma4:e2b --out ci_report.sarif
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

from main import SEMGREP_CONFIG, get_code_snippet, infer_lang  # noqa: E402 (той самий конвеєр, що й продукт)
from snippet_clean import clean_snippet  # noqa: E402
import ollama_client  # noqa: E402

PROMPT_VERSION = "V2"  # фіксовано — той самий промпт, що й продукт за замовчуванням


def run_semgrep_sarif(path):
    """semgrep scan --sarif з наборами SEMGREP_CONFIG (той самий конфіг, що
    й main.py::run_semgrep). --no-git-ignore — для узгодженості з продуктом
    (дозволяє сканувати теки, виключені у .gitignore самого репозиторію)."""
    cmd = ["semgrep", "scan", "--sarif", "--no-git-ignore", "--metrics=off"]
    for cfg in SEMGREP_CONFIG:
        cmd += ["--config", cfg]
    cmd += [path]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"[ci_scan] Semgrep не повернув валідний SARIF/JSON: {e}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(2)


def sarif_results(sarif):
    runs = sarif.get("runs", [])
    if not runs:
        return []
    return runs[0].get("results", [])


def result_location(res):
    """(file, start_line, end_line) з першої фізичної локації результату SARIF."""
    locations = res.get("locations") or [{}]
    phys = (locations[0] or {}).get("physicalLocation", {}) or {}
    uri = (phys.get("artifactLocation", {}) or {}).get("uri", "Unknown")
    region = phys.get("region", {}) or {}
    start_line = region.get("startLine", 1)
    end_line = region.get("endLine", start_line)
    return uri, start_line, end_line


def explain_result(model_name, res):
    """Той самий конвеєр, що main.py::ask_slm: ±5 рядків контексту, очищення
    коментарів, ollama_client.generate_explanation (V2, TEMPERATURE з .env)."""
    rule_id = res.get("ruleId", "Unknown")
    message = (res.get("message") or {}).get("text", "")
    file_path, start_line, end_line = result_location(res)

    lines = get_code_snippet(file_path, start_line, end_line)
    cleaned = clean_snippet(lines, infer_lang(file_path))

    return ollama_client.generate_explanation(
        model_name=model_name, prompt_version=PROMPT_VERSION,
        rule_id=rule_id, message=message, lines=cleaned,
    )


def augment_result_with_explanation(res, model_name, stats):
    """Дописує XAI-пояснення в SARIF-результат, не ламаючи схему. У message.text
    потрапляє наявний текст плюс роздільник і українське пояснення, а в
    properties.xai_explanation / model / prompt_version / total_s — повний текст
    і метадані генерації, для інструментів, що читають властивості окремо."""
    explanation = stats.get("explanation", "")
    message = res.setdefault("message", {"text": ""})
    original_text = message.get("text", "") or ""
    message["text"] = f"{original_text}\n---\nXAI-пояснення (SLM {model_name}):\n{explanation}"

    props = res.setdefault("properties", {})
    props["xai_explanation"] = explanation
    props["model"] = model_name
    props["prompt_version"] = PROMPT_VERSION
    props["total_s"] = stats.get("total_s")


def verify_sarif_valid(sarif):
    """Перевіряє, що звіт лишається валідним JSON з обов'язковими полями
    SARIF 2.1.0 на місці: поля лише додаються — наявні не видаляються і не
    змінюють тип."""
    json.loads(json.dumps(sarif))  # круговий round-trip -- впаде, якщо щось не серіалізується
    assert "$schema" in sarif, "SARIF: відсутнє поле $schema"
    assert "version" in sarif, "SARIF: відсутнє поле version"
    assert isinstance(sarif.get("runs"), list) and sarif["runs"], "SARIF: runs[] порожній або відсутній"
    run = sarif["runs"][0]
    assert "tool" in run, "SARIF: runs[0].tool відсутній"
    assert isinstance(run.get("results"), list), "SARIF: runs[0].results відсутній"
    for res in run["results"]:
        assert "ruleId" in res, "SARIF: результат без ruleId"
        assert "message" in res and "text" in res["message"], "SARIF: результат без message.text"


def main():
    parser = argparse.ArgumentParser(description="CI-скан: Semgrep (SARIF) + XAI-пояснення SLM")
    parser.add_argument("--path", required=True, help="Файл або папка для сканування")
    parser.add_argument("--model", default="gemma4:e2b", help="Модель Ollama (за замовчуванням gemma4:e2b)")
    parser.add_argument("--out", default="ci_report.sarif", help="Шлях для запису SARIF-звіту")
    parser.add_argument("--fail-on", choices=["none", "any"], default="any",
                         help="any (за замовчуванням) — код виходу 1, якщо є знахідки; none — завжди 0")
    parser.add_argument("--max-findings", type=int, default=0,
                         help="Максимум знахідок, для яких генерувати пояснення SLM (0 — без обмеження); "
                              "у SARIF потрапляють УСІ знахідки Semgrep незалежно від цього ліміту — "
                              "обмежується лише (дорожчий) крок пояснення, щоб керувати часом CI")
    parser.add_argument("--no-explain", action="store_true",
                         help="Не звертатися до Ollama — записати SARIF від Semgrep без пояснень")
    args = parser.parse_args()

    print(f"[ci_scan] Semgrep scan: {args.path} (конфіг: {', '.join(SEMGREP_CONFIG)})")
    sarif = run_semgrep_sarif(args.path)
    results = sarif_results(sarif)
    n = len(results)
    print(f"[ci_scan] Знахідок: {n}")

    explain_n = n if args.max_findings <= 0 else min(n, args.max_findings)
    total_explain_s = 0.0
    explained = 0

    if not args.no_explain and explain_n > 0:
        for i, res in enumerate(results[:explain_n], start=1):
            rule_id = res.get("ruleId", "Unknown")
            file_path, start_line, _ = result_location(res)
            print(f"[ci_scan] {i}/{explain_n}: {rule_id} ({file_path}:{start_line})")

            t0 = time.time()
            stats = explain_result(args.model, res)
            elapsed = time.time() - t0
            total_explain_s += elapsed
            explained += 1

            augment_result_with_explanation(res, args.model, stats)

        if explain_n < n:
            print(f"[ci_scan] --max-findings={args.max_findings}: пояснення згенеровано лише для "
                  f"{explain_n}/{n} знахідок (решта — у SARIF без xai_explanation).")
    elif args.no_explain:
        print("[ci_scan] --no-explain: пояснення SLM пропущено, записую SARIF від Semgrep як є.")

    verify_sarif_valid(sarif)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)
    print(f"[ci_scan] Записано {out_path}")

    avg_s = round(total_explain_s / explained, 2) if explained else None
    print("\n[ci_scan] === Зведення ===")
    print(f"  Знахідок: {n}")
    print(f"  Пояснень згенеровано: {explained}")
    print(f"  Сумарний час пояснень: {round(total_explain_s, 2)} с")
    print(f"  Середній час на пояснення: {avg_s} с")

    if args.fail_on == "any" and n > 0:
        print(f"[ci_scan] --fail-on=any і знахідок {n} > 0 -> код виходу 1")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
