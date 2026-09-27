import json
import subprocess
import requests


def run_semgrep():
    # encoding='utf-8' обов'язковий: без нього читання виводу Semgrep падає
    # на не-cp1251 символах у Windows-консолі.
    cmd = ["semgrep", "scan", "--config=auto", "--json", "vulnerable_app.py"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Помилка запуску Semgrep: {e}")
        return None


def analyze_with_slm(vulnerability):
    rule_id = vulnerability.get("check_id", "Невідоме правило")
    message = vulnerability.get("extra", {}).get("message", "Опис відсутній")
    lines = vulnerability.get("extra", {}).get("lines", "Код відсутній")

    prompt = f"""
    Ти експерт з кібербезпеки (Explainable AI). Проаналізуй наступну вразливість:

    Вразливість: {rule_id}
    Опис: {message}
    Код:
    {lines}

    Поясни коротко і чітко:
    1. Чому цей код небезпечний (механіка експлуатації).
    2. Як його виправити безпечним способом.
    """

    payload = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_gpu": 0
        }
    }

    try:
        response = requests.post("http://localhost:11434/api/generate", json=payload)
        data = response.json()

        if "error" in data:
            return f"Помилка від Ollama: {data['error']}"

        return data.get("response", f"Відповідь порожня. Дані: {data}")
    except Exception as e:
        return f"Детальна помилка підключення: {e}"


if __name__ == "__main__":
    print("[*] Запускаємо статичний аналіз для vulnerable_app.py...\n")
    report = run_semgrep()

    if report and "results" in report:
        for res in report["results"]:
            rule_id = res.get("check_id", "Невідомо")
            print("=" * 50)
            print(f"Знайдено: {rule_id}")
            print("=" * 50)
            print(f"[*] Відправляємо вразливість {rule_id} на аналіз ШІ...\n")

            ai_explanation = analyze_with_slm(res)
            print("[Аналіз від локальної моделі]:")
            print(ai_explanation)
            print("\n")
    else:
        print("Вразливостей не знайдено.")