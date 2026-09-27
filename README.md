# SLM Vulnerability Analyzer

Бекенд (FastAPI) для аналізу вразливостей: Semgrep + пояснення від локальної SLM через Ollama.
Фронтенд — окремий Next.js застосунок у `frontend/` (див. `frontend/README.md`).

## Запуск з нуля

Передумови: Python 3.9+, Node.js 20+, [Ollama](https://ollama.com) встановлена
й запущена, [Semgrep](https://semgrep.dev) у `PATH` (входить у
`requirements.txt` — встановиться разом з рештою залежностей).

```bash
# 1. Клонувати репозиторій
git clone https://github.com/OleksandrVlasiuk/slm-vuln-analyzer
cd slm-vuln-analyzer

# 2. Python-оточення й залежності бекенду
python -m venv venv
venv\Scripts\activate          # Windows;  source venv/bin/activate — Linux/macOS
pip install -r requirements.txt

# 3. Залежності фронтенду
cd frontend
npm install
cd ..

# 4. Модель для Ollama (за замовчуванням продукту — gemma4:e2b)
ollama pull gemma4:e2b

# 5. Конфігурація
copy .env.example .env         # Windows;  cp .env.example .env — Linux/macOS
# Відкрий .env і за потреби зміни SECRET_KEY (згенеруй власний —
# python -c "import secrets; print(secrets.token_hex(32))") та JAVA_HOME
# (лише якщо плануєш запускати scripts/evaluate.py — див. розділ нижче).

# 6. Запуск бекенду (з кореня репозиторію, окремий термінал)
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# 7. Запуск фронтенду (окремий термінал)
cd frontend
npm run dev
```

Фронтенд — http://localhost:3000 (логін: `admin` / `password123` — створюється
автоматично при першому старті бекенду). Бекенд і документація API (Swagger) —
http://127.0.0.1:8000/docs.

## Режими сканування

Вкладка «Нове сканування» має чотири режими (усі, крім «Один файл», віддають
результати NDJSON-потоком — картки з'являються по одній, є кнопка
«Зупинити»):

- **Один файл** / **Папка** — шлях у файловій системі сервера, обмежений
  `SCAN_ROOTS` (.env) — 403 за межами.
- **Вставити код** (`POST /api/scan/snippet`, `{code, language, model_name}`)
  — вставлений фрагмент (Python/JavaScript/TypeScript, ліміт 100 КБ)
  сканується без доступу до файлової системи користувача: код пишеться у
  тимчасовий файл, скан, тимчасовий файл видаляється одразу після
  завершення потоку. У БД/картці результату — `"(вставлений код)"`, не
  шлях на диску сервера.
- **Завантажити** (`POST /api/scan/upload`, multipart: `file`, `model_name`)
  — один файл коду (`.py`/`.js`/`.jsx`/`.ts`/`.tsx`) або `.zip`-архів.
  Ліміти (кожен -> 400 з поясненням): 10 МБ на файл, 50 МБ розпакованого
  архіву, не більше 500 файлів; розширення поза білим списком у архіві
  ігноруються мовчки. **Захист від Zip Slip**: кожен запис архіву
  перевіряється — `os.path.realpath()` призначення має лишатися в межах
  тимчасової теки, інакше запис мовчки пропускається (символьні посилання
  теж пропускаються); один шкідливий запис (напр. `../../evil.py`) не
  зупиняє скан решти архіву. У БД/картці — оригінальне ім'я файлу з
  архіву, не тимчасовий шлях.

Усі три потокові ендпоінти (`/api/scan/batch/stream`, `/api/scan/snippet`,
`/api/scan/upload`) використовують спільну функцію `stream_scan_events()` у
`main.py` — цикл по знахідках Semgrep, збереження в БД, формування подій —
щоб не дублювати цю логіку тричі.

## Встановлення залежностей (Python)

```
pip install -r requirements.txt
```

### Оновлення `requirements.txt`

`requirements.txt` має зберігатись у **UTF-8**. На Windows PowerShell звичайний
редирект ламає кодування:

```powershell
# Неправильно — PowerShell пише UTF-16LE, pip це не завжди читає коректно
pip freeze > requirements.txt
```

Правильно:

```powershell
pip freeze | Out-File -Encoding utf8 requirements.txt
```

(У звичайному bash/POSIX-шелі `pip freeze > requirements.txt` пише UTF-8 і проблеми немає —
вона стосується саме PowerShell-редиректу.)

## Java (LanguageTool) для `scripts/evaluate.py`

`lt_errors_per_100w` у `scripts/evaluate.py` використовує LanguageTool через
`language_tool_python`, якому потрібна **Java >= 17**. Якщо в системі стоїть
старіша Java (напр. 8), встановіть портативний JDK 17 (без прав адміністратора)
і вкажіть шлях у `.env`:

```
JAVA_HOME=D:\Tools\jdk17
```

`evaluate.py` сам додає `%JAVA_HOME%\bin` на початок `PATH` під час запуску —
префіксувати команду вручну не потрібно.

## Інтеграція в CI/CD

`scripts/ci_scan.py` запускає Semgrep у форматі SARIF (ті самі набори правил
`SEMGREP_CONFIG`, що й продукт) і дописує в кожен результат XAI-пояснення від
локальної SLM — той самий конвеєр генерації, що й `main.py`/`scripts/bench.py`
(±5 рядків контексту, очищення коментарів, промпт V2).

```bash
python scripts/ci_scan.py --path . --model gemma4:e2b --out ci_report.sarif
```

| Прапорець | За замовчуванням | Призначення |
|---|---|---|
| `--path` | (обов'язковий) | Файл або папка для сканування |
| `--model` | `gemma4:e2b` | Модель Ollama для пояснень |
| `--out` | `ci_report.sarif` | Куди записати SARIF-звіт |
| `--fail-on` | `any` | `any` — код виходу 1, якщо є знахідки; `none` — завжди 0 |
| `--max-findings` | `0` (без обмеження) | Максимум знахідок, для яких генерується пояснення SLM (у SARIF потрапляють усі знахідки Semgrep незалежно від цього ліміту) — обмежує лише час/вартість найдорожчого кроку в CI |
| `--no-explain` | вимкнено | Записати SARIF від Semgrep без звернень до Ollama |

Пояснення потрапляє і в `message.text` (роздільник + читабельний український
текст — видно одразу в GitHub Code Scanning), і в `properties.xai_explanation`
разом з `model`/`prompt_version`/`total_s` (для інструментів, що читають
властивості SARIF окремо). Схема SARIF 2.1.0 лишається валідною — скрипт лише
додає поля, нічого не видаляє й не змінює типи наявних.

### GitHub Actions

`.github/workflows/slm-vuln-scan.yml` — готовий приклад: запускає
`ci_scan.py` і вивантажує SARIF через `github/codeql-action/upload-sarif`.

**Runner обов'язково self-hosted**, а не стандартний хмарний GitHub-runner:
XAI-пояснення генерує локальна Ollama, і код репозиторію (фрагменти з
вразливостями) не повинен залишати приватну мережу організації для
пояснення сторонньою LLM — self-hosted runner з локальною Ollama гарантує,
що весь аналіз лишається на вашій інфраструктурі.
