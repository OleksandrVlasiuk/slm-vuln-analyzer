# Джерела експериментального датасету

## Клоновані репозиторії (`corpus/`, `git clone --depth 1`)

| Репозиторій | URL | Commit hash |
|---|---|---|
| pygoat | https://github.com/adeyosemanputra/pygoat | `19d17cc8874861142b330636d068bbde54e86b85` |
| NodeGoat | https://github.com/OWASP/NodeGoat | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` |
| dvna | https://github.com/appsecco/dvna | `9ba473add536f66ac9007966acb2a775dd31277a` |
| juice-shop | https://github.com/juice-shop/juice-shop | `1618a611b173b4bf114028e6e02549950606e29d` |
| dvpwa | https://github.com/anxolerd/dvpwa | `a1d8f89fac2e57093189853c6527c2b01fc1d9c1` |
| vulpy | https://github.com/fportantier/vulpy | `5249cc8b05a1c37f6b2f757b1cf16a509c327122` |

`corpus/` не входить у git (див. `.gitignore`) — це лише вихідний матеріал для сканування,
відтворюваний за хешами вище.

## Semgrep

- Версія: `1.136.0`
- Конфігурації (фіксовані набори для відтворюваності, замість `--config=auto`):
  `--config p/python --config p/javascript --config p/typescript --config p/owasp-top-ten`
- Сирий результат: `data/semgrep_raw.json`
- Команда (`--no-git-ignore` обов'язковий, бо `corpus/` виключено в `.gitignore`
  батьківського репозиторію, і без цього прапорця Semgrep сканує 0 файлів;
  `PYTHONIOENCODING=utf-8 PYTHONUTF8=1` обидва обов'язкові — без `PYTHONUTF8=1`
  запис `--output` падає на не-cp1251 символах у juice-shop, бо Python на цій
  машині відкриває файл через `locale.getpreferredencoding()` (cp1251), а саму
  лише `PYTHONIOENCODING` це не змінює):
  ```
  PYTHONIOENCODING=utf-8 PYTHONUTF8=1 semgrep scan --no-git-ignore --config p/python --config p/javascript --config p/typescript --config p/owasp-top-ten --json --output data/semgrep_raw.json corpus
  ```
- Результат: 96 сирих знахідок, 135 попереджень парсингу (переважно на
  фрагментарних `juice-shop/data/static/codefixes/*.ts` — навчальні сніпети,
  не повноцінні файли; це обмеження вихідних даних, не помилка конвеєра).

### Розширення Python-частини (`p/django`, `p/flask`)

Додатково до вже описаних наборів для Python-частини запущено `p/django` і
`p/flask` (разом із `p/python`, `p/owasp-top-ten`) на весь оновлений `corpus/`
(включно з `dvpwa`, `vulpy`):
```
PYTHONIOENCODING=utf-8 PYTHONUTF8=1 semgrep scan --no-git-ignore --config p/python --config p/django --config p/flask --config p/owasp-top-ten --json --output data/semgrep_raw_py.json corpus
```
- Сирий результат: `data/semgrep_raw_py.json`
- Результат: 150 сирих знахідок, 147 попереджень парсингу.

## data/findings.csv

Формується `scripts/build_dataset.py` з `data/semgrep_raw.json`:
- Залишає лише Python/JS/TS-знахідки, виключає тести, `node_modules`, `dist`/`build`,
  мінімізовані файли та дублікати (той самий rule_id + файл + рядок).
- Після фільтрації залишилось лише **52** релевантні знахідки (Python/JS/TS) —
  менше за цільові 80, оскільки фіксовані набори правил (`p/python`, `p/javascript`,
  `p/typescript`, `p/owasp-top-ten`) значно вужчі за `--config=auto`, а сам corpus
  невеликий. Стратифікована вибірка з обмеженням "не більше 5 на правило" дала
  **50** знахідок (максимум, досяжний за цих обмежень) — 13 Python, 37 JS/TS.
- Розширення Python-частини (`data/semgrep_raw_py.json`, `dvpwa`+`vulpy`):
  оригінальні 50 рядків (id 0001–0050) лишились без змін; дописано 17 нових
  python-знахідок (id 0051–0067), обмеження "не більше 5 на правило" зберігається
  глобально по всьому файлу. Підсумок: **67** рядків — python 30, javascript 21,
  typescript 16.
