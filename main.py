import asyncio
import csv
import json
import shutil
import stat
import subprocess
import tempfile
import os
import sys
import zipfile
from pathlib import Path

import requests
from fastapi import FastAPI, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from database import engine, SessionLocal, ScanSession, Vulnerability, AIExplanation, User, Base
from auth import hash_password, verify_password, create_token, verify_token
import ollama_client
from ollama_client import OLLAMA_HOST

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from snippet_clean import clean_snippet  # noqa: E402 (перевикористовуємо той самий чистильник, що й bench.py)

load_dotenv()
PROMPT_VERSION = os.getenv("PROMPT_VERSION", "V2")
SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG", "p/python p/javascript p/typescript p/owasp-top-ten").split()
SCAN_ROOTS = [r.strip() for r in os.getenv("SCAN_ROOTS", "dataset,corpus").split(",") if r.strip()]
DEFAULT_MODEL = "gemma4:e2b"  # за результатами етапів 1-2 (results/stage1_summary.csv, stage2_compare.csv)

# --- /api/scan/snippet ---
SNIPPET_LANG_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts"}
MAX_SNIPPET_BYTES = 100 * 1024  # 100 КБ

# --- /api/scan/upload ---
UPLOAD_CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
MAX_UPLOAD_FILE_BYTES = 10 * 1024 * 1024  # 10 МБ на файл
MAX_UPLOAD_UNPACKED_BYTES = 50 * 1024 * 1024  # 50 МБ розпакованого архіву
MAX_UPLOAD_FILES = 500

# Підказки для селектора моделі на фронтенді — висновок дослідницьких етапів 1-2.
MODEL_NOTES = {
    "gemma4:e2b": "Рекомендовано: найкращий баланс точності й швидкості",
    "hf.co/INSAIT-Institute/MamayLM-Gemma-3-4B-IT-v1.0-GGUF:Q4_K_M": "Найкраща якість української, повільніша",
}
DEFAULT_MODEL_NOTE = "Експериментальна"

ROOT = Path(__file__).resolve().parent
STAGE1_SUMMARY_PATH = ROOT / "results" / "stage1_summary.csv"
STAGE2_COMPARE_PATH = ROOT / "results" / "stage2_compare.csv"
MANUAL_SUMMARY_PATH = ROOT / "results" / "manual_summary.csv"

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
}


def infer_lang(file_path: str) -> str:
    return LANG_BY_EXT.get(Path(file_path).suffix.lower(), "")


def get_current_user_id(authorization: str = Header(None)) -> int:
    """Дістає user_id з Authorization: Bearer <token>. user_id, переданий у
    тілі запиту чи шляху, ніколи не використовується для визначення власника."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Відсутній токен авторизації")
    user_id = verify_token(authorization[len("Bearer "):])
    if user_id is None:
        raise HTTPException(status_code=401, detail="Недійсний або прострочений токен")
    return user_id


def is_within_scan_roots(path: str) -> bool:
    """Чи лежить path у межах одного з дозволених SCAN_ROOTS (захист від виходу за межі)."""
    abs_path = os.path.realpath(path)
    for root in SCAN_ROOTS:
        abs_root = os.path.realpath(root)
        if abs_path == abs_root or abs_path.startswith(abs_root + os.sep):
            return True
    return False

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SLM Vulnerability Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Pydantic Моделі ---
class LoginRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    file_path: str
    model_name: str = DEFAULT_MODEL
    user_id: int = 1  # ігнорується — власника визначає токен, див. get_current_user_id


class BatchScanRequest(BaseModel):
    directory_path: str = "dataset"
    model_name: str = DEFAULT_MODEL
    user_id: int = 1  # ігнорується — власника визначає токен, див. get_current_user_id


class SnippetScanRequest(BaseModel):
    code: str
    language: str
    model_name: str = DEFAULT_MODEL


# --- Створення тестового користувача при старті (+ міграція паролів на pbkdf2_hmac) ---
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    user = db.query(User).filter(User.username == "admin").first()
    if not user:
        pw_hash, salt = hash_password("password123")
        new_user = User(username="admin", password=pw_hash, salt=salt, role="admin")
        db.add(new_user)
        db.commit()
        print("[*] Створено тестового користувача: логін 'admin', пароль 'password123'")
    elif not user.salt:
        # Легасі: пароль зберігався у відкритому вигляді — хешуємо на місці
        pw_hash, salt = hash_password(user.password)
        user.password = pw_hash
        user.salt = salt
        db.commit()
        print(f"[*] Мігровано пароль користувача '{user.username}' на pbkdf2_hmac")
    db.close()


# --- Ендпоінти Авторизації та Історії ---
@app.post("/api/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user or not user.salt or not verify_password(request.password, user.password, user.salt):
        raise HTTPException(status_code=401, detail="Невірний логін або пароль")
    token = create_token(user.id)
    return {
        "message": "Успішний вхід", "user_id": user.id, "username": user.username,
        "role": user.role, "token": token,
    }


def ollama_unavailable_message() -> str:
    return f"Ollama не відповідає за адресою {OLLAMA_HOST}. Перевірте, що сервіс запущено (ollama serve)."


def check_ollama_available():
    """Швидка перевірка доступності Ollama — щоб повернути зрозумілу 503 до
    того, як почнеться (можливо, довге) сканування Semgrep, або до того, як
    почнеться NDJSON-потік /api/scan/batch/stream (де змінити статус-код
    відповіді вже неможливо, якщо перевірку зробити пізніше)."""
    try:
        requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail=ollama_unavailable_message())


@app.get("/api/models")
def get_models():
    """Список моделей Ollama (без embedding-моделей) для випадаючого списку на фронтенді."""
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail=ollama_unavailable_message())
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Не вдалося отримати список моделей від Ollama: {e}")

    names = [
        m["name"] for m in data.get("models", [])
        if "completion" in (m.get("capabilities") or ["completion"])
    ]
    models = [{"name": n, "note": MODEL_NOTES.get(n, DEFAULT_MODEL_NOTE)} for n in names]
    return {"models": models, "default": DEFAULT_MODEL}


@app.get("/api/research")
def get_research(current_user_id: int = Depends(get_current_user_id)):
    """Дані досліджень (results/stage1_summary.csv, results/stage2_compare.csv)
    для вкладки «Дослідження». Ці файли пише дослідницький конвеєр
    (scripts/evaluate.py -> build_stage1_summary.py -> compare.py), не
    продукт — якщо їх ще не запускали, повертаємо зрозумілу помилку
    замість порожньої/дивної відповіді."""
    missing = [p.name for p in (STAGE1_SUMMARY_PATH, STAGE2_COMPARE_PATH) if not p.exists()]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Відсутні файли результатів досліджень: {', '.join(missing)}. "
                "Запустіть scripts/evaluate.py, потім scripts/build_stage1_summary.py "
                "і scripts/compare.py."
            ),
        )
    with open(STAGE1_SUMMARY_PATH, encoding="utf-8", newline="") as f:
        stage1 = list(csv.DictReader(f))
    with open(STAGE2_COMPARE_PATH, encoding="utf-8", newline="") as f:
        stage2 = list(csv.DictReader(f))
    return {
        "stage1": stage1,
        "stage2": stage2,
        "recommended_model": DEFAULT_MODEL,
        "recommended_prompt_version": PROMPT_VERSION,
        "recommended_temperature": os.getenv("TEMPERATURE", "0.1"),
    }


@app.get("/api/manual_review")
def get_manual_review(current_user_id: int = Depends(get_current_user_id)):
    """Зведення ручної розмітки (results/manual_summary.csv) — точність
    Semgrep (is_true_positive), fix_correct/explanation_correct по моделях,
    precision автоматичної метрики fix_valid відносно експертної fix_correct.
    Джерело: data/manual_review.csv + data/tp_fp_review.csv (ручна розмітка)
    -> scripts/manual_review_summary.py. fix_valid — автоматична метрика
    (evaluate.py), fix_correct — експертна оцінка людини; вони не те саме."""
    if not MANUAL_SUMMARY_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "Результати ручної розмітки відсутні. Заповніть data/manual_review.csv "
                "і data/tp_fp_review.csv (scripts/build_manual_review.py / "
                "build_tp_fp_review.py формують заготовки), потім запустіть "
                "scripts/manual_review_summary.py."
            ),
        )
    with open(MANUAL_SUMMARY_PATH, encoding="utf-8", newline="") as f:
        summary = list(csv.DictReader(f))
    return {
        "summary": summary,
    }


@app.get("/api/history/{user_id}")
def get_history(user_id: int, current_user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    # user_id зі шляху ігнорується — власника визначає лише токен (current_user_id).
    # Сесії bench.py (scan_type="bench") — це дослідницький бенчмарк, не історія
    # користувача продукту, тому в /api/history не показуємо.
    sessions = db.query(ScanSession).filter(
        ScanSession.user_id == current_user_id, ScanSession.scan_type != "bench"
    ).order_by(ScanSession.created_at.desc()).all()
    history = []
    for sess in sessions:
        history.append({
            "session_id": sess.id,
            "scan_type": sess.scan_type,
            "created_at": sess.created_at,
            "vulnerabilities_count": len(sess.vulnerabilities)
        })
    return {"history": history}


@app.get("/api/session/{session_id}")
def get_session(session_id: int, current_user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    """Результати минулої сесії у тому самому форматі, що й /api/scan/* — щоб
    фронтенд міг показати їх тим самим компонентом картки результату.
    Сесія іншого користувача -> 404 (не видаємо факту її існування)."""
    session_db = db.query(ScanSession).filter(
        ScanSession.id == session_id, ScanSession.user_id == current_user_id
    ).first()
    if not session_db:
        raise HTTPException(status_code=404, detail="Сесію не знайдено")

    results = []
    for vuln in session_db.vulnerabilities:
        ai = vuln.ai_explanation
        results.append({
            "file": vuln.file_path,
            "rule_id": vuln.rule_id,
            "code_snippet": vuln.code_snippet,
            "ai_explanation": ai.explanation_text if ai else None,
            "inference_time_seconds": round(ai.total_s, 2) if ai and ai.total_s is not None else None,
            "model": ai.model_name if ai else None,
            "device": ai.device if ai else None,
            "prompt_version": ai.prompt_version if ai else None,
            "tokens_per_sec": ai.tokens_per_sec if ai else None,
            "gpu_share": ai.gpu_share if ai else None,
            "output_tokens": ai.output_tokens if ai else None,
        })

    return {
        "session_id": session_db.id,
        "scan_type": session_db.scan_type,
        "created_at": session_db.created_at,
        "total_vulnerabilities": len(results),
        "results": results,
    }


# --- Допоміжна функція для точного зчитування коду з файлу ---
def get_code_snippet(file_path: str, start_line: int, end_line: int = None, context: int = 5):
    """Повертає фрагмент коду в межах ±context рядків навколо [start_line, end_line]."""
    if end_line is None or end_line < start_line:
        end_line = start_line
    try:
        if not os.path.exists(file_path):
            return "Файл не знайдено"
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            start = max(0, (start_line - 1) - context)
            end = min(len(lines), end_line + context)
            return "".join(lines[start:end])
    except Exception as e:
        return f"Помилка читання коду: {e}"


# --- Логіка Сканування ---
def run_semgrep(target_path: str):
    # --no-git-ignore обов'язковий: corpus/ (один із SCAN_ROOTS) виключений
    # у .gitignore самого проєкту, інакше Semgrep сканує там 0 файлів.
    cmd = ["semgrep", "scan", "--no-git-ignore", "--metrics=off"]
    for config in SEMGREP_CONFIG:
        cmd += ["--config", config]
    cmd += ["--json", target_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Помилка Semgrep: {e}")
        return None


def _is_within_directory(base_dir_real: str, target_path: str) -> bool:
    target_real = os.path.realpath(target_path)
    return target_real == base_dir_real or target_real.startswith(base_dir_real + os.sep)


def safe_extract_zip(zip_path: str, dest_dir: str):
    """Безпечно розпаковує архів у dest_dir: для кожного запису перевіряє, що
    os.path.realpath(призначення) лишається в межах realpath(dest_dir) —
    захист від Zip Slip (запис виду "../../evil.py" чи абсолютний шлях у
    архіві), який інакше дозволив би записати файл у будь-яке місце диска.
    Підозрілі записи мовчки пропускаються (архів сканується далі), а не
    зупиняють увесь запит — так один шкідливий запис не блокує решту
    легітимних файлів.

    Символьні посилання пропускаються (не розпаковуються — вони можуть
    вказувати за межі dest_dir). Розширення поза UPLOAD_CODE_EXTENSIONS
    ігноруються мовчки (білий список). Ліміти (ValueError з українським
    текстом, зупиняє розпакування): MAX_UPLOAD_FILE_BYTES на файл,
    MAX_UPLOAD_UNPACKED_BYTES сумарно, MAX_UPLOAD_FILES файлів.

    Повертає [(реальний_шлях, ім'я_у_архіві), ...] для успішно видобутих файлів.
    """
    dest_real = os.path.realpath(dest_dir)
    extracted = []
    total_bytes = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue

            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                print(f"[*] Zip: пропускаю символьне посилання: {info.filename!r}")
                continue

            if Path(info.filename).suffix.lower() not in UPLOAD_CODE_EXTENSIONS:
                continue  # білий список розширень — решту ігноруємо мовчки

            dest_path = os.path.join(dest_dir, info.filename)
            if not _is_within_directory(dest_real, dest_path):
                print(f"[*] Zip Slip: пропускаю запис поза межами теки: {info.filename!r}")
                continue

            if info.file_size > MAX_UPLOAD_FILE_BYTES:
                raise ValueError(
                    f"Файл «{info.filename}» у архіві перевищує ліміт "
                    f"{MAX_UPLOAD_FILE_BYTES // (1024 * 1024)} МБ."
                )
            total_bytes += info.file_size
            if total_bytes > MAX_UPLOAD_UNPACKED_BYTES:
                raise ValueError(
                    f"Розпакований розмір архіву перевищує ліміт "
                    f"{MAX_UPLOAD_UNPACKED_BYTES // (1024 * 1024)} МБ."
                )
            if len(extracted) >= MAX_UPLOAD_FILES:
                raise ValueError(f"У архіві забагато файлів (ліміт {MAX_UPLOAD_FILES}).")

            real_dest = os.path.realpath(dest_path)
            os.makedirs(os.path.dirname(real_dest), exist_ok=True)
            with zf.open(info) as src, open(real_dest, "wb") as dst:
                dst.write(src.read())
            extracted.append((real_dest, info.filename))
    return extracted


def ask_slm(vulnerability_data, model_name):
    rule_id = vulnerability_data.get("check_id", "Невідомо")
    message = vulnerability_data.get("extra", {}).get("message", "Опис відсутній")

    # Витягуємо точний фрагмент коду (±5 рядків навколо start/end) через нову
    # функцію або, якщо файл недоступний, беремо сирий сніпет із Semgrep
    start_line = vulnerability_data.get("start", {}).get("line", 1)
    end_line = vulnerability_data.get("end", {}).get("line", start_line)
    file_path = vulnerability_data.get("path", "")

    if file_path and os.path.exists(file_path):
        lines = get_code_snippet(file_path, start_line, end_line)
    else:
        lines = vulnerability_data.get("extra", {}).get("lines", "Код відсутній")

    # Моделі показуємо очищений від коментарів сніпет (як і bench.py) — щоб
    # коментарі на кшталт "# Vulnerable: ..." не підказували відповідь.
    # У БД/картці результату лишається оригінальний `lines`.
    cleaned_lines = clean_snippet(lines, infer_lang(file_path))

    stats = ollama_client.generate_explanation(
        model_name=model_name,
        prompt_version=PROMPT_VERSION,
        rule_id=rule_id,
        message=message,
        lines=cleaned_lines,
    )
    return stats


def save_ai_explanation(db: Session, vulnerability_id: int, model_name: str, stats: dict) -> AIExplanation:
    """Записує пояснення від SLM і всі метрики генерації в БД."""
    ai_db = AIExplanation(
        vulnerability_id=vulnerability_id,
        model_name=model_name,
        explanation_text=stats["explanation"],
        inference_time=stats.get("total_s"),
        prompt_version=PROMPT_VERSION,
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
    )
    db.add(ai_db)
    db.commit()
    db.refresh(ai_db)
    return ai_db


@app.post("/api/scan/single")
def scan_single_file(request: ScanRequest, current_user_id: int = Depends(get_current_user_id),
                      db: Session = Depends(get_db)):
    print(f"[*] Починаємо сканування файлу: {request.file_path}")
    check_ollama_available()

    if not is_within_scan_roots(request.file_path):
        raise HTTPException(status_code=403,
                             detail=f"Шлях поза дозволеними межами SCAN_ROOTS ({', '.join(SCAN_ROOTS)})")

    # Ціль має бути конкретним файлом, не текою
    if not os.path.exists(request.file_path):
        raise HTTPException(status_code=404, detail="Файл не знайдено за вказаним шляхом.")
    if not os.path.isfile(request.file_path):
        raise HTTPException(status_code=400,
                            detail="Це папка, а не файл. Для папок використовуйте відповідний режим сканування.")

    report = run_semgrep(request.file_path)
    if not report or "results" not in report:
        raise HTTPException(status_code=400, detail="Помилка сканування або файл чистий")

    results = report["results"]
    if not results:
        return {"message": "Вразливостей не знайдено", "vulnerabilities": 0}

    session_db = ScanSession(scan_type="single", user_id=current_user_id)
    db.add(session_db)
    db.commit()
    db.refresh(session_db)

    response_data = {"session_id": session_db.id, "results": []}

    for res in results:
        res["path"] = request.file_path
        start_line = res.get("start", {}).get("line", 1)
        end_line = res.get("end", {}).get("line", start_line)
        code_snippet = get_code_snippet(request.file_path, start_line, end_line)

        vuln_db = Vulnerability(
            session_id=session_db.id,
            file_path=request.file_path,
            rule_id=res.get("check_id", "Невідомо"),
            code_snippet=code_snippet
        )
        db.add(vuln_db)
        db.commit()
        db.refresh(vuln_db)

        stats = ask_slm(res, request.model_name)
        ai_db = save_ai_explanation(db, vuln_db.id, request.model_name, stats)

        response_data["results"].append({
            "rule_id": vuln_db.rule_id,
            "ai_explanation": ai_db.explanation_text,
            "inference_time_seconds": round(ai_db.total_s, 2) if ai_db.total_s is not None else None,
            "code_snippet": vuln_db.code_snippet,
            "model": ai_db.model_name,
            "device": ai_db.device,
            "prompt_version": ai_db.prompt_version,
            "tokens_per_sec": ai_db.tokens_per_sec,
            "gpu_share": ai_db.gpu_share,
            "output_tokens": ai_db.output_tokens,
        })

    return response_data


@app.post("/api/scan/batch")
def scan_directory(request: BatchScanRequest, current_user_id: int = Depends(get_current_user_id),
                    db: Session = Depends(get_db)):
    print(f"[*] Починаємо масове сканування папки: {request.directory_path}")
    check_ollama_available()

    if not is_within_scan_roots(request.directory_path):
        raise HTTPException(status_code=403,
                             detail=f"Шлях поза дозволеними межами SCAN_ROOTS ({', '.join(SCAN_ROOTS)})")

    if not os.path.exists(request.directory_path):
        raise HTTPException(status_code=404, detail="Папку не знайдено.")
    if not os.path.isdir(request.directory_path):
        raise HTTPException(status_code=400,
                            detail="Це файл, а не папка. Для окремих файлів використовуйте відповідний режим сканування.")

    report = run_semgrep(request.directory_path)
    if not report or "results" not in report:
        raise HTTPException(status_code=400, detail="Помилка сканування або папка чиста")

    results = report["results"]
    if not results:
        return {"message": "Вразливостей не знайдено", "vulnerabilities": 0}

    session_db = ScanSession(scan_type="batch", user_id=current_user_id)
    db.add(session_db)
    db.commit()
    db.refresh(session_db)

    response_data = {"session_id": session_db.id, "total_vulnerabilities": len(results), "results": []}

    for res in results:
        file_path = res.get("path", "Невідомо")
        start_line = res.get("start", {}).get("line", 1)
        end_line = res.get("end", {}).get("line", start_line)
        code_snippet = get_code_snippet(file_path, start_line, end_line)

        vuln_db = Vulnerability(
            session_id=session_db.id,
            file_path=file_path,
            rule_id=res.get("check_id", "Невідомо"),
            code_snippet=code_snippet
        )
        db.add(vuln_db)
        db.commit()
        db.refresh(vuln_db)

        stats = ask_slm(res, request.model_name)
        ai_db = save_ai_explanation(db, vuln_db.id, request.model_name, stats)

        response_data["results"].append({
            "file": file_path,
            "rule_id": vuln_db.rule_id,
            "raw_message": res.get("extra", {}).get("message", "Опис відсутній"),
            "ai_explanation": ai_db.explanation_text,
            "inference_time_seconds": round(ai_db.total_s, 2) if ai_db.total_s is not None else None,
            "code_snippet": vuln_db.code_snippet,
            "model": ai_db.model_name,
            "device": ai_db.device,
            "prompt_version": ai_db.prompt_version,
            "tokens_per_sec": ai_db.tokens_per_sec,
            "gpu_share": ai_db.gpu_share,
            "output_tokens": ai_db.output_tokens,
        })

    return response_data


async def stream_scan_events(results, model_name, session_id, db, http_request, cleanup=None):
    """Спільна частина потокових ендпоінтів сканування: цикл по знахідках
    Semgrep, запис у базу і NDJSON-події ("start" -> "result"/"error" -> "done").
    Аргумент cleanup, якщо переданий, виконується у finally цього генератора, а
    не в ендпоінті, бо генератор працює вже після повернення StreamingResponse.
    """
    try:
        yield json.dumps({"type": "start", "total": len(results)}, ensure_ascii=False) + "\n"

        for i, res in enumerate(results):
            if await http_request.is_disconnected():
                print(f"[*] Клієнт відключився — зупиняю потоковий скан (сесія {session_id}, {i}/{len(results)})")
                break

            file_path = res.get("path", "Невідомо")
            display_path = res.get("display_path", file_path)
            start_line = res.get("start", {}).get("line", 1)
            end_line = res.get("end", {}).get("line", start_line)
            rule_id = res.get("check_id", "Невідомо")

            try:
                # get_code_snippet (I/O) і ask_slm (мережевий запит до Ollama, секунди) —
                # у окремому потоці, інакше блокують event loop і решта запитів (напр.
                # /api/history, /api/research) чекають, поки не завершиться весь скан.
                code_snippet = await asyncio.to_thread(get_code_snippet, file_path, start_line, end_line)
                vuln_db = Vulnerability(
                    session_id=session_id, file_path=display_path, rule_id=rule_id, code_snippet=code_snippet)
                db.add(vuln_db)
                db.commit()
                db.refresh(vuln_db)

                stats = await asyncio.to_thread(ask_slm, res, model_name)
                ai_db = save_ai_explanation(db, vuln_db.id, model_name, stats)

                event = {
                    "type": "result", "index": i,
                    "file": display_path, "rule_id": vuln_db.rule_id,
                    "raw_message": res.get("extra", {}).get("message", "Опис відсутній"),
                    "ai_explanation": ai_db.explanation_text,
                    "inference_time_seconds": round(ai_db.total_s, 2) if ai_db.total_s is not None else None,
                    "code_snippet": vuln_db.code_snippet,
                    "model": ai_db.model_name,
                    "device": ai_db.device,
                    "prompt_version": ai_db.prompt_version,
                    "tokens_per_sec": ai_db.tokens_per_sec,
                    "gpu_share": ai_db.gpu_share,
                    "output_tokens": ai_db.output_tokens,
                }
            except Exception as e:
                print(f"[*] Помилка при обробці знахідки {i} ({display_path}:{rule_id}): {e}")
                event = {"type": "error", "index": i, "file": display_path, "rule_id": rule_id, "error": str(e)}

            yield json.dumps(event, ensure_ascii=False) + "\n"

        yield json.dumps({"type": "done", "session_id": session_id, "total": len(results)}, ensure_ascii=False) + "\n"
    finally:
        if cleanup:
            cleanup()


@app.post("/api/scan/batch/stream")
async def scan_directory_stream(payload: BatchScanRequest, http_request: Request,
                                 current_user_id: int = Depends(get_current_user_id),
                                 db: Session = Depends(get_db)):
    """Той самий batch-скан, що й /api/scan/batch (яке лишається без змін),
    але результати віддаються по одному, NDJSON-потоком — див.
    stream_scan_events для формату подій."""
    await asyncio.to_thread(check_ollama_available)

    if not is_within_scan_roots(payload.directory_path):
        raise HTTPException(status_code=403,
                             detail=f"Шлях поза дозволеними межами SCAN_ROOTS ({', '.join(SCAN_ROOTS)})")
    if not os.path.exists(payload.directory_path):
        raise HTTPException(status_code=404, detail="Папку не знайдено.")
    if not os.path.isdir(payload.directory_path):
        raise HTTPException(status_code=400,
                            detail="Це файл, а не папка. Для окремих файлів використовуйте відповідний режим сканування.")

    # Функція async def (потрібна для http_request.is_disconnected() нижче),
    # а run_semgrep блокує на секунди — звідси окремий потік.
    report = await asyncio.to_thread(run_semgrep, payload.directory_path)
    if not report or "results" not in report:
        raise HTTPException(status_code=400, detail="Помилка сканування або папка чиста")
    results = report["results"]

    session_db = ScanSession(scan_type="batch", user_id=current_user_id)
    db.add(session_db)
    db.commit()
    db.refresh(session_db)

    return StreamingResponse(
        stream_scan_events(results, payload.model_name, session_db.id, db, http_request),
        media_type="application/x-ndjson",
    )


@app.post("/api/scan/snippet")
async def scan_snippet(payload: SnippetScanRequest, http_request: Request,
                        current_user_id: int = Depends(get_current_user_id),
                        db: Session = Depends(get_db)):
    """Сканує вставлений фрагмент коду (без файлів користувача): записує у
    tempfile з розширенням за мовою, скан тим самим Semgrep-конвеєром, що й
    решта ендпоінтів, видаляє tempfile після завершення потоку (див.
    stream_scan_events). У БД/подіях шлях знахідки — "(вставлений код)"."""
    await asyncio.to_thread(check_ollama_available)

    code = payload.code or ""
    if not code.strip():
        raise HTTPException(status_code=400, detail="Код порожній — вставте фрагмент для аналізу.")
    if len(code.encode("utf-8")) > MAX_SNIPPET_BYTES:
        raise HTTPException(status_code=400,
                             detail=f"Код завеликий (ліміт {MAX_SNIPPET_BYTES // 1024} КБ).")
    ext = SNIPPET_LANG_EXT.get(payload.language)
    if not ext:
        raise HTTPException(status_code=400,
                             detail=f"Невідома мова «{payload.language}». Підтримуються: "
                                    f"{', '.join(SNIPPET_LANG_EXT)}.")

    fd, tmp_path = tempfile.mkstemp(suffix=ext)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)

    try:
        report = await asyncio.to_thread(run_semgrep, tmp_path)
    except Exception:
        os.unlink(tmp_path)
        raise
    if not report or "results" not in report:
        os.unlink(tmp_path)
        raise HTTPException(status_code=400, detail="Помилка сканування фрагмента коду.")

    results = report["results"]
    for res in results:
        res["path"] = tmp_path
        res["display_path"] = "(вставлений код)"

    session_db = ScanSession(scan_type="snippet", user_id=current_user_id)
    db.add(session_db)
    db.commit()
    db.refresh(session_db)

    def cleanup():
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return StreamingResponse(
        stream_scan_events(results, payload.model_name, session_db.id, db, http_request, cleanup=cleanup),
        media_type="application/x-ndjson",
    )


@app.post("/api/scan/upload")
async def scan_upload(http_request: Request, file: UploadFile = File(...),
                       model_name: str = Form(DEFAULT_MODEL),
                       current_user_id: int = Depends(get_current_user_id),
                       db: Session = Depends(get_db)):
    """Сканує завантажений файл коду або .zip-архів: розпаковує у
    tempfile.mkdtemp() (архів — через safe_extract_zip, захист від Zip Slip
    і ліміти розміру/кількості файлів), скан тим самим Semgrep-конвеєром,
    видаляє теку після завершення потоку (див. stream_scan_events). У
    БД/подіях шлях знахідки — оригінальне ім'я файлу з архіву (чи саме
    завантаженого файлу), не тимчасовий шлях на диску сервера."""
    await asyncio.to_thread(check_ollama_available)

    original_name = Path(file.filename or "").name  # без шляху — лише ім'я
    ext = Path(original_name).suffix.lower()
    if ext != ".zip" and ext not in UPLOAD_CODE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Непідтримуване розширення «{ext or original_name}». Дозволено: "
                   f"{', '.join(sorted(UPLOAD_CODE_EXTENSIONS))}, .zip.",
        )

    content = await file.read()
    upfront_limit = MAX_UPLOAD_UNPACKED_BYTES if ext == ".zip" else MAX_UPLOAD_FILE_BYTES
    if len(content) > upfront_limit:
        raise HTTPException(status_code=400,
                             detail=f"Файл завеликий (ліміт {upfront_limit // (1024 * 1024)} МБ).")

    tmp_dir = tempfile.mkdtemp(prefix="upload_scan_")
    try:
        if ext == ".zip":
            zip_path = os.path.join(tmp_dir, "_upload.zip")
            with open(zip_path, "wb") as f:
                f.write(content)
            try:
                files_to_scan = safe_extract_zip(zip_path, tmp_dir)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            finally:
                os.unlink(zip_path)
            if not files_to_scan:
                raise HTTPException(
                    status_code=400,
                    detail=f"У архіві не знайдено файлів підтримуваних мов "
                           f"({', '.join(sorted(UPLOAD_CODE_EXTENSIONS))}).",
                )
        else:
            dest_path = os.path.join(tmp_dir, original_name)
            with open(dest_path, "wb") as f:
                f.write(content)
            files_to_scan = [(os.path.realpath(dest_path), original_name)]

        report = await asyncio.to_thread(run_semgrep, tmp_dir)
        if not report or "results" not in report:
            raise HTTPException(status_code=400, detail="Помилка сканування завантаженого файлу.")
        results = report["results"]

        display_by_real = {os.path.normcase(real): disp for real, disp in files_to_scan}
        for res in results:
            real_path = os.path.normcase(os.path.realpath(res.get("path", "")))
            res["display_path"] = display_by_real.get(real_path, Path(res.get("path", "")).name)

        session_db = ScanSession(scan_type="upload", user_id=current_user_id)
        db.add(session_db)
        db.commit()
        db.refresh(session_db)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    def cleanup():
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return StreamingResponse(
        stream_scan_events(results, model_name, session_db.id, db, http_request, cleanup=cleanup),
        media_type="application/x-ndjson",
    )
