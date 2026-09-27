# SLM Vulnerability Analyzer

Програмний комплекс для локального аналізу та інтерпретації вразливостей вихідного коду з використанням Малих Мовних Моделей (SLM). 

## 📌 Архітектура та Стек
- **Frontend:** Next.js 14, React, Tailwind CSS (Dashboard UI).
- **Backend:** FastAPI (Python), Uvicorn, SQLite + SQLAlchemy.
- **Security Analysis:** Semgrep (SAST).
- **AI Explainability (XAI):** Ollama API (Qwen 2.5, Gemma 2, Llama 3) для локальної генерації звітів без витоку коду.

## 🚀 Основний функціонал
- Аутентифіковане сканування (Single file / Batch mode).
- Точне зчитування вразливих фрагментів за допомогою `start.line`.
- Генерація структурованих звітів безпеки (Прозорість, Обґрунтування, Дієвість).
- Збереження історії сесій та результатів у базу даних.