"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import ReactMarkdown from "react-markdown";
import { apiFetch, clearAuth } from "@/lib/api";
import ResearchTab from "./ResearchTab";

// Компактний бейдж поруч із часом на картці результату
function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[10px] text-zinc-400 bg-zinc-800 border border-zinc-700 px-1.5 py-0.5 rounded-md font-mono">
      {children}
    </span>
  );
}

// Картка одного результату — використовується і для живого сканування, і для перегляду сесії з історії
function ResultCard({ res }: { res: any }) {
  if (res.is_error) {
    return (
      <div className="bg-zinc-950 rounded-2xl border border-red-900/50 overflow-hidden p-5">
        <div className="flex items-center gap-2 text-red-400 font-semibold mb-2">
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          Не вдалося обробити знахідку
        </div>
        <p className="text-xs text-zinc-500 font-mono mb-2">{res.rule_id} — {res.file}</p>
        <p className="text-sm text-red-300/90">{res.error}</p>
      </div>
    );
  }
  return (
    <div className="bg-zinc-950 rounded-2xl border border-zinc-800 overflow-hidden">
      <div className="bg-zinc-900 px-5 py-3.5 border-b border-zinc-800 flex flex-wrap justify-between items-center gap-2">
        <div className="flex items-center gap-3">
          <span className="text-red-400 font-semibold flex items-center gap-1.5">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            Вразливість
          </span>
          <span className="text-xs text-zinc-400 font-mono bg-zinc-800 border border-zinc-700 px-2 py-1 rounded-md">{res.rule_id.split('.').pop()}</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-zinc-500 font-mono flex items-center gap-1">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            {res.inference_time_seconds != null ? `${res.inference_time_seconds} сек` : "—"}
          </span>
          {res.model && <Badge>{res.model}</Badge>}
          {res.device && <Badge>{res.device}</Badge>}
          {res.prompt_version && <Badge>{res.prompt_version}</Badge>}
          {res.tokens_per_sec != null && <Badge>{res.tokens_per_sec} tok/s</Badge>}
          {res.gpu_share != null && <Badge>GPU {Math.round(res.gpu_share * 100)}%</Badge>}
          {res.output_tokens != null && <Badge>{res.output_tokens} tok</Badge>}
        </div>
      </div>

      <div className="p-5 space-y-5">
        {res.code_snippet && (
          <div className="rounded-xl overflow-hidden border border-zinc-800">
            <div className="bg-zinc-900 px-4 py-2 text-xs text-zinc-400 font-mono flex items-center gap-2 border-b border-zinc-800">
              <svg className="w-4 h-4 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
              Вразливий фрагмент ({res.file || 'Один файл'})
            </div>
            <pre className="bg-[#121212] p-4 text-sm text-red-300 font-mono overflow-x-auto">
              <code>{res.code_snippet.trim()}</code>
            </pre>
          </div>
        )}

        <div className="bg-zinc-900/50 border border-zinc-800/50 p-5 rounded-xl text-zinc-300 text-sm space-y-3 leading-relaxed">
          <ReactMarkdown
            components={{
              strong: ({node, ...props}) => <span className="font-bold text-zinc-100" {...props} />,
              ul: ({node, ...props}) => <ul className="list-disc pl-5 space-y-1.5 mt-2" {...props} />,
              ol: ({node, ...props}) => <ol className="list-decimal pl-5 space-y-1.5 mt-2" {...props} />,
              code: ({node, className, children, ...props}: any) => {
                const match = /language-(\w+)/.exec(className || "");
                return match ? (
                  <pre className="bg-[#121212] p-4 rounded-xl overflow-x-auto border border-zinc-800 my-4 text-xs text-emerald-400 font-mono shadow-inner">
                    <code className={className} {...props}>
                      {children}
                    </code>
                  </pre>
                ) : (
                  <code className="bg-zinc-800 text-zinc-200 border border-zinc-700 px-1.5 py-0.5 rounded-md font-mono text-xs" {...props}>
                    {children}
                  </code>
                );
              },
            }}
          >
            {res.ai_explanation}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const router = useRouter();
  const [user, setUser] = useState<{ id: string; name: string } | null>(null);
  const [activeTab, setActiveTab] = useState<"scan" | "history" | "research">("scan");

  const [targetPath, setTargetPath] = useState("dataset");
  const [scanMode, setScanMode] = useState<"single" | "batch" | "snippet" | "upload">("batch");
  const isStreamingMode = scanMode !== "single";  // batch/snippet/upload — усі потокові
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState("");

  const [streamResults, setStreamResults] = useState<any[]>([]);
  const [streamTotal, setStreamTotal] = useState(0);
  const [streamRan, setStreamRan] = useState(false);
  const [streamAborter, setStreamAborter] = useState<AbortController | null>(null);

  const [snippetCode, setSnippetCode] = useState("");
  const [snippetLanguage, setSnippetLanguage] = useState<"python" | "javascript" | "typescript">("python");
  const SNIPPET_MAX_BYTES = 100 * 1024;
  const snippetByteLen = typeof window !== "undefined" ? new TextEncoder().encode(snippetCode).length : snippetCode.length;

  const CODE_EXAMPLES: { label: string; language: "python"; code: string }[] = [
    {
      label: "SQL-ін'єкція",
      language: "python",
      code: `from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///test.db')

def get_user(username):
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))
        return result.fetchall()`,
    },
    {
      label: "Виконання команд ОС",
      language: "python",
      code: `import subprocess

def ping_server(user_input_ip):
    command = f"ping -c 4 {user_input_ip}"
    subprocess.run(command, shell=True)

def get_system_info():
    return subprocess.run("uname -a", shell=True, capture_output=True).stdout`,
    },
    {
      label: "Режим налагодження",
      language: "python",
      code: `import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('uploads', filename)
    return send_file(filepath)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)`,
    },
  ];

  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [isDragActive, setIsDragActive] = useState(false);

  const [history, setHistory] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [viewingSession, setViewingSession] = useState<any>(null);
  const [sessionLoading, setSessionLoading] = useState(false);

  const [selectedModel, setSelectedModel] = useState("gemma4:e2b");

  // Запасний статичний список — якщо /api/models недоступний (Ollama не відповідає)
  const FALLBACK_MODELS = [
    { value: "gemma4:e2b", label: "gemma4:e2b", note: "Рекомендовано: найкращий баланс точності й швидкості" },
    { value: "gemma3:4b", label: "gemma3:4b", note: "Експериментальна" },
    { value: "llama3:latest", label: "llama3:latest", note: "Експериментальна" },
    { value: "qwen2.5:1.5b", label: "qwen2.5:1.5b", note: "Експериментальна" },
    { value: "gemma2:latest", label: "gemma2:latest", note: "Експериментальна" },
  ];
  const [availableModels, setAvailableModels] = useState(FALLBACK_MODELS);

  // Список моделей — з Ollama (без embedding-моделей), інакше запасний статичний.
  // Помилку (напр. Ollama не запущена — 503) показуємо в червоній плашці, а не
  // мовчки: запасний список лишається доступним, але користувач має бачити причину.
  useEffect(() => {
    apiFetch("/api/models")
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          setError(data.detail || "Не вдалося отримати список моделей від Ollama.");
          return;
        }
        if (Array.isArray(data.models) && data.models.length > 0) {
          setAvailableModels(
            data.models.map((m: { name: string; note: string }) => ({
              value: m.name, label: m.name, note: m.note,
            }))
          );
          if (data.default) setSelectedModel(data.default);
        }
      })
      .catch(() => setError("Сервер недоступний"));
  }, []);

  // Перевірка авторизації при завантаженні
  useEffect(() => {
    const uid = localStorage.getItem("user_id");
    const uname = localStorage.getItem("username");
    if (!uid) {
      router.push("/");
    } else {
      setUser({ id: uid, name: uname || "Користувач" });
    }
  }, [router]);

  const loadHistory = async () => {
    if (!user?.id) return;
    setHistoryLoading(true);
    try {
      const res = await apiFetch(`/api/history/${user.id}`);
      if (res.status === 401) {
        clearAuth();
        router.push("/");
        return;
      }
      const data = await res.json();
      setHistory(data.history || []);
    } catch (err) {
      console.error("Помилка завантаження історії:", err);
    }
    setHistoryLoading(false);
  };

  useEffect(() => {
    if (activeTab === "history") {
      loadHistory();
    }
  }, [activeTab, user]);

  const [sessionError, setSessionError] = useState("");

  // Перегляд результатів минулої сесії (клік по рядку історії)
  const loadSession = async (sessionId: number) => {
    setSessionLoading(true);
    setSessionError("");
    setViewingSession(null);
    try {
      const res = await apiFetch(`/api/session/${sessionId}`);
      if (res.status === 401) {
        clearAuth();
        router.push("/");
        return;
      }
      const data = await res.json();
      if (res.ok) {
        setViewingSession(data);
      } else {
        setSessionError(data.detail || "Не вдалося завантажити сесію.");
      }
    } catch (err) {
      setSessionError("Сервер недоступний");
    }
    setSessionLoading(false);
  };

  const handleLogout = () => {
    clearAuth();
    router.push("/");
  };

  const handleScan = async () => {
    setLoading(true);
    setReport(null);
    setError("");
    setStreamRan(false);
    setStreamResults([]);
    setStatusMessage("Ініціалізація сканування...");

    const modelLabel = availableModels.find(m => m.value === selectedModel)?.label || selectedModel;

    const timer1 = setTimeout(() => setStatusMessage("Запуск статичного аналізатора Semgrep..."), 1000);
    const timer2 = setTimeout(() => setStatusMessage("Аналіз структури коду та пошук вразливостей..."), 3000);
    const timer3 = setTimeout(() => setStatusMessage(`Передача контексту локальній SLM (${modelLabel})...`), 6000);
    const timer4 = setTimeout(() => setStatusMessage("Генерація людино-зрозумілого пояснення (XAI)..."), 10000);

    try {
      const res = await apiFetch("/api/scan/single", {
        method: "POST",
        body: JSON.stringify({ file_path: targetPath, model_name: selectedModel }),
      });

      if (res.status === 401) {
        clearAuth();
        router.push("/");
        return;
      }

      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || "Сталася помилка під час сканування.");
      } else {
        setReport(data);
      }
    } catch (err) {
      setError("Сервер недоступний");
    } finally {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);
      setLoading(false);
      setStatusMessage("");
    }
  };

  // Спільна логіка для всіх потокових ендпоінтів (/api/scan/batch/stream,
  // /api/scan/snippet, /api/scan/upload) — картки з'являються по одній,
  // замість очікування всього скану цілком.
  const runStreamingScan = async (endpoint: string, fetchOptions: RequestInit) => {
    setLoading(true);
    setReport(null);
    setError("");
    setStreamResults([]);
    setStreamTotal(0);
    setStreamRan(true);
    setStatusMessage("Запуск статичного аналізатора Semgrep...");

    const controller = new AbortController();
    setStreamAborter(controller);

    try {
      const res = await apiFetch(endpoint, { ...fetchOptions, signal: controller.signal });

      if (res.status === 401) {
        clearAuth();
        router.push("/");
        return;
      }
      if (!res.ok || !res.body) {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || "Сталася помилка під час сканування.");
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const event = JSON.parse(line);
          if (event.type === "start") {
            setStreamTotal(event.total);
            setStatusMessage(`Обробка знахідок локальною SLM (${selectedModel})...`);
          } else if (event.type === "result") {
            setStreamResults((prev) => [...prev, event]);
          } else if (event.type === "error") {
            setStreamResults((prev) => [...prev, { ...event, is_error: true }]);
          } else if (event.type === "done") {
            setStatusMessage("");
          }
        }
      }
    } catch (err: any) {
      if (err?.name !== "AbortError") {
        setError("Сервер недоступний");
      }
    } finally {
      setLoading(false);
      setStatusMessage("");
      setStreamAborter(null);
    }
  };

  const handleBatchStreamScan = () => runStreamingScan("/api/scan/batch/stream", {
    method: "POST",
    body: JSON.stringify({ directory_path: targetPath, model_name: selectedModel }),
  });

  const handleSnippetScan = () => runStreamingScan("/api/scan/snippet", {
    method: "POST",
    body: JSON.stringify({ code: snippetCode, language: snippetLanguage, model_name: selectedModel }),
  });

  const handleUploadScan = () => {
    if (!uploadFile) return;
    const formData = new FormData();
    formData.append("file", uploadFile);
    formData.append("model_name", selectedModel);
    return runStreamingScan("/api/scan/upload", { method: "POST", body: formData });
  };

  const handleStopStream = () => {
    streamAborter?.abort();
  };

  if (!user) return <div className="min-h-screen bg-zinc-950 flex justify-center items-center text-zinc-100">Завантаження...</div>;

  return (
    <div className="h-screen w-screen bg-zinc-950 text-zinc-300 flex overflow-hidden font-sans">

      {/* Бокове меню */}
      <aside className="w-72 bg-zinc-900 border-r border-zinc-800 p-6 flex flex-col shrink-0">
        <div className="flex items-center gap-3 mb-10">
          <div className="w-10 h-10 bg-zinc-100 rounded-xl flex items-center justify-center text-zinc-950 font-bold shadow-sm">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
          </div>
          <div>
            <span className="text-xl font-bold text-zinc-100 block leading-tight">SLM Analyzer</span>
            <span className="text-xs text-zinc-500 font-medium">Дослідницький прототип</span>
          </div>
        </div>

        <nav className="flex-1 space-y-2">
          <button
            onClick={() => setActiveTab("scan")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium ${activeTab === 'scan' ? 'bg-zinc-800 text-zinc-100 border border-zinc-700/50 shadow-sm' : 'hover:bg-zinc-800/50 text-zinc-400'}`}
          >
            🔍 Нове сканування
          </button>
          <button
            onClick={() => setActiveTab("history")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium ${activeTab === 'history' ? 'bg-zinc-800 text-zinc-100 border border-zinc-700/50 shadow-sm' : 'hover:bg-zinc-800/50 text-zinc-400'}`}
          >
            📚 Історія перевірок
          </button>
          <button
            onClick={() => setActiveTab("research")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium ${activeTab === 'research' ? 'bg-zinc-800 text-zinc-100 border border-zinc-700/50 shadow-sm' : 'hover:bg-zinc-800/50 text-zinc-400'}`}
          >
            📊 Дослідження
          </button>
        </nav>

        <div className="mt-auto border-t border-zinc-800 pt-6">
          <div className="flex items-center justify-between bg-zinc-950/50 p-3 rounded-xl border border-zinc-800/50">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 bg-zinc-800 rounded-full flex items-center justify-center text-zinc-100 font-bold border border-zinc-700">
                {user.name.charAt(0).toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-semibold text-zinc-200">{user.name}</p>
                <p className="text-xs text-zinc-500">AppSec Інженер</p>
              </div>
            </div>
            <button onClick={handleLogout} className="text-zinc-500 hover:text-red-400 transition-colors p-2" title="Вийти">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
            </button>
          </div>
        </div>
      </aside>

      {/* Головний контент */}
      {/* «Дослідження» — довгий вертикальний контент без внутрішніх панелей:
          прокручується сам main (overflow-y-auto), а не вкладений контейнер.
          «Сканування»/«Історія» мають власні внутрішні панелі прокрутки —
          main лишається overflow-hidden, як і був. */}
      <main className={`flex-1 flex flex-col h-screen p-8 ${activeTab === "research" ? "overflow-y-auto" : "overflow-hidden"}`}>
        {activeTab === "scan" ? (
          <div className="flex flex-col h-full max-w-6xl w-full mx-auto">
            <header className="mb-6 shrink-0">
              <h1 className="text-3xl font-bold text-zinc-100">Аналіз вразливостей коду</h1>
              <p className="text-zinc-500 mt-2">Локальна перевірка безпеки з використанням ШІ</p>
            </header>

            <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 min-h-0 overflow-hidden">

              {/* Ліва панель налаштувань */}
              <div className={`${scanMode === "snippet" && streamResults.length === 0 ? "lg:col-span-7" : "lg:col-span-4"} bg-zinc-900 p-6 rounded-2xl border border-zinc-800 shadow-xl overflow-y-auto h-fit max-h-full`}>
                <h2 className="text-lg font-semibold text-zinc-100 mb-5">Параметри</h2>
                <div className="grid grid-cols-2 gap-1 bg-zinc-950 p-1 rounded-xl mb-6 border border-zinc-800">
                  <button onClick={() => setScanMode("single")} className={`py-2 rounded-lg text-sm font-medium transition-colors ${scanMode === "single" ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/50' : 'text-zinc-500 hover:text-zinc-300'}`}>Один файл</button>
                  <button onClick={() => setScanMode("batch")} className={`py-2 rounded-lg text-sm font-medium transition-colors ${scanMode === "batch" ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/50' : 'text-zinc-500 hover:text-zinc-300'}`}>Папка</button>
                  <button onClick={() => setScanMode("snippet")} className={`py-2 rounded-lg text-sm font-medium transition-colors ${scanMode === "snippet" ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/50' : 'text-zinc-500 hover:text-zinc-300'}`}>Вставити код</button>
                  <button onClick={() => setScanMode("upload")} className={`py-2 rounded-lg text-sm font-medium transition-colors ${scanMode === "upload" ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/50' : 'text-zinc-500 hover:text-zinc-300'}`}>Завантажити</button>
                </div>

                <div className="mb-6">
                  <label className="block text-sm font-medium text-zinc-400 mb-2">SLM Модель:</label>
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    title={availableModels.find((m) => m.value === selectedModel)?.note || ""}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-zinc-100 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all appearance-none"
                  >
                    {availableModels.map((m) => (
                      <option key={m.value} value={m.value} title={m.note}>{m.label}</option>
                    ))}
                  </select>
                  {availableModels.find((m) => m.value === selectedModel)?.note && (
                    <p className="text-xs text-zinc-500 mt-1.5">
                      {availableModels.find((m) => m.value === selectedModel)?.note}
                    </p>
                  )}
                </div>

                {(scanMode === "single" || scanMode === "batch") && (
                  <div className="mb-8">
                    <label className="block text-sm font-medium text-zinc-400 mb-2">Шлях до цілі:</label>
                    <input type="text" value={targetPath} onChange={(e) => setTargetPath(e.target.value)} className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-zinc-100 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all" />
                  </div>
                )}

                {scanMode === "snippet" && (
                  <div className="mb-8 space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-zinc-400 mb-2">Мова:</label>
                      <select
                        value={snippetLanguage}
                        onChange={(e) => setSnippetLanguage(e.target.value as "python" | "javascript" | "typescript")}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-zinc-100 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all appearance-none"
                      >
                        <option value="python">Python</option>
                        <option value="javascript">JavaScript</option>
                        <option value="typescript">TypeScript</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-zinc-400 mb-2">Вставте фрагмент коду для аналізу:</label>
                      <textarea
                        value={snippetCode}
                        onChange={(e) => setSnippetCode(e.target.value)}
                        rows={20}
                        placeholder="Вставте фрагмент коду для аналізу..."
                        className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-zinc-100 font-mono text-xs focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all resize-y"
                      />
                      <p className={`text-xs mt-1.5 ${snippetByteLen > SNIPPET_MAX_BYTES ? "text-red-400" : "text-zinc-500"}`}>
                        {snippetByteLen.toLocaleString("uk-UA")} / {SNIPPET_MAX_BYTES.toLocaleString("uk-UA")} байт
                      </p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-zinc-400 mb-2">Приклади:</label>
                      <div className="flex flex-wrap gap-2">
                        {CODE_EXAMPLES.map((ex) => (
                          <button
                            key={ex.label}
                            onClick={() => { setSnippetCode(ex.code); setSnippetLanguage(ex.language); }}
                            className="text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1.5 rounded-lg transition-colors"
                          >
                            {ex.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {scanMode === "upload" && (
                  <div className="mb-8">
                    <label className="block text-sm font-medium text-zinc-400 mb-2">Файл або архів:</label>
                    <div
                      onDragOver={(e) => { e.preventDefault(); setIsDragActive(true); }}
                      onDragLeave={() => setIsDragActive(false)}
                      onDrop={(e) => {
                        e.preventDefault();
                        setIsDragActive(false);
                        const f = e.dataTransfer.files?.[0];
                        if (f) setUploadFile(f);
                      }}
                      onClick={() => document.getElementById("upload-file-input")?.click()}
                      className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${isDragActive ? "border-zinc-400 bg-zinc-800/50" : "border-zinc-700 hover:border-zinc-600"}`}
                    >
                      <input
                        id="upload-file-input"
                        type="file"
                        accept=".py,.js,.jsx,.ts,.tsx,.zip"
                        className="hidden"
                        onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                      />
                      <svg className="w-8 h-8 mx-auto mb-2 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg>
                      {uploadFile ? (
                        <div>
                          <p className="text-zinc-200 text-sm font-medium break-all">{uploadFile.name}</p>
                          <p className="text-zinc-500 text-xs mt-1">{(uploadFile.size / 1024).toFixed(1)} КБ</p>
                        </div>
                      ) : (
                        <p className="text-zinc-500 text-sm">Перетягніть файл або архів</p>
                      )}
                    </div>
                  </div>
                )}

                <button
                  onClick={
                    scanMode === "single" ? handleScan :
                    scanMode === "batch" ? handleBatchStreamScan :
                    scanMode === "snippet" ? handleSnippetScan :
                    handleUploadScan
                  }
                  disabled={loading || (scanMode === "snippet" && (!snippetCode.trim() || snippetByteLen > SNIPPET_MAX_BYTES)) || (scanMode === "upload" && !uploadFile)}
                  className="w-full bg-zinc-100 hover:bg-zinc-200 disabled:bg-zinc-800 disabled:text-zinc-600 text-zinc-950 font-bold py-3.5 px-4 rounded-xl transition-all flex justify-center items-center gap-2 shadow-sm"
                >
                  {loading ? (
                    <><svg className="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Обробка...</>
                  ) : "Запустити сканування"}
                </button>
                {isStreamingMode && loading && (
                  <button onClick={handleStopStream} className="w-full mt-2 bg-transparent hover:bg-red-950/30 text-red-400 border border-red-900/50 font-medium py-2.5 px-4 rounded-xl transition-all text-sm">
                    Зупинити
                  </button>
                )}
              </div>

              {/* Права панель результатів */}
              <div className={`${scanMode === "snippet" && streamResults.length === 0 ? "lg:col-span-5" : "lg:col-span-8"} bg-zinc-900 p-6 rounded-2xl border border-zinc-800 shadow-xl flex flex-col min-h-0`}>
                <div className="flex justify-between items-center mb-6 border-b border-zinc-800 pb-4 shrink-0">
                  <h2 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
                    <svg className="w-5 h-5 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                    Звіт про безпеку (XAI)
                  </h2>
                  {isStreamingMode && streamRan ? (
                    loading ? (
                      <span className="bg-zinc-800 text-zinc-300 px-3 py-1 rounded-full text-sm font-medium border border-zinc-700 font-mono">
                        {streamResults.length} / {streamTotal || "?"}
                      </span>
                    ) : error ? null : streamResults.filter((r) => !r.is_error).length === 0 ? (
                      <span className="bg-emerald-950/50 text-emerald-400 px-3 py-1 rounded-full text-sm font-medium border border-emerald-900/50">Безпечно</span>
                    ) : (
                      <span className="bg-red-950/50 text-red-400 px-3 py-1 rounded-full text-sm font-medium border border-red-900/50">
                        Знайдено: {streamResults.filter((r) => !r.is_error).length}
                      </span>
                    )
                  ) : (
                    report && (
                      report.vulnerabilities === 0 ? (
                        <span className="bg-emerald-950/50 text-emerald-400 px-3 py-1 rounded-full text-sm font-medium border border-emerald-900/50">Безпечно</span>
                      ) : (
                        <span className="bg-red-950/50 text-red-400 px-3 py-1 rounded-full text-sm font-medium border border-red-900/50">
                          Знайдено: {report.total_vulnerabilities ?? report.results?.length}
                        </span>
                      )
                    )
                  )}
                </div>

                <div className="flex-1 overflow-y-auto pr-2 space-y-6 custom-scrollbar">
                  {error && (
                    <div className="bg-red-950/50 border border-red-900/50 text-red-400 p-4 rounded-xl text-sm flex items-start gap-3">
                      <svg className="w-5 h-5 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                      <span>{error}</span>
                    </div>
                  )}

                  {!report && !loading && !error && !streamRan && (
                    <div className="h-full min-h-[200px] flex flex-col items-center justify-center text-zinc-600">
                      <svg className="w-16 h-16 mb-4 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2v0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
                      <p>Очікування цілі для аналізу...</p>
                    </div>
                  )}

                  {loading && scanMode === "single" && (
                    <div className="bg-zinc-950 border border-zinc-800 p-8 rounded-2xl flex flex-col items-center justify-center space-y-5 my-12">
                      <div className="relative flex items-center justify-center">
                        <div className="w-10 h-10 border-3 border-zinc-800 border-t-zinc-300 rounded-full animate-spin"></div>
                      </div>
                      <div className="text-center">
                        <p className="text-zinc-200 font-medium text-base mb-1">Виконується аудит безпеки</p>
                        <p className="text-zinc-500 text-sm font-mono animate-pulse">{statusMessage}</p>
                      </div>
                    </div>
                  )}

                  {loading && isStreamingMode && (
                    <div className="bg-zinc-950 border border-zinc-800 p-6 rounded-2xl space-y-3">
                      <div className="text-sm">
                        <span className="text-zinc-300 font-medium block truncate">{statusMessage || "Сканування..."}</span>
                      </div>
                      <div className="w-full bg-zinc-800 rounded-full h-2 overflow-hidden">
                        <div
                          className="bg-zinc-100 h-full rounded-full transition-all duration-300"
                          style={{ width: streamTotal ? `${Math.min(100, (streamResults.length / streamTotal) * 100)}%` : "5%" }}
                        />
                      </div>
                    </div>
                  )}

                  {!error && ((report && report.vulnerabilities === 0) ||
                    (isStreamingMode && streamRan && !loading && streamResults.length === 0)) && (
                    <div className="bg-emerald-950/30 border border-emerald-900/40 p-8 rounded-2xl flex flex-col items-center justify-center space-y-4 my-12">
                      <div className="w-16 h-16 bg-emerald-900/50 rounded-2xl flex items-center justify-center text-emerald-400 border border-emerald-800/50 shadow-inner">
                        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <div className="text-center">
                        <h3 className="text-emerald-400 text-lg font-bold mb-1">Код безпечний!</h3>
                        <p className="text-zinc-400 text-sm">Статичний аналізатор не виявив жодних загроз у цьому файлі.</p>
                      </div>
                    </div>
                  )}

                  {report && report.results?.length > 0 && (
                    <div className="space-y-6 pb-6">
                      {report.results.map((res: any, idx: number) => (
                        <ResultCard key={idx} res={res} />
                      ))}
                    </div>
                  )}

                  {isStreamingMode && streamResults.length > 0 && (
                    <div className="space-y-6 pb-6">
                      {streamResults.map((res: any, idx: number) => (
                        <ResultCard key={idx} res={res} />
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        ) : activeTab === "research" ? (
          <ResearchTab />
        ) : (
          <div className="flex flex-col h-full max-w-6xl w-full mx-auto">
            <header className="mb-6 shrink-0 flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-zinc-100">Історія сканувань</h1>
                <p className="text-zinc-500 mt-2">Журнал аудитів безпеки вашого коду</p>
              </div>
              {(viewingSession || sessionError) && (
                <button
                  onClick={() => { setViewingSession(null); setSessionError(""); }}
                  className="text-sm text-zinc-400 hover:text-zinc-100 border border-zinc-800 hover:border-zinc-700 px-4 py-2 rounded-xl transition-all"
                >
                  ← Назад до списку
                </button>
              )}
            </header>

            {sessionLoading ? (
              <div className="flex-1 flex justify-center items-center text-zinc-500 bg-zinc-900 rounded-2xl border border-zinc-800">Завантаження сесії...</div>
            ) : sessionError ? (
              <div className="bg-red-950/50 border border-red-900/50 text-red-400 p-4 rounded-xl text-sm flex items-start gap-3">
                <svg className="w-5 h-5 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                <span>{sessionError}</span>
              </div>
            ) : viewingSession ? (
              <div className="flex-1 overflow-y-auto space-y-6 pb-6 pr-2 custom-scrollbar">
                {viewingSession.results?.length > 0 ? (
                  viewingSession.results.map((res: any, idx: number) => (
                    <ResultCard key={idx} res={res} />
                  ))
                ) : (
                  <div className="p-8 text-center text-zinc-500 bg-zinc-900 rounded-2xl border border-zinc-800">Ця сесія не містить результатів.</div>
                )}
              </div>
            ) : (
            <div className="flex-1 overflow-y-auto bg-zinc-900 rounded-2xl border border-zinc-800 shadow-xl">
              {historyLoading ? (
                <div className="p-8 text-center text-zinc-500 flex justify-center items-center h-full">Завантаження історії...</div>
              ) : history.length === 0 ? (
                <div className="p-8 text-center text-zinc-500 flex justify-center items-center h-full">Ви ще не проводили жодного сканування.</div>
              ) : (
                <table className="w-full text-left text-sm text-zinc-300">
                  <thead className="bg-zinc-950/50 text-zinc-400 border-b border-zinc-800 sticky top-0 backdrop-blur-md">
                    <tr>
                      <th className="px-6 py-4 font-semibold">ID Сесії</th>
                      <th className="px-6 py-4 font-semibold">Дата (UTC)</th>
                      <th className="px-6 py-4 font-semibold">Тип</th>
                      <th className="px-6 py-4 font-semibold">Вразливостей</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    {history.map((item, idx) => (
                      <tr
                        key={idx}
                        onClick={() => loadSession(item.session_id)}
                        className="hover:bg-zinc-800/30 transition-colors cursor-pointer"
                        title="Переглянути результати цієї сесії"
                      >
                        <td className="px-6 py-4 font-mono text-zinc-300">#{item.session_id}</td>
                        <td className="px-6 py-4 text-zinc-400">{new Date(item.created_at).toLocaleString()}</td>
                        <td className="px-6 py-4">
                          <span className={`px-2.5 py-1 rounded-md text-xs font-medium border ${item.scan_type === 'batch' ? 'bg-purple-950/30 text-purple-400 border-purple-900/50' : 'bg-zinc-800 text-zinc-300 border-zinc-700'}`}>
                            {item.scan_type.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-semibold text-red-400">
                           {item.vulnerabilities_count === 0 ? (
                               <span className="text-emerald-400">0</span>
                           ) : (
                               item.vulnerabilities_count
                           )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
}