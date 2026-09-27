"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:8000/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (res.ok) {
        const data = await res.json();
        // Токен і дані користувача — у localStorage; lib/api.ts читає їх
        // для заголовка Authorization у наступних запитах.
        localStorage.setItem("user_id", data.user_id);
        localStorage.setItem("username", data.username);
        localStorage.setItem("token", data.token);
        router.push("/dashboard");
      } else {
        setError("Невірний логін або пароль");
      }
    } catch (err) {
      setError("Помилка підключення до сервера");
    }
    setLoading(false);
  };

  return (
    <main className="min-h-screen bg-zinc-950 flex items-center justify-center p-4 font-sans">
      <div className="bg-zinc-900 p-8 rounded-2xl border border-zinc-800 shadow-2xl w-full max-w-md">

        <div className="text-center mb-8">
          <div className="bg-zinc-800 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-zinc-700 shadow-inner">
            <svg className="w-8 h-8 text-zinc-100" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-zinc-100">SLM Analyzer</h1>
          <p className="text-zinc-500 mt-2">Корпоративний доступ</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-1.5">Користувач</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-zinc-100 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-1.5">Пароль</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-zinc-100 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all"
            />
          </div>

          {error && (
            <div className="bg-red-950/50 text-red-400 p-3 rounded-xl text-sm text-center border border-red-900/50">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold py-3 rounded-xl transition-all mt-6 disabled:opacity-50"
          >
            {loading ? "Авторизація..." : "Увійти в систему"}
          </button>
        </form>

      </div>
    </main>
  );
}