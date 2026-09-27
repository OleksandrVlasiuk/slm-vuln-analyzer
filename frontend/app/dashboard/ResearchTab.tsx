"use client";
import { useEffect, useState } from "react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ErrorBar, Cell,
} from "recharts";
import { apiFetch } from "@/lib/api";

// Вкладка «Дослідження»: результати scripts/evaluate.py -> build_stage1_summary.py
// -> compare.py (results/stage1_summary.csv, results/stage2_compare.csv), подані
// через GET /api/research.

const STAGE1_COLUMNS: { key: string; label: string; direction: "higher" | "lower" }[] = [
  { key: "fix_valid", label: "fix_valid", direction: "higher" },
  { key: "cwe_keyword_hit", label: "cwe_keyword_hit", direction: "higher" },
  { key: "off_topic_class", label: "off_topic_class", direction: "lower" },
  { key: "lt_errors_per_100w", label: "LT-помилок/100 слів", direction: "lower" },
  { key: "avoid_hits", label: "avoid_hits", direction: "lower" },
  { key: "ru_chars", label: "русизми (симв.)", direction: "lower" },
  { key: "median_total_s", label: "медіана часу, с", direction: "lower" },
];

const STAGE2_METRICS = [
  { key: "fix_valid", label: "fix_valid" },
  { key: "cwe_keyword_hit", label: "cwe_keyword_hit" },
  { key: "localization_hit", label: "localization_hit" },
  { key: "off_topic_class", label: "off_topic_class" },
  { key: "lt_errors_per_100w", label: "LT-помилок/100 слів" },
  { key: "avoid_hits", label: "avoid_hits" },
];

const CONDITION_ORDER = ["temp_0.5", "temp_0.9", "prompt_V0", "prompt_V1", "codeonly", "rag", "think_on"];
const CONDITION_LABELS: Record<string, string> = {
  "temp_0.5": "T = 0.5",
  "temp_0.9": "T = 0.9",
  prompt_V0: "Промпт V0",
  prompt_V1: "Промпт V1",
  codeonly: "Без SAST-контексту",
  rag: "RAG (глосарій)",
  think_on: "Режим міркування",
};

function toNum(v: any): number | null {
  if (v === null || v === undefined || v === "" || v === "NA") return null;
  const n = parseFloat(v);
  return Number.isNaN(n) ? null : n;
}

function shortModel(name: string): string {
  return name.split("/").pop() || name;
}

export default function ResearchTab() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [stage1, setStage1] = useState<any[]>([]);
  const [stage2, setStage2] = useState<any[]>([]);
  const [recommended, setRecommended] = useState<{ model?: string; prompt_version?: string; temperature?: string }>({});

  const [selectedModel, setSelectedModel] = useState<string>("");
  const [selectedMetric, setSelectedMetric] = useState<string>("fix_valid");

  const [manualSummary, setManualSummary] = useState<any[]>([]);
  const [manualError, setManualError] = useState("");
  const [manualLoading, setManualLoading] = useState(true);

  useEffect(() => {
    apiFetch("/api/research")
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          setError(data.detail || "Не вдалося завантажити дані досліджень.");
          return;
        }
        setStage1(data.stage1 || []);
        setStage2(data.stage2 || []);
        setRecommended({
          model: data.recommended_model,
          prompt_version: data.recommended_prompt_version,
          temperature: String(data.recommended_temperature),
        });
        const models = Array.from(new Set((data.stage2 || []).map((r: any) => r.model))) as string[];
        if (models.length > 0) setSelectedModel(models[0]);
      })
      .catch(() => setError("Сервер недоступний"))
      .finally(() => setLoading(false));

    // Ручна перевірка — окремий, незалежний запит: відсутність цих даних не
    // повинна ховати решту вкладки «Дослідження».
    apiFetch("/api/manual_review")
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          setManualError(data.detail || "Не вдалося завантажити ручну перевірку.");
          return;
        }
        setManualSummary(data.summary || []);
      })
      .catch(() => setManualError("Сервер недоступний"))
      .finally(() => setManualLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex-1 flex justify-center items-center text-zinc-500 h-full">Завантаження результатів досліджень...</div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col h-full max-w-4xl mx-auto justify-center">
        <div className="bg-red-950/50 border border-red-900/50 text-red-400 p-4 rounded-xl text-sm flex items-start gap-3">
          <svg className="w-5 h-5 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          <span>{error}</span>
        </div>
      </div>
    );
  }

  // Найкраще значення в кожній колонці етапу 1
  const bestByColumn: Record<string, number | null> = {};
  for (const col of STAGE1_COLUMNS) {
    const values = stage1.map((r) => toNum(r[col.key])).filter((v): v is number => v !== null);
    if (values.length === 0) { bestByColumn[col.key] = null; continue; }
    bestByColumn[col.key] = col.direction === "higher" ? Math.max(...values) : Math.min(...values);
  }

  const stage2Models = Array.from(new Set(stage2.map((r) => r.model)));
  const rowsForSelection = stage2.filter((r) => r.model === selectedModel && r.metric === selectedMetric);
  const baseline = rowsForSelection.length > 0 ? toNum(rowsForSelection[0].mean_baseline) : null;

  const chartData = CONDITION_ORDER.map((cond) => {
    const row = rowsForSelection.find((r) => r.condition === cond);
    if (!row) return null;
    const md = toNum(row.mean_diff) ?? 0;
    const lo = toNum(row.ci95_lo);
    const hi = toNum(row.ci95_hi);
    return {
      condition: CONDITION_LABELS[cond] || cond,
      mean_diff: md,
      error: [Math.max(0, md - (lo ?? md)), Math.max(0, (hi ?? md) - md)],
      p_value: row.p_value,
    };
  }).filter((d): d is NonNullable<typeof d> => d !== null);

  return (
    <div className="flex flex-col max-w-6xl w-full mx-auto space-y-8 pb-8">
      <header className="shrink-0">
        <h1 className="text-3xl font-bold text-zinc-100">Дослідження</h1>
        <p className="text-zinc-500 mt-2">Результати оцінки якості пояснень SLM (results/stage1_summary.csv, results/stage2_compare.csv)</p>
      </header>

      {/* Конфігурація продукту */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-xl shrink-0">
        <h2 className="text-lg font-semibold text-zinc-100 mb-3 flex items-center gap-2">
          <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          Конфігурація продукту
        </h2>
        <div className="flex flex-wrap gap-2 mb-3">
          <span className="text-xs text-zinc-300 bg-zinc-800 border border-zinc-700 px-2.5 py-1 rounded-md font-mono">{recommended.model || "gemma4:e2b"}</span>
          <span className="text-xs text-zinc-300 bg-zinc-800 border border-zinc-700 px-2.5 py-1 rounded-md font-mono">Промпт {recommended.prompt_version || "V2"}</span>
          <span className="text-xs text-zinc-300 bg-zinc-800 border border-zinc-700 px-2.5 py-1 rounded-md font-mono">T = {recommended.temperature || "0.1"}</span>
        </div>
        <p className="text-sm text-zinc-400 leading-relaxed">
          Базова конфігурація обрана за етапом 1 (найкращий баланс fix_valid, влучності термінології
          й швидкості серед протестованих моделей) — жодна з умов етапу 2 (температура, спрощені
          промпти, RAG-глосарій) не дала статистично значущого покращення fix_valid відносно бази.
        </p>
      </div>

      {/* Етап 1 */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-xl overflow-x-auto shrink-0">
        <h2 className="text-lg font-semibold text-zinc-100 mb-4">Етап 1 — порівняння моделей (базова умова)</h2>
        <table className="w-full text-sm text-left text-zinc-300 min-w-[700px]">
          <thead className="text-zinc-400 border-b border-zinc-800">
            <tr>
              <th className="py-2 pr-4 font-semibold">Модель</th>
              {STAGE1_COLUMNS.map((col) => (
                <th key={col.key} className="py-2 pr-4 font-semibold whitespace-nowrap">{col.label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/50">
            {stage1.map((row, idx) => (
              <tr key={idx}>
                <td className="py-2.5 pr-4 font-mono text-zinc-200">
                  {shortModel(row.model)}
                  {row.model === recommended.model && (
                    <span className="ml-2 text-[10px] text-emerald-400 bg-emerald-950/50 border border-emerald-900/50 px-1.5 py-0.5 rounded-md align-middle">рекомендовано</span>
                  )}
                </td>
                {STAGE1_COLUMNS.map((col) => {
                  const v = toNum(row[col.key]);
                  const isBest = v !== null && bestByColumn[col.key] !== null && v === bestByColumn[col.key];
                  return (
                    <td key={col.key} className={`py-2.5 pr-4 font-mono ${isBest ? "text-emerald-400 font-bold" : "text-zinc-300"}`}>
                      {v === null ? "—" : v}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Етап 2 */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-xl shrink-0">
        <h2 className="text-lg font-semibold text-zinc-100 mb-4">Етап 2 — умова vs база</h2>

        <div className="flex flex-wrap gap-4 mb-6">
          <div>
            <label className="block text-xs font-medium text-zinc-500 mb-1.5">Модель</label>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-sm text-zinc-100 focus:outline-none focus:border-zinc-500"
            >
              {stage2Models.map((m) => (
                <option key={m} value={m}>{shortModel(m)}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-500 mb-1.5">Метрика</label>
            <select
              value={selectedMetric}
              onChange={(e) => setSelectedMetric(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-sm text-zinc-100 focus:outline-none focus:border-zinc-500"
            >
              {STAGE2_METRICS.map((m) => (
                <option key={m.key} value={m.key}>{m.label}</option>
              ))}
            </select>
          </div>
        </div>

        {rowsForSelection.length === 0 ? (
          <p className="text-zinc-500 text-sm">Немає даних для цієї комбінації моделі й метрики.</p>
        ) : (
          <>
            <div className="overflow-x-auto mb-6">
              <table className="w-full text-sm text-left text-zinc-300 min-w-[600px]">
                <thead className="text-zinc-400 border-b border-zinc-800">
                  <tr>
                    <th className="py-2 pr-4 font-semibold">Умова</th>
                    <th className="py-2 pr-4 font-semibold">База</th>
                    <th className="py-2 pr-4 font-semibold">Умова</th>
                    <th className="py-2 pr-4 font-semibold">95% ДІ різниці</th>
                    <th className="py-2 pr-4 font-semibold">p</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50">
                  {CONDITION_ORDER.map((cond) => {
                    const row = rowsForSelection.find((r) => r.condition === cond);
                    if (!row) return null;
                    const p = toNum(row.p_value);
                    const sig = p !== null && p < 0.05;
                    return (
                      <tr key={cond}>
                        <td className="py-2.5 pr-4 text-zinc-200">{CONDITION_LABELS[cond] || cond}</td>
                        <td className="py-2.5 pr-4 font-mono">{row.mean_baseline}</td>
                        <td className="py-2.5 pr-4 font-mono">{row.mean_condition}</td>
                        <td className="py-2.5 pr-4 font-mono text-zinc-400">
                          [{row.ci95_lo ?? "—"}, {row.ci95_hi ?? "—"}]
                        </td>
                        <td className={`py-2.5 pr-4 font-mono ${sig ? "text-amber-400 font-bold" : "text-zinc-400"}`}>
                          {row.p_value || "—"}{sig ? " *" : ""}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <p className="text-xs text-zinc-600 mt-2">* p &lt; 0.05 (парний тест: Мак-Немар для бінарних метрик, Вілкоксон — для числових)</p>
            </div>

            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                  <XAxis dataKey="condition" tick={{ fill: "#a1a1aa", fontSize: 12 }} angle={-20} textAnchor="end" height={60} />
                  <YAxis tick={{ fill: "#a1a1aa", fontSize: 12 }} label={{ value: `Δ ${selectedMetric}`, angle: -90, position: "insideLeft", fill: "#a1a1aa", fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: 8, color: "#e4e4e7" }} />
                  <ReferenceLine y={0} stroke="#71717a" />
                  <Bar dataKey="mean_diff" fill="#818cf8" radius={[4, 4, 0, 0]}>
                    <ErrorBar dataKey="error" width={4} strokeWidth={2} stroke="#f87171" direction="y" />
                    {chartData.map((d, i) => (
                      <Cell key={i} fill={d.mean_diff >= 0 ? "#34d399" : "#f87171"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </>
        )}
      </div>

      {/* Ручна перевірка */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 shadow-xl shrink-0">
        <h2 className="text-lg font-semibold text-zinc-100 mb-1 flex items-center gap-2">
          <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          Ручна перевірка
        </h2>
        <p className="text-xs text-zinc-500 mb-4">
          <code className="text-zinc-400">fix_valid</code> — автоматична метрика (evaluate.py);{" "}
          <code className="text-zinc-400">fix_correct</code> — оцінка людини-експерта. Це не те саме.
        </p>

        {manualLoading ? (
          <p className="text-zinc-500 text-sm">Завантаження...</p>
        ) : manualError ? (
          <div className="bg-red-950/50 border border-red-900/50 text-red-400 p-4 rounded-xl text-sm flex items-start gap-3">
            <svg className="w-5 h-5 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            <span>{manualError}</span>
          </div>
        ) : (
          (() => {
            const byCategory = (cat: string) => manualSummary.filter((r) => r.category === cat);
            const single = (cat: string) => byCategory(cat)[0];
            const semgrepPrecision = single("semgrep_precision_overall");
            const fixValidPrecision = single("fix_valid_precision");
            const fixCorrectByModel = byCategory("fix_correct_by_model");
            const explCorrectByModel = byCategory("explanation_correct_by_model");

            const pct = (v: any) => (v === "" || v === null || v === undefined ? "—" : `${Math.round(parseFloat(v) * 100)}%`);

            return (
              <div className="space-y-5">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4">
                    <p className="text-xs text-zinc-500 mb-1">Точність Semgrep</p>
                    <p className="text-2xl font-bold text-zinc-100">{pct(semgrepPrecision?.value)}</p>
                    <p className="text-[11px] text-zinc-600 mt-1">{semgrepPrecision?.positive}/{semgrepPrecision?.labeled} TP</p>
                  </div>
                  <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4">
                    <p className="text-xs text-zinc-500 mb-1">Precision fix_valid</p>
                    <p className="text-2xl font-bold text-zinc-100">{pct(fixValidPrecision?.value)}</p>
                    <p className="text-[11px] text-zinc-600 mt-1">{fixValidPrecision?.positive}/{fixValidPrecision?.labeled} справді правильні</p>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left text-zinc-300 min-w-[500px]">
                    <thead className="text-zinc-400 border-b border-zinc-800">
                      <tr>
                        <th className="py-2 pr-4 font-semibold">Модель</th>
                        <th className="py-2 pr-4 font-semibold">Правильні виправлення (fix_correct)</th>
                        <th className="py-2 pr-4 font-semibold">Правильні пояснення (explanation_correct)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/50">
                      {fixCorrectByModel.map((r) => {
                        const expl = explCorrectByModel.find((e) => e.key === r.key);
                        return (
                          <tr key={r.key}>
                            <td className="py-2.5 pr-4 font-mono text-zinc-200">{shortModel(r.key)}</td>
                            <td className="py-2.5 pr-4 font-mono">{pct(r.value)} <span className="text-zinc-600 text-xs">({r.positive}/{r.labeled})</span></td>
                            <td className="py-2.5 pr-4 font-mono">{pct(expl?.value)} <span className="text-zinc-600 text-xs">({expl?.positive}/{expl?.labeled})</span></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })()
        )}
      </div>
    </div>
  );
}
