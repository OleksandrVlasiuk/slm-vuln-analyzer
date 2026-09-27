// Синтаксична перевірка TS/TSX-файлу через parseDiagnostics пакета
// "typescript" (frontend/node_modules) — той самий пакет, що й
// strip_ts_comments.js. Друкує {"ok": bool, "count": int} у stdout.
"use strict";

const path = require("path");
const fs = require("fs");
const ts = require(path.join(__dirname, "..", "frontend", "node_modules", "typescript"));

const filePath = process.argv[2];
const source = fs.readFileSync(filePath, "utf8");
const scriptKind = /\.tsx$/i.test(filePath) ? ts.ScriptKind.TSX : ts.ScriptKind.TS;

const sourceFile = ts.createSourceFile(filePath, source, ts.ScriptTarget.Latest, false, scriptKind);
const diagnostics = sourceFile.parseDiagnostics || [];

process.stdout.write(JSON.stringify({ ok: diagnostics.length === 0, count: diagnostics.length }));
