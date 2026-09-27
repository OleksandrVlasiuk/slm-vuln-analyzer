// Видаляє всі коментарі (// та /* */) з JS/TS-коду, читаючи з stdin і пишучи
// в stdout. Символи коментарів замінюються пробілами, символи переносу рядка
// (\n, \r) НЕ чіпаються — кількість рядків і номери рядків лишаються тими
// самими. Використовує сканер з пакета "typescript" (frontend/node_modules).
"use strict";

const path = require("path");
const ts = require(path.join(__dirname, "..", "frontend", "node_modules", "typescript"));

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    /* skipTrivia */ false,
    ts.LanguageVariant.Standard,
    input
  );

  const chars = input.split("");
  let tok = scanner.scan();
  while (tok !== ts.SyntaxKind.EndOfFileToken) {
    if (
      tok === ts.SyntaxKind.SingleLineCommentTrivia ||
      tok === ts.SyntaxKind.MultiLineCommentTrivia
    ) {
      const start = scanner.getTokenPos();
      const end = scanner.getTextPos();
      for (let i = start; i < end; i++) {
        if (chars[i] !== "\n" && chars[i] !== "\r") {
          chars[i] = " ";
        }
      }
    }
    tok = scanner.scan();
  }

  process.stdout.write(chars.join(""));
});
