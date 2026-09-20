/**
 * Build REPORT.pdf from REPORT.md.
 *
 * Renders the Markdown to a print-styled HTML file; headless Chrome then
 * converts that to PDF. Kept in the repository so the PDF deliverable can be
 * regenerated after any edit to REPORT.md, rather than being a one-off
 * artefact nobody can reproduce.
 *
 * Usage:
 *   npm install --no-save markdown-it
 *   node scripts/build-report.js
 *   "C:/Program Files/Google/Chrome/Application/chrome.exe"  *     --headless --disable-gpu --no-pdf-header-footer  *     --print-to-pdf=REPORT.pdf file:///<abs-path>/REPORT.html
 *
 * On macOS/Linux substitute the platform's Chrome binary path.
 */
const fs = require("fs");
const path = require("path");
const MarkdownIt = require("markdown-it");

// Resolve relative to this file so the script works from any checkout.
const ROOT = path.resolve(__dirname, "..");
const src = process.argv[2] || path.join(ROOT, "REPORT.md");
const out = process.argv[3] || path.join(ROOT, "REPORT.html");

const md = new MarkdownIt({ html: true, linkify: false, typographer: false });
const body = md.render(fs.readFileSync(src, "utf8"));

const css = `
@page { size: A4; margin: 18mm 16mm 20mm 16mm; }

:root {
  --ink:      #1a1d23;
  --muted:    #55606e;
  --rule:     #d7dce3;
  --accent:   #1f4e79;
  --codebg:   #f5f7fa;
  --thbg:     #eef2f7;
}

* { box-sizing: border-box; }

body {
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-size: 10.2pt;
  line-height: 1.55;
  color: var(--ink);
  margin: 0;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

h1, h2, h3, h4 { color: var(--accent); line-height: 1.25; margin: 1.1em 0 .45em; }
h1 { font-size: 20pt; border-bottom: 2.5px solid var(--accent); padding-bottom: .3em; margin-top: 0; }
h2 { font-size: 14pt; border-bottom: 1px solid var(--rule); padding-bottom: .22em; margin-top: 1.6em; page-break-after: avoid; }
h3 { font-size: 11.6pt; margin-top: 1.3em; page-break-after: avoid; }
h4 { font-size: 10.6pt; color: var(--ink); page-break-after: avoid; }

/* Keep a vulnerability heading with the table that follows it. */
h3 + table { page-break-before: avoid; }

p { margin: .5em 0; orphans: 3; widows: 3; }

code {
  font-family: "Cascadia Mono", Consolas, "Courier New", monospace;
  font-size: 8.9pt;
  background: var(--codebg);
  border: 1px solid var(--rule);
  border-radius: 3px;
  padding: .06em .32em;
}

pre {
  background: var(--codebg);
  border: 1px solid var(--rule);
  border-left: 3px solid var(--accent);
  border-radius: 4px;
  padding: .7em .9em;
  overflow-x: auto;
  page-break-inside: avoid;
  font-size: 8.6pt;
  line-height: 1.45;
}
pre code { background: none; border: none; padding: 0; font-size: inherit; }

table {
  border-collapse: collapse;
  width: 100%;
  margin: .8em 0;
  font-size: 9.1pt;
  page-break-inside: avoid;
}
th, td { border: 1px solid var(--rule); padding: .42em .6em; text-align: left; vertical-align: top; }
th { background: var(--thbg); font-weight: 600; color: var(--accent); }
tr:nth-child(even) td { background: #fbfcfd; }

blockquote {
  margin: .9em 0;
  padding: .6em 1em;
  border-left: 3.5px solid var(--accent);
  background: #f2f6fa;
  color: var(--muted);
  page-break-inside: avoid;
}
blockquote p { margin: .3em 0; }
blockquote strong { color: var(--accent); }

ul, ol { margin: .5em 0; padding-left: 1.5em; }
li { margin: .22em 0; }

hr { border: none; border-top: 1px solid var(--rule); margin: 1.6em 0; }

strong { color: #111; }
a { color: var(--accent); text-decoration: none; }
`;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>SE4030 Security Assessment Report</title>
<style>${css}</style>
</head>
<body>
${body}
</body>
</html>`;

fs.writeFileSync(out, html, "utf8");
console.log("wrote", out, fs.statSync(out).size, "bytes");
