// Build a self-contained prototype file from the source parts.
import { readFileSync, writeFileSync } from 'node:fs';

const template = readFileSync('src/index.html', 'utf8');
const css = readFileSync('src/styles.css', 'utf8');
const js = readFileSync('src/app.js', 'utf8');

const output = template
  .replace('  <link rel="stylesheet" href="styles.css">', () => `  <style>\n${css}\n  </style>`)
  .replace('  <script src="app.js"></script>', () => `  <script>\n${js}\n  </script>`);

writeFileSync('index.html', output, 'utf8');
console.log(`Built index.html (${(output.length / 1024).toFixed(1)} KB)`);
