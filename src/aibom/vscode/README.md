# aibom VS Code extension (scaffold)

This directory is a **scaffold** — it ships enough to `npm install && code --extensionDevelopmentPath=.` your way to a running extension, but it deliberately does not bundle a JS build pipeline (esbuild / webpack / tsc) because that's an opinion that should live in the consuming repo.

## What it does

- On every save of a Python / JS / TS / YAML / Terraform file, runs `aibom scan <workspace> --format sarif --output /tmp/aibom.sarif`.
- Reads the resulting SARIF and surfaces findings as **diagnostics** in the Problems panel and inline editor squigglies.
- One command palette entry: `AiBOM: Scan Workspace`.

## Requirements

- `aibom` on the user's PATH (install from this repo: `pip install -e .` at the repo root).
- VS Code 1.85+.

## Build

```bash
cd src/aibom/vscode
npm install
# package as a .vsix
npx @vscode/vsce package
```

## Status

This is a scaffold that the team can extend. The intentional gaps:

- No CodeLens / hover provider yet — diagnostics only.
- No webview to render the executive dashboard (P4) — that's a separate v0.2.
- No language-server protocol — sequential subprocess + SARIF re-read on every save.
