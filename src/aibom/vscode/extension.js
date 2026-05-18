// AiBOM VS Code extension — scaffold.
//
// On activation we register a single command (`aibom.scanWorkspace`) and
// a save listener that re-runs the scan. Findings are surfaced as
// diagnostics via the SARIF output of `aibom scan ... --format sarif`.

const vscode = require('vscode');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let diagnosticCollection;

function activate(context) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('aibom');
  context.subscriptions.push(diagnosticCollection);

  const scanCommand = vscode.commands.registerCommand('aibom.scanWorkspace', () => runScan());
  context.subscriptions.push(scanCommand);

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      const cfg = vscode.workspace.getConfiguration('aibom');
      if (cfg.get('scanOnSave', true)) {
        runScan();
      }
    })
  );

  // Initial scan on activation.
  runScan();
}

function runScan() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return;
  }
  const cwd = folders[0].uri.fsPath;
  const cfg = vscode.workspace.getConfiguration('aibom');
  const exe = cfg.get('executable', 'aibom');

  const sarifPath = path.join(os.tmpdir(), `aibom-${process.pid}.sarif`);
  const args = ['scan', cwd, '--format', 'sarif', '--output', sarifPath];

  const proc = spawn(exe, args, { cwd });
  proc.on('error', (err) => {
    vscode.window.showWarningMessage(`AiBOM: failed to start ${exe}: ${err.message}`);
  });
  proc.on('close', (code) => {
    if (code !== 0) {
      vscode.window.showWarningMessage(`AiBOM: scan exited with code ${code}`);
      return;
    }
    try {
      const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
      applyDiagnostics(cwd, sarif);
    } catch (err) {
      vscode.window.showWarningMessage(`AiBOM: failed to parse SARIF: ${err.message}`);
    }
  });
}

function applyDiagnostics(cwd, sarif) {
  diagnosticCollection.clear();
  const byFile = new Map();
  const run = (sarif.runs || [])[0];
  if (!run) return;
  for (const result of run.results || []) {
    const loc = (result.locations || [])[0] || {};
    const physical = loc.physicalLocation || {};
    const uri = (physical.artifactLocation || {}).uri;
    if (!uri) continue;
    const fileUri = vscode.Uri.file(path.join(cwd, uri));
    const region = physical.region || {};
    const line = Math.max(0, (region.startLine || 1) - 1);
    const range = new vscode.Range(line, 0, line, 200);
    const message = (result.message && result.message.text) || result.ruleId || 'aibom finding';
    const severity = mapSeverity(result.level);
    const diag = new vscode.Diagnostic(range, message, severity);
    diag.source = 'aibom';
    diag.code = result.ruleId;
    const arr = byFile.get(fileUri.toString()) || [];
    arr.push(diag);
    byFile.set(fileUri.toString(), arr);
  }
  for (const [uriStr, diags] of byFile.entries()) {
    diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
  }
}

function mapSeverity(level) {
  switch (level) {
    case 'error':   return vscode.DiagnosticSeverity.Error;
    case 'warning': return vscode.DiagnosticSeverity.Warning;
    case 'note':    return vscode.DiagnosticSeverity.Information;
    default:        return vscode.DiagnosticSeverity.Hint;
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
