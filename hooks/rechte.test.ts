import { expect, test } from 'claude-code/testing'
import { setLang } from './i18n'
import { rechteAbschalter } from './rechte'

// Erwartungen aus dem Auftrag vom 27.11.2026 (Regel "KI-Agent schaltet seine eigenen Rückfragen ab") und den Anleitungen der
// Hersteller (Namen siehe Kopf von rechte.ts). Diese Datei ist eine Prüfdatei: die Schalter stehen hier absichtlich im Klartext.
const art = (text: string, file: string) => rechteAbschalter(text, file).map(f => `${f.code}${f.schwer ? '!' : ''}@${f.line}`)

test('Claude Code: Schalter und Modus bypassPermissions in Skripten, Code und Einstellungen sind rot', () => {
  expect(art('claude --dangerously-skip-permissions -p "Aufgabe"\n', 'D:\\p\\start.ps1')).toEqual(['RECHTE-AUS!@1'])
  expect(art('@echo off\r\nclaude -p "x" --dangerously-skip-permissions\r\n', 'D:\\p\\start.cmd')).toEqual(['RECHTE-AUS!@2'])
  expect(art('#!/bin/sh\nclaude --allow-dangerously-skip-permissions\n', 'D:\\p\\start.sh')).toEqual(['RECHTE-AUS!@2'])
  expect(art('subprocess.run(["claude", "--permission-mode", "bypassPermissions", "-p", aufgabe])\n', 'D:\\p\\lauf.py')).toEqual(['RECHTE-AUS!@1'])
  expect(art('spawn("claude", ["--permission-mode=bypassPermissions"])\n', 'D:\\p\\lauf.js')).toEqual(['RECHTE-AUS!@1'])
  expect(art('claude --permission-mode bypassPermissions\n', 'D:\\p\\lauf.ps1')).toEqual(['RECHTE-AUS!@1'])
  expect(art('{\n  "permissions": {\n    "defaultMode": "bypassPermissions"\n  }\n}\n', 'D:\\p\\einstellung.json')).toEqual(['RECHTE-AUS!@3'])
  expect(art("const q = query({ prompt, options: { permissionMode: 'bypassPermissions' } })\n", 'D:\\p\\agent.ts')).toEqual(['RECHTE-AUS!@1'])
  expect(art('const o = {\n  allowDangerouslySkipPermissions: true,\n}\n', 'D:\\p\\agent.ts')).toEqual(['RECHTE-AUS!@2'])
  expect(art('options = ClaudeAgentOptions(permission_mode="bypassPermissions")\n', 'D:\\p\\agent.py')).toEqual(['RECHTE-AUS!@1'])
  expect(art('    with:\n      claude_args: "--dangerously-skip-permissions"\n', 'D:\\p\\.github\\workflows\\ki.yml')).toEqual(['RECHTE-AUS!@2'])
})

test('Claude Code: ähnliche, harmlose Stellen bleiben still', () => {
  expect(art("if (permissionMode === 'bypassPermissions') warnen()\n", 'D:\\p\\a.ts')).toEqual([])
  expect(art('if permission_mode == "bypassPermissions":\n    warnen()\n', 'D:\\p\\a.py')).toEqual([])
  expect(art("type Modus = { permissionMode: 'default' | 'bypassPermissions' }\n", 'D:\\p\\a.ts')).toEqual([])
  expect(art('{ "permissions": { "defaultMode": "acceptEdits", "disableBypassPermissionsMode": "disable" } }', 'D:\\p\\e.json')).toEqual([])
  expect(art('claude --permission-mode plan --dangerously-load-development-channels server:x\n', 'D:\\p\\s.ps1')).toEqual([])
  expect(art('{ "allowDangerouslySkipPermissions": false }', 'D:\\p\\e.json')).toEqual([])
  expect(art('claude -p "Aufgabe" --allowedTools "Read"\n', 'D:\\p\\s.sh')).toEqual([])
  expect(art('const name = "--dangerously-skip-permissions-hinweis"\n', 'D:\\p\\a.ts')).toEqual([])
})

test('Gemini CLI: yolo, y und approval-mode yolo nur in einem gemini-Aufruf', () => {
  expect(art('gemini --yolo -p "Aufgabe"\n', 'D:\\p\\a.ps1')).toEqual(['RECHTE-AUS!@1'])
  expect(art('gemini -y -p "x"\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  expect(art('gemini --approval-mode=yolo -p x\r\n', 'D:\\p\\a.cmd')).toEqual(['RECHTE-AUS!@1'])
  expect(art('gemini --approval-mode yolo\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  expect(art('npx @google/gemini-cli -y -p x\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  expect(art('& "C:\\Tools\\gemini.cmd" --yolo\n', 'D:\\p\\a.ps1')).toEqual(['RECHTE-AUS!@1'])
  expect(art('subprocess.run(["gemini", "-p", aufgabe, "-y"])\n', 'D:\\p\\a.py')).toEqual(['RECHTE-AUS!@1'])
  expect(art('befehl = [\n    "gemini",\n    "-p", aufgabe,\n    "--yolo",\n]\n', 'D:\\p\\a.py')).toEqual(['RECHTE-AUS!@4'])
  // Die Kurzform gehört hier einem anderen Programm oder steht nach dem Ende des Aufrufs.
  expect(art('npx -y @google/gemini-cli -p "x"\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('apt-get install -y gemini\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('gemini -p "x" && apt-get install -y curl\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('gemini -p "x" | tee log; choco install -y foo\n', 'D:\\p\\a.ps1')).toEqual([])
  expect(art('gemini --approval-mode=auto_edit -p x\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('llm -m gemini-2.5-pro -y\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('mytool --yolo\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art("const gemini = require('x'); run('-y')\n", 'D:\\p\\a.js')).toEqual([])
})

test('Codex und Amazon Q: Schalter, die alle Befehle ohne Rückfrage erlauben', () => {
  expect(art('codex --dangerously-bypass-approvals-and-sandbox exec "x"\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  expect(art('codex exec --yolo "x"\n', 'D:\\p\\a.ps1')).toEqual(['RECHTE-AUS!@1'])
  expect(art('subprocess.run(["codex", "--yolo"])\n', 'D:\\p\\a.py')).toEqual(['RECHTE-AUS!@1'])
  expect(art('q chat --trust-all-tools --no-interactive "x"\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  expect(art("const c = { cmd: 'q', args: ['chat', '--trust-all-tools'] }\n", 'D:\\p\\a.ts')).toEqual(['RECHTE-AUS!@1'])
  expect(art('codex exec --sandbox read-only "x"\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('q chat --trust-tools=fs_read "x"\n', 'D:\\p\\a.sh')).toEqual([])
  expect(art('yolo predict model=yolov8n.pt\n', 'D:\\p\\a.sh')).toEqual([])
})

test('VS Code: Einstellungen, die alle Werkzeuge ohne Rückfrage freigeben, sind rot', () => {
  const vs = 'D:\\p\\.vscode\\settings.json'
  const rot = ['RECHTE-DATEI@1', 'RECHTE-AUS!@2']
  expect(art('{\n  "chat.tools.autoApprove": true\n}\n', vs)).toEqual(rot)
  expect(art('{\n  "chat.tools.global.autoApprove": true\n}\n', vs)).toEqual(rot)
  expect(art('{\n  "chat.permissions.default": "autoApprove"\n}\n', vs)).toEqual(rot)
  expect(art('{\n  "chat.permissions.default": "autopilot"\n}\n', vs)).toEqual(rot)
  expect(art('{\n  "chat.defaultConfiguration": { "mode": "interactive", "approvals": "allowAll" }\n}\n', vs)).toEqual(rot)
  expect(art('{\n  "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions": true\n}\n', vs)).toEqual(rot)
  expect(art('{ "settings": { "chat.tools.global.autoApprove": true } }', 'D:\\p\\projekt.code-workspace')).toEqual(['RECHTE-AUS!@1'])
  // Aus, einzelne Regeln oder die Grundeinstellung: nur der Hinweis auf die Datei
  expect(art('{\n  "chat.tools.global.autoApprove": false\n}\n', vs)).toEqual(['RECHTE-DATEI@1'])
  expect(art('{\n  "chat.tools.terminal.autoApprove": { "rm": false, "git status": true }\n}\n', vs)).toEqual(['RECHTE-DATEI@1'])
  expect(art('{\n  "chat.tools.edits.autoApprove": { "**/*.md": true }\n}\n', vs)).toEqual(['RECHTE-DATEI@1'])
  expect(art('{\n  "chat.permissions.default": "default"\n}\n', vs)).toEqual(['RECHTE-DATEI@1'])
  expect(art('{\n  "chat.defaultConfiguration": { "approvals": "manual" }\n}\n', vs)).toEqual(['RECHTE-DATEI@1'])
})

test('Nx-Angriff 2025: Liste mit cmd und args wird je Eintrag rot (Aufbau nach dem Bericht von Snyk)', () => {
  const nx = [
    "const PROMPT = 'x'",
    'const cliChecks = {',
    "  claude: { cmd: 'claude', args: ['--dangerously-skip-permissions', '-p', PROMPT] },",
    "  gemini: { cmd: 'gemini', args: ['--yolo', '-p', PROMPT] },",
    "  q: { cmd: 'q', args: ['chat', '--trust-all-tools', '--no-interactive', PROMPT] },",
    '}',
  ].join('\n')
  const f = rechteAbschalter(nx, 'D:\\p\\node_modules\\nx\\telemetry.js')
  expect(f.map(x => `${x.code}${x.schwer ? '!' : ''}@${x.line}`)).toEqual(['RECHTE-AUS!@3', 'RECHTE-AUS!@4', 'RECHTE-AUS!@5'])
  expect(f[0]?.text).toContain('Claude Code')
  expect(f[1]?.text).toContain('Gemini CLI')
  expect(f[2]?.text).toContain('Amazon Q')
})

test('Kommentare zählen nicht, Zeichenketten schon', () => {
  expect(art('// nie claude --dangerously-skip-permissions benutzen\nconst a = 1\n', 'D:\\p\\a.ts')).toEqual([])
  expect(art('/* Beispiel:\n   claude --dangerously-skip-permissions\n*/\nconst a = 1\n', 'D:\\p\\a.ts')).toEqual([])
  expect(art('const u = "http://x"; const a = ["--dangerously-skip-permissions"]\n', 'D:\\p\\a.ts')).toEqual(['RECHTE-AUS!@1'])
  expect(art('# claude --dangerously-skip-permissions\nx = 1\n', 'D:\\p\\a.py')).toEqual([])
  expect(art('x = "# kein Kommentar --dangerously-skip-permissions"\n', 'D:\\p\\a.py')).toEqual(['RECHTE-AUS!@1'])
  expect(art('<#\nclaude --dangerously-skip-permissions\n#>\nWrite-Host "ok"\n', 'D:\\p\\a.ps1')).toEqual([])
  expect(art('Write-Host "ok" # claude --dangerously-skip-permissions\n', 'D:\\p\\a.ps1')).toEqual([])
  expect(art('REM claude --dangerously-skip-permissions\r\n:: gemini --yolo\r\n@rem codex --yolo\r\n', 'D:\\p\\a.bat')).toEqual([])
  expect(art('# claude --dangerously-skip-permissions\nname: x\n', 'D:\\p\\a.yml')).toEqual([])
  expect(art('<!-- claude --dangerously-skip-permissions -->\n<Exec Command="claude --dangerously-skip-permissions" />\n', 'D:\\p\\a.csproj')).toEqual(['RECHTE-AUS!@2'])
  // C#-Text @"...\" endet am Anführungszeichen (kein Escape): der Kommentar dahinter bleibt ein Kommentar.
  expect(art('var p = @"C:\\x\\"; // claude --dangerously-skip-permissions\n', 'D:\\p\\a.cs')).toEqual([])
  expect(art('claude --dangerously-skip-permissions # Kommentar\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  expect(art('{\n  // "defaultMode": "bypassPermissions"\n  "defaultMode": "default"\n}\n', 'D:\\p\\e.jsonc')).toEqual([])
})

test('Textdateien, Prüfdateien und die Markierung bleiben ohne roten Fund', () => {
  const q = 'q chat --trust-all-tools "x"\n'
  expect(art(q, 'D:\\p\\README.md')).toEqual([])
  expect(art(q, 'D:\\p\\Notizen.txt')).toEqual([])
  expect(art(q, 'D:\\p\\Notizen.markdown')).toEqual([])
  expect(art(q, 'D:\\p\\Tests\\lauf.ps1')).toEqual([])
  expect(art('gemini --yolo -p x\n', 'D:\\p\\rechte.test.ts')).toEqual([])
  expect(art('{ "defaultMode": "bypassPermissions" }', 'D:\\p\\Tests\\e.json')).toEqual([])
  expect(art(q, 'D:\\p\\Mod.Probe\\start.cmd')).toEqual([])
  expect(art('q chat --trust-all-tools # code-waechter:ok SICHERHEIT nur in der Wegwerf-VM\n', 'D:\\p\\vm.sh')).toEqual([])
  expect(art('q chat --trust-all-tools # code-waechter:ok SICHERHEIT nur in der Wegwerf-VM\nq chat --trust-all-tools\n', 'D:\\p\\vm.sh')).toEqual(['RECHTE-AUS!@2'])
})

test('RECHTE-DATEI: Hinweis in Zeile 1 nur für die Dateien, die die Rechte eines KI-Agenten festlegen', () => {
  const ja = [
    'C:\\Users\\nutzer\\.claude\\settings.json',
    'D:\\p\\.claude\\settings.json',
    'D:\\p\\.claude\\settings.local.json',
    'C:\\Users\\nutzer\\.claude.json',
    'D:\\p\\.mcp.json',
    'D:\\p\\.vscode\\settings.json',
    'D:\\p\\.vscode\\tasks.json',
    'D:\\p\\.cursor\\mcp.json',
    'C:\\Users\\nutzer\\.claude\\plugins\\code-waechter\\hooks\\hooks.json',
    'D:/p/.claude/settings.json',
    'D:\\P\\.VSCODE\\SETTINGS.JSON',
  ]
  for (const p of ja) {
    const f = rechteAbschalter('{}\n', p)
    expect(f.map(x => [x.line, x.col, x.code, x.schwer])).toEqual([[1, 1, 'RECHTE-DATEI', false]])
    expect(f[0]?.text).toContain('Diese Datei steuert, was ein KI-Agent ohne Rückfrage darf - jede Änderung prüfen')
  }
  expect(art('', 'D:\\p\\.mcp.json')).toEqual(['RECHTE-DATEI@1'])
  const nein = ['D:\\p\\settings.json', 'D:\\p\\hooks.json', 'D:\\p\\.vscode\\launch.json', 'D:\\p\\.claude\\settings.json.bak', 'D:\\p\\claude.json', 'D:\\p\\.claude\\agents\\helfer.json', 'D:\\p\\mcp.json']
  for (const p of nein) expect(art('{}\n', p)).toEqual([])
  expect(art('// code-waechter:ok SICHERHEIT geprüft 27.11.2026\n{}\n', 'D:\\p\\.vscode\\settings.json')).toEqual([])
  // Prüfdatei: höchstens der Hinweis, kein roter Fund
  expect(art('{\n  "chat.tools.global.autoApprove": true\n}\n', 'D:\\p\\Tests\\.vscode\\settings.json')).toEqual(['RECHTE-DATEI@1'])
})

test('Zeile, Spalte und Text der Meldung; ein Fund je Zeile', () => {
  const f = rechteAbschalter('x\n  claude --dangerously-skip-permissions\n', 'D:\\p\\a.sh')
  expect(f.map(x => [x.line, x.col, x.code, x.schwer])).toEqual([[2, 10, 'RECHTE-AUS', true]])
  expect(f[0]?.text).toContain('Claude Code')
  expect(f[0]?.text).toContain('«--dangerously-skip-permissions»')
  expect(f[0]?.text).toContain('schaltet die Rückfragen ab')
  const j = rechteAbschalter('a\r\nb\r\n  "defaultMode": "bypassPermissions"\r\n', 'D:\\p\\e.json')
  expect(j.map(x => [x.line, x.col])).toEqual([[3, 4]])
  expect(j[0]?.text).toContain('«defaultMode: bypassPermissions»')
  expect(art('claude --dangerously-skip-permissions --permission-mode bypassPermissions\n', 'D:\\p\\a.sh')).toEqual(['RECHTE-AUS!@1'])
  setLang('en')
  try {
    expect(rechteAbschalter('gemini --yolo\n', 'D:\\p\\a.sh')[0]?.text).toContain('switches off the confirmations')
    expect(rechteAbschalter('{}', 'D:\\p\\.mcp.json')[0]?.text).toContain('This file controls what an AI agent may do without asking')
  } finally {
    setLang('de')
  }
})
