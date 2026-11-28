// KI-Agent schaltet seine eigenen Rückfragen ab (27.11.2026, Bauplan "Alle drei Stufen").
//
//   RECHTE-AUS    Fehler: in Code, Skripten und Einstellungen ein Schalter, mit dem ein KI-Agent jeden Befehl ohne Rückfrage ausführt.
//                 Nicht in Textdateien (.md, .markdown, .mdx, .txt) und nicht in Prüfdateien (PRUEF_PFAD).
//   RECHTE-DATEI  Hinweis in Zeile 1: die Datei selbst legt fest, was ein KI-Agent ohne Rückfrage darf.
//
// Anlass und Belege (gelesen 27.11.2026):
//   CVE-2025-53773 (GitHub Copilot, August 2025): eingeschleuster Text liess Copilot die Einstellung chat.tools.autoApprove in
//     .vscode\settings.json einschalten, danach lief jeder Befehl ohne Rückfrage.
//     https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection
//   Nx "s1ngularity" (26./27.08.2025): ein verseuchtes npm-Paket rief Claude Code, Gemini CLI und Amazon Q über eine Liste
//     { cmd, args: [...] } mit ihren Abschalt-Schaltern auf.
//     https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package
//   OWASP Top 10 for Agentic Applications (Dezember 2025): ASI03 Missbrauch von Identität und Rechten, ASI05 unerwartete Codeausführung.
//
// Namen der Schalter und Einstellungen, je aus der Anleitung des Herstellers:
//   Claude Code  https://code.claude.com/docs/en/cli-reference, https://code.claude.com/docs/en/permission-modes,
//                https://code.claude.com/docs/en/agent-sdk/permissions
//                Schalter dangerously-skip-permissions (laut Anleitung gleich wie der Modus bypassPermissions) und
//                allow-dangerously-skip-permissions (nimmt den Modus in den Wechsel mit Shift+Tab auf, im Planmodus laufen dann die
//                meisten Befehle ohne Rückfrage); der Modus bypassPermissions über den Schalter permission-mode, die Einstellung
//                permissions.defaultMode oder das SDK (permissionMode in TypeScript, permission_mode in Python); die SDK-Option
//                allowDangerouslySkipPermissions.
//   VS Code      https://code.visualstudio.com/docs/copilot/reference/copilot-settings, https://code.visualstudio.com/docs/agents/run/approvals
//                chat.tools.global.autoApprove ("Automatically approve all tools", heutiger Name), chat.tools.autoApprove (alter
//                Name aus der CVE), chat.permissions.default mit autoApprove oder autopilot ("Allow all and Autopilot skip ordinary
//                tool confirmations"), chat.defaultConfiguration mit approvals allowAll ("Allow all skips ordinary tool
//                confirmations"), github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions.
//   Gemini CLI   https://geminicli.com/docs/cli/cli-reference/  Schalter yolo mit der Kurzform y ("Auto-approve all actions") und
//                approval-mode mit dem Wert yolo.
//   Codex        https://learn.chatgpt.com/docs/developer-commands?surface=cli  Schalter dangerously-bypass-approvals-and-sandbox mit
//                dem zweiten Namen yolo ("Run every command without approvals or sandboxing").
//   Amazon Q     AWS-Befehlsreferenz zu q chat (docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-reference.html) und der
//                Nx-Bericht oben: Schalter trust-all-tools.
//
// Die Schalter stehen hier nur aus Teilen zusammengesetzt, sonst meldete der Wächter seinen eigenen Quelltext.
// Anders als bei den übrigen Mustern zählt Text in Zeichenketten mit: in einem Aufruf steht ein Schalter fast immer in einer
// Zeichenkette (Nx: args: ['...', '-p', PROMPT]). Kommentare zählen nicht.

import { t } from './i18n'
import { OK_SICHER, PRUEF_PFAD, daten } from './sicherheit'
import type { SFund } from './sicherheit'

const ZWEI = '-'.repeat(2)
const GEFAHR = 'dangerously'
const BYPASS = 'bypass' + 'Permissions'
const Q = String.raw`["'\x60]?`

// Ein Schalter als ganzes Wort: kein Buchstabe, keine Ziffer, kein _ und kein - direkt davor oder danach.
const schalter = (s: string): RegExp => new RegExp(String.raw`(?<![\w-])${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\w-])`, 'g')

type Regel = { re: RegExp; wer: string }

// Überall in Code, Skripten und Einstellungen.
const REGELN: Regel[] = [
  { re: schalter(`${ZWEI}${GEFAHR}-skip-permissions`), wer: 'Claude Code' },
  { re: schalter(`${ZWEI}allow-${GEFAHR}-skip-permissions`), wer: 'Claude Code' },
  // permissions.defaultMode, permissionMode, permission_mode, claudeCode.initialPermissionMode und der Schalter permission-mode, je
  // mit dem Wert bypassPermissions (als Zuweisung, Schlüssel: Wert oder nächstes Listenelement - ein Vergleich mit === zählt nicht).
  { re: new RegExp(String.raw`(?:defaultMode|[Pp]ermission[_-]?[Mm]ode)(?:${Q}\s*[:=,]\s*${Q}|\s+)${BYPASS}(?![\w-])`, 'g'), wer: 'Claude Code' },
  { re: new RegExp(String.raw`allow${'Dangerously'}SkipPermissions${Q}\s*[:=]\s*${Q}[Tt]rue\b`, 'g'), wer: 'Claude Code' },
  { re: schalter(`${ZWEI}${GEFAHR}-bypass-approvals-and-sandbox`), wer: 'Codex' },
  { re: schalter(`${ZWEI}trust-all-tools`), wer: 'Amazon Q' },
  { re: new RegExp(String.raw`["']chat\.tools\.(?:global\.)?auto${'Approve'}["']\s*:\s*true\b`, 'g'), wer: 'VS Code' },
  { re: new RegExp(String.raw`["']chat\.permissions\.default["']\s*:\s*["'](?:auto${'Approve'}|autopilot)["']`, 'g'), wer: 'VS Code' },
  { re: new RegExp(String.raw`["']approvals["']\s*:\s*["']allow${'All'}["']`, 'g'), wer: 'VS Code' },
]

// Nur in einem Aufruf des Programms: die Kurzformen sind zu allgemein (npx und apt-get kennen auch die Kurzform y).
type Aufruf = { befehl: RegExp; schalter: RegExp[]; wer: string }
const AUFRUFE: Aufruf[] = [
  {
    befehl: /(?<![\w.-])(?:@google\/gemini-cli|gemini(?:\.(?:cmd|exe|ps1|bat))?)(?![\w.-])/g,
    schalter: [schalter(`${ZWEI}yolo`), schalter('-y'), new RegExp(String.raw`${ZWEI}approval-mode(?:${Q}\s*[=,]\s*${Q}|\s+)yolo(?![\w-])`, 'g')],
    wer: 'Gemini CLI',
  },
  { befehl: /(?<![\w.-])(?:@openai\/codex|codex(?:\.(?:cmd|exe|ps1|bat))?)(?![\w.-])/g, schalter: [schalter(`${ZWEI}yolo`)], wer: 'Codex' },
]

// Wie weit ein Aufruf reicht: bis zum Zeilenende, über Folgezeilen nur bei offener Klammer oder wenn die Zeile mit \ ` ^ , ( [ {
// endet (höchstens 8 Zeilen, 600 Zeichen); Schluss bei einer Klammer, die vor dem Aufruf aufging, und bei ; | && auf oberster Ebene.
function fensterEnde(s: string, ab: number): number {
  let tiefe = 0
  let zeilen = 0
  const max = Math.min(s.length, ab + 600)
  for (let k = ab; k < max; k++) {
    const c = s[k]
    if (c === '(' || c === '[' || c === '{') tiefe++
    else if (c === ')' || c === ']' || c === '}') {
      if (--tiefe < 0) return k
    } else if (tiefe <= 0 && (c === ';' || c === '|' || (c === '&' && s[k + 1] === '&'))) return k
    else if (c === '\n') {
      if (tiefe <= 0 && !/[\\`^,([{]$/.test(s.slice(ab, k).trimEnd())) return k
      if (++zeilen > 8) return k
    }
  }
  return max
}

// Textdateien: dort beschreibt ein Schalter etwas, er schaltet nichts.
const PROSA = /\.(?:md|markdown|mdx|txt)$/i

// Die Dateien, die festlegen, was ein KI-Agent ohne Rückfrage darf (27.11.2026).
const RECHTE_DATEI =
  /(?:^|[\\/])\.claude[\\/]settings(?:\.local)?\.json$|(?:^|[\\/])\.claude\.json$|(?:^|[\\/])\.mcp\.json$|(?:^|[\\/])\.vscode[\\/](?:settings|tasks)\.json$|(?:^|[\\/])\.cursor[\\/]mcp\.json$|(?:^|[\\/])hooks[\\/]hooks\.json$/i

// Kommentarart je Dateiart. Unbekannte Arten: nichts gilt als Kommentar.
type Art = 'c' | 'py' | 'ps' | 'bat' | 'ini' | 'raute' | 'xml' | 'keine'
const ARTEN: [RegExp, Art][] = [
  [/\.(?:js|mjs|cjs|jsx|ts|tsx|mts|cts|cs|c|cc|cpp|cxx|h|hpp|hxx|java|kt|kts|go|rs|swift|scala|dart|php|json|jsonc|json5|code-workspace|gradle|groovy|css|scss|less)$/i, 'c'],
  [/\.pyw?$/i, 'py'],
  [/\.ps[dm]?1$/i, 'ps'],
  [/\.(?:bat|cmd)$/i, 'bat'],
  [/\.(?:ini|cfg|conf)$/i, 'ini'],
  [/\.(?:sh|bash|zsh|fish|ya?ml|toml|env|properties|rb|pl|pm|r|nix|tf|mk|cmake)$|(?:^|[\\/])(?:Dockerfile|Makefile|GNUmakefile|\.env(?:\.[\w.-]+)?)$/i, 'raute'],
  [/\.(?:xml|xaml|axaml|csproj|vbproj|fsproj|vcxproj|props|targets|config|manifest|nuspec|resx|html?|svg|xsd|xslt?)$/i, 'xml'],
]

const artVon = (file: string): Art => ARTEN.find(([re]) => re.test(file))?.[1] ?? 'keine'

// Kommentare durch Leerzeichen ersetzt (Zeilen und Längen bleiben, Zeichenketten bleiben stehen).
function kommentarFrei(text: string, art: Art): string {
  if (art === 'keine') return text
  const o = text.split('')
  const leer = (a: number, b: number) => {
    for (let k = a; k < b && k < o.length; k++) if (o[k] !== '\n' && o[k] !== '\r') o[k] = ' '
  }
  const zeilenEnde = (i: number): number => {
    const e = text.indexOf('\n', i)
    return e === -1 ? text.length : e
  }
  if (art === 'bat') {
    // REM und :: am Zeilenanfang (auch nach @)
    for (let i = 0; i < text.length; ) {
      const e = zeilenEnde(i)
      if (/^\s*@?\s*(?:rem(?:\s|$)|::)/i.test(text.slice(i, e))) leer(i, e)
      i = e + 1
    }
    return o.join('')
  }
  if (art === 'xml') {
    for (let i = text.indexOf('<!--'); i !== -1; ) {
      const e = text.indexOf('-->', i + 4)
      const s = e === -1 ? text.length : e + 3
      leer(i, s)
      i = text.indexOf('<!--', s)
    }
    return o.join('')
  }
  // Ende einer Zeichenkette, die bei i beginnt (Stelle nach dem schliessenden Zeichen).
  const textEnde = (i: number): number => {
    const c = text[i]
    const bis = (zu: string, flucht: string | undefined, mehrzeilig: boolean): number => {
      let k = i + zu.length
      while (k < text.length && !text.startsWith(zu, k) && (mehrzeilig || text[k] !== '\n')) k += flucht !== undefined && text[k] === flucht ? 2 : 1
      return text.startsWith(zu, k) ? k + zu.length : k
    }
    if (art === 'c') {
      if (c === '`') return bis('`', '\\', true)
      if (text.startsWith('"""', i)) return bis('"""', undefined, true)
      // C# @"..." und $@"...": kein Escape, "" ist ein Anführungszeichen
      if (c === '"' && (text[i - 1] === '@' || (text[i - 1] === '$' && text[i - 2] === '@'))) {
        let k = i + 1
        while (k < text.length && !(text[k] === '"' && text[k + 1] !== '"')) k += text[k] === '"' ? 2 : 1
        return k + 1
      }
      return bis(c, '\\', false)
    }
    if (art === 'py') return text.startsWith(c.repeat(3), i) ? bis(c.repeat(3), '\\', true) : bis(c, '\\', false)
    if (art === 'ps') {
      // Here-String @" ... "@ (das Ende steht am Anfang einer Zeile)
      if (text[i - 1] === '@' && /^\s*$/.test(text.slice(i + 1, zeilenEnde(i)))) {
        const e = text.indexOf(`\n${c}@`, i)
        return e === -1 ? text.length : e + 3
      }
      return bis(c, c === '"' ? '`' : undefined, false)
    }
    // Shell, YAML, TOML, INI: ' ohne Escape, " mit \
    return bis(c, c === '"' ? '\\' : undefined, false)
  }
  let i = 0
  while (i < text.length) {
    const c = text[i]
    const d = text[i + 1]
    const nachLeer = i === 0 || /\s/.test(text[i - 1] ?? '')
    if (art === 'c' && c === '/' && d === '/') {
      const s = zeilenEnde(i)
      leer(i, s)
      i = s
    } else if ((art === 'c' && c === '/' && d === '*') || (art === 'ps' && c === '<' && d === '#')) {
      const e = text.indexOf(c === '/' ? '*/' : '#>', i + 2)
      const s = e === -1 ? text.length : e + 2
      leer(i, s)
      i = s
    } else if (art !== 'c' && ((c === '#' && (art === 'py' || nachLeer)) || (art === 'ini' && c === ';' && /(?:^|\n)[ \t]*$/.test(text.slice(Math.max(0, i - 200), i))))) {
      const s = zeilenEnde(i)
      leer(i, s)
      i = s
    } else if (c === '"' || c === "'" || (art === 'c' && c === '`')) i = textEnde(i)
    else i++
  }
  return o.join('')
}

export function rechteAbschalter(text: string, file: string): SFund[] {
  const funde: SFund[] = []
  const roh = text.split(/\r?\n/)
  const muster = t('Muster', 'pattern')
  if (RECHTE_DATEI.test(file) && !OK_SICHER.test(roh[0] ?? '')) {
    funde.push({ line: 1, col: 1, code: 'RECHTE-DATEI', schwer: false, scanner: muster,
      text: t('Diese Datei steuert, was ein KI-Agent ohne Rückfrage darf - jede Änderung prüfen.',
        'This file controls what an AI agent may do without asking - check every change.') })
  }
  if (PROSA.test(file) || PRUEF_PFAD.test(file)) return funde
  const frei = kommentarFrei(text, artVon(file))
  // Anfang jeder Zeile, für Zeile und Spalte eines Fundes.
  const anfang = [0]
  for (let k = frei.indexOf('\n'); k !== -1; k = frei.indexOf('\n', k + 1)) anfang.push(k + 1)
  const zeileBei = (at: number): number => {
    let lo = 0
    let hi = anfang.length - 1
    while (lo < hi) {
      const mitte = (lo + hi + 1) >> 1
      if ((anfang[mitte] ?? 0) <= at) lo = mitte
      else hi = mitte - 1
    }
    return lo + 1
  }
  const zeilen = new Set<number>()
  const melden = (at: number, wer: string, gefunden: string) => {
    const nr = zeileBei(at)
    if (zeilen.has(nr) || OK_SICHER.test(roh[nr - 1] ?? '')) return
    zeilen.add(nr)
    const was = daten(gefunden.replace(/["'`]/g, '').replace(/\s+/g, ' ').trim(), 80)
    funde.push({ line: nr, col: at - (anfang[nr - 1] ?? 0) + 1, code: 'RECHTE-AUS', schwer: true, scanner: muster,
      text: t(`${wer}: ${was} schaltet die Rückfragen ab - der KI-Agent führt dann jeden Befehl ohne Nachfrage aus, auch einen eingeschleusten. Schalter entfernen und nur einzelne Befehle gezielt freigeben.`,
        `${wer}: ${was} switches off the confirmations - the AI agent then runs every command without asking, including an injected one. Remove the switch and allow only single commands on purpose.`) })
  }
  for (const r of REGELN) for (const m of frei.matchAll(r.re)) melden(m.index ?? 0, r.wer, m[0])
  for (const a of AUFRUFE) {
    for (const m of frei.matchAll(a.befehl)) {
      const von = (m.index ?? 0) + m[0].length
      const fenster = frei.slice(von, fensterEnde(frei, von))
      for (const s of a.schalter) for (const x of fenster.matchAll(s)) melden(von + (x.index ?? 0), a.wer, x[0])
    }
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}
