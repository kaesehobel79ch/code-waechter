// Sicherheits-Scanner: nach jedem Schreiben laufen die Scanner, die zur Dateiart passen; alle Funde stehen zusätzlich gebündelt
// in <Ablage>\security-report.txt.
//
//   DevSkim   C#, C, C++ (unsichere Aufrufe, schwache Verschlüsselung, abgeschaltete Zertifikatsprüfung)
//   Cppcheck  C, C++ (Speicherfehler, Pufferüberläufe, Zeigerfehler)
//   Bandit    Python (typische Python-Sicherheitslücken)
//   Gitleaks  jede geprüfte Datei und Einstellungsdateien (Passwörter, Zugangsschlüssel, Token, Webhooks)
//   MSVC /analyze und clang-tidy  C, C++ (seit 27.11.2026, c_analyse.ts: Lesen/Schreiben über Puffer, uninitialisiert, nach free/delete)
//   OSV-Scanner  Paketdateien (seit 27.11.2026, osv.ts: Pakete mit bekannten Lücken, offline gegen die geladene Datenbank)
//   Semgrep   Python, C#, JavaScript/TypeScript (seit 28.11.2026, semgrep.ts: Datenfluss innerhalb einer Funktion mit eigenen Regeln)
//   eigene Muster: C# Harmony-Patches (aus der Anleitung von Harmony 2) und Process.Start; C/C++ Überlauf und Formattext;
//             JavaScript/TypeScript Pfad und SQL aus der Anfrage; Python Pfad aus einer Eingabe; eingebaute Schlüssel (alle vier)
//
// Seit 27.11.2026 (Crashtest Lücken L1-L6) laufen alle Scanner und Muster auch im /scan (scannenOrdner), je Scanner ein Aufruf.
//
// Gemessen am 20.11.2026 (DevSkim 1.0.90): DevSkim meldet BinaryFormatter und Process.Start NICHT - BinaryFormatter prüfen die
// KI-Fehlerarten (haertung.ts), Process.Start die eigenen Muster hier.
//
// Fehler (✖) sind nur Funde, die fast nie absichtlich sind: Geheimnisse (Gitleaks, ohne die Regel generic-api-key), Cppcheck-Schwere
// "error" (ausser unsicher), DevSkim "Critical", Bandit hohe Schwere mit hoher Sicherheit, Harmony UnpatchAll() ohne Kennung und
// nicht statische Patch-Methoden. Alles andere ist ein Hinweis. Bewusste Stellen: die Unterdrückung des jeweiligen Scanners
// (DevSkim: "DevSkim: ignore DS…", Cppcheck: "cppcheck-suppress id", Bandit: "# nosec", Gitleaks: "gitleaks:allow"), bei den
// eigenen Mustern "code-waechter:ok SICHERHEIT" in der Zeile.
// Fehlt ein Scanner, lief er nicht durch oder hat er die Datei übersprungen, steht das offen beim ✔ ("nicht geprüft: …") - nie still.
//
// Unabhängige Gegenprüfung 20.11.2026 (39 Prüfer, 34 bestätigte Funde), daraus u. a.: Gitleaks generic-api-key traf in einem
// Spiel-Mod-Projekt 5247-mal, alles Übersetzungsschlüssel (description_key=...); DevSkim DS126858 (MD2/MD4/MD5) trifft ohne Wortgrenze auch "fremd2";
// Cppcheck las .h als C; DevSkim überspringt **/bin/** und Bandit Pfade mit ".git" still; Spalten von DevSkim sind 0-basiert, die von
// Gitleaks ab Zeile 2 um 1 zu gross; Bandit B105-B107 und Gitleaks-Zeilen enthielten das Geheimnis selbst.

import { t } from './i18n'
import { C_ANALYSE_MS, cAnalyse } from './c_analyse'
import type { CWerkzeuge } from './c_analyse'
import { OSV_DATEI, osvPruefen } from './osv'
import { SEMGREP_DATEI, SEMGREP_MS, semgrepPruefen } from './semgrep'

// geheim: die Fundstelle enthält ein Geheimnis - die Quelltextzeile wird nirgends gezeigt.
export type SFund = { line: number; col: number; code: string; text: string; schwer: boolean; scanner: string; geheim?: boolean }

export type Lauf =
  | { ok: true; exitCode: number; stdout: string; stderr: string; truncated: boolean }
  | { ok: false; reason: string }

export type Ergebnis = { funde: SFund[]; luecken: string[]; liefen: string[] }

// Was die Scanner von der Mod brauchen (in den Tests ersetzbar).
export type Umgebung = {
  run: (argv: string[], opts: { cwd?: string; env?: Record<string, string>; timeoutMs?: number }) => Promise<Lauf>
  python: string[]
  exe: (name: 'devskim' | 'cppcheck' | 'gitleaks') => Promise<string | undefined>
  workDir: () => Promise<string>
  read: (path: string) => Promise<string | undefined>
  write: (path: string, text: string) => Promise<void>
  // Kennung dieses Chats für Hilfsdateien: der Arbeitsordner gehört allen Chats, jeder prüft für sich.
  kennung: string
  // Nur für den Ordner-Scan (scannenOrdner): einen Hilfsordner samt Inhalt löschen, und die Uhr für die Zeitgrenze.
  leeren?: (dir: string) => Promise<void>
  // Nur für den Ordner-Scan: eine Datei unverändert in den Spiegel kopieren, wenn write sie nicht schreiben kann ($.fs.write
  // lehnt laut Schnittstelle alles über 4 MiB ab; gemessen 28.11.2026: 37 Dateien ab 4,79 MB blieben ungeprüft).
  // fristMs: höchstens so lange darf die Kopie dauern (Rest der Zeitgrenze des Scans, höchstens 120 s).
  kopieren?: (von: string, nach: string, fristMs: number) => Promise<void>
  jetzt?: () => Promise<number>
  // C/C++-Analyse (c_analyse.ts): cl.exe mit seinen Kopfdatei-Ordnern und clang-tidy, je mit vollem Pfad (fehlt eins: offene Lücke).
  // Ohne dieses Feld gehört die Analyse nicht zur Umgebung; die Mod (scannerUmgebung in register.tsx) gibt es immer an.
  cAnalyse?: () => Promise<CWerkzeuge>
  // OSV-Scanner (osv.ts): voller Pfad oder undefined (fehlt: offene Lücke). Ohne dieses Feld gehört die Prüfung nicht zur Umgebung.
  osv?: () => Promise<string | undefined>
  // Semgrep mit den eigenen Datenfluss-Regeln (semgrep.ts): voller Pfad oder undefined (fehlt: offene Lücke). Ohne dieses Feld gehört
  // die Prüfung nicht zur Umgebung.
  semgrep?: () => Promise<string | undefined>
}

// Steht vor dem Lauf in der Berichtsdatei: ist sie danach noch da, hat Gitleaks keinen Bericht geschrieben (nie als "keine Funde").
export const GITLEAKS_VORHER = 'CODE-WAECHTER-KEIN-BERICHT'

const C_CPP = /\.(?:c|cc|cpp|cxx|h|hpp|hxx)$/i
const CS = /\.cs$/i
const PY = /\.pyw?$/i

export function scannerFuer(file: string): { devskim: boolean; cppcheck: boolean; bandit: boolean; gitleaks: boolean; muster: boolean } {
  // Muster seit 27.11.2026 auch für JavaScript/TypeScript (Crashtest Lücke L5: Schlüssel; L3/L4: Pfad und SQL aus der Anfrage).
  return { devskim: CS.test(file) || C_CPP.test(file), cppcheck: C_CPP.test(file), bandit: PY.test(file), gitleaks: true, muster: CS.test(file) || C_CPP.test(file) || PY.test(file) || JS.test(file) }
}

// Alle eigenen Muster einer Datei (gleich beim Schreiben und im Scan).
export function eigeneMuster(text: string, file: string): SFund[] {
  const funde: SFund[] = []
  if (CS.test(file)) funde.push(...musterBefunde(text, file))
  if (C_CPP.test(file)) funde.push(...cMuster(text))
  if (JS.test(file)) funde.push(...jsMuster(text, file))
  if (PY.test(file)) funde.push(...pyPfadMuster(text, file))
  funde.push(...geheimMuster(text, file))
  return funde
}

// Text aus einem Scanner für Meldung und Bericht: ohne Farbcodes und Steuerzeichen (sonst entstünden falsche Berichtszeilen), gekürzt.
export function rein(s: string, n = 200): string {
  const x = s
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u001f\u007f-\u009f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, ' ')
    // Unicode-Tags (U+E0000-U+E007F) ganz weg: unsichtbarer Text, den eine KI liest (ASCII-Smuggling) - sonst stand er wörtlich
    // im Fehlerbericht (Gegenprüfung 28.11.2026).
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/\s+/g, ' ')
    .trim()
  return x.length > n ? `${x.slice(0, n - 1)}…` : x
}

// Text, der aus einem Scanner oder der geprüften Datei stammt, in einer Meldung: bereinigt und in «…» gesetzt, damit er als Daten
// erkennbar ist (der Wächter hängt dann den Hinweis "Daten, keine Anweisungen" an).
export function daten(s: string, n = 160): string {
  return `«${rein(s, n).replace(/[«»]/g, '"')}»`
}

// ---- DevSkim: Ausgabe mit -f text -o "%L|%C|%S|%R|%N" (Zeile|Spalte|Schwere|Regel|Name), gemessen an 1.0.90. Die Spalte ist
// 0-basiert; der Wächter zählt ab 1.
export const DEVSKIM_FORMAT = '%L|%C|%S|%R|%N'
// DevSkim lässt ohne -g alles unter **/.git/** und **/bin/** still aus. Ein Muster, das nie zutrifft, ersetzt diese Ausnahmen.
export const NIE_AUSGELASSEN = '**/.code-waechter-nie/**'

export function devskimLesen(stdout: string): { funde: SFund[]; fehler?: string } {
  const funde: SFund[] = []
  for (const z of stdout.split(/\r?\n/)) {
    if (/\bERR\]/.test(z)) return { funde, fehler: z.trim() }
    const m = /^(\d+)\|(\d+)\|(Critical|Important|Moderate|BestPractice|ManualReview)\|(DS\d+)\|(.*)$/.exec(z.trim())
    if (!m) continue
    funde.push({ line: Number(m[1]), col: Number(m[2]) + 1, code: m[4], text: `[${m[3]}] ${rein(m[5])}`, schwer: m[3] === 'Critical', scanner: 'DevSkim' })
  }
  return { funde }
}

// DS126858 (schwacher Hash) sucht MD2/MD4/MD5 ohne Wortgrenze: "fremd2" ist kein Hash. Steht vor der Fundstelle ein Buchstabe, eine
// Ziffer oder _, ist es ein Name, kein Fund.
// DS106863 (Verfahren DES) trifft auch das deutsche Wort "des" in Grossbuchstaben (28.11.2026, ein Prüfprogramm:
// "// GEAENDERT AM ABEND DES 23.09.2026"). Eine Zeile, die mit // beginnt, ist in C#, C und C++ (nur dort läuft DevSkim) ganz
// Kommentar und benutzt kein Verfahren. Nur diese: # ist dort eine Präprozessor-Zeile (#define VERFAHREN "DES"), und eine Zeile
// mit * oder /* am Anfang kann Code sein (*verfahren = "DES"; /* alt */ DES.Create()) - Gegenprüfung 28.11.2026.
export function devskimImWort(f: SFund, zeilen: string[]): boolean {
  const zeile = zeilen[f.line - 1] ?? ''
  if (f.code === 'DS106863') return /^\s*\/\//.test(zeile)
  if (f.code !== 'DS126858') return false
  return /[A-Za-z0-9_]/.test(zeile.charAt(f.col - 2))
}

// ---- Cppcheck: eigenes Format über --template, Felder mit | getrennt (Windows-Pfade enthalten kein |); {inconclusive:U} schreibt U
// nur bei unsicheren Funden. Funde aus eingebundenen Dateien gehören nicht zur geprüften Datei.
export const CPPCHECK_TEMPLATE = '{file}|{line}|{column}|{severity}|{id}|{inconclusive:U}|{message}'
// Meldungen, die bei einer einzelnen Datei nichts aussagen: fehlende Systemkopfdateien, "Funktion nie benutzt" (der Aufrufer
// steht in einer anderen Datei), die Liste der aktiven Prüfungen.
export const CPPCHECK_UNTERDRUECKT = ['missingIncludeSystem', 'missingInclude', 'unusedFunction', 'checkersReport', 'unmatchedSuppression']
// Meldungen, nach denen Cppcheck die Datei nicht (ganz) ausgewertet hat: kein Fund, aber nicht geprüft.
export const CPPCHECK_UNVOLLSTAENDIG = new Set(['syntaxError', 'unknownMacro', 'internalAstError', 'preprocessorErrorDirective', 'toomanyconfigs', 'internalError', 'cppcheckError'])

const gleicherPfad = (a: string, b: string): boolean => a.replace(/\//g, '\\').toLowerCase() === b.replace(/\//g, '\\').toLowerCase()

export function cppcheckLesen(text: string, file: string): { funde: SFund[]; unvollstaendig: string[] } {
  const funde: SFund[] = []
  const unvollstaendig: string[] = []
  for (const z of text.split(/\r?\n/)) {
    const m = /^(.*?)\|(\d+)\|(\d+)\|(error|warning|style|performance|portability|information)\|([\w-]+)\|(U?)\|(.*)$/.exec(z.trim())
    if (!m) continue
    if (CPPCHECK_UNVOLLSTAENDIG.has(m[5])) {
      unvollstaendig.push(`${m[5]}: ${rein(m[7], 120)}`)
      continue
    }
    if (m[4] === 'information' || !gleicherPfad(m[1], file)) continue
    funde.push({ line: Number(m[2]), col: Number(m[3]), code: m[5], text: `[${m[4]}${m[6] ? ', unsicher' : ''}] ${rein(m[7])}`, schwer: m[4] === 'error' && m[6] === '', scanner: 'Cppcheck' })
  }
  return { funde, unvollstaendig }
}

// Dieselben Regeln, die der Wächter bei Ruff auslässt (RUFF_IGNORE in register.tsx: S101, S311, S404, S603, S607), weil sie in
// Werkzeug-Skripten fast immer stimmen: assert, random, "import subprocess", subprocess ohne Shell, Programm ohne vollen Pfad.
// Gemessen 20.11.2026 (Bandit 1.9.4): ohne das meldete schon "import subprocess" (B404).
export const BANDIT_AUSGELASSEN = 'B101,B311,B404,B603,B607'
// Bandit lässt ohne -x jeden Pfad mit .git, .svn, .tox usw. still aus (auch .github, gemessen). Ein Muster, das nie zutrifft, ersetzt das.
export const BANDIT_KEIN_AUSSCHLUSS = '*.code-waechter-nie'
// Diese Regeln geben das gefundene Passwort im Text wieder: der Text wird ersetzt.
const BANDIT_PASSWORT = new Set(['B105', 'B106', 'B107'])
// Harte Blocker unabhängig von Bandits eigener Schwere (24.11.2026, nach einem Sicherheits-Crashtest): exec, eval, pickle, marshal und
// yaml.load führen fremden Code aus; eingebaute Passwörter. Gemessen am 24.11.2026 an 325 Python-Dateien eines Entwicklers: B105-B107 und
// pickle/marshal/yaml 0 Treffer, eval 2 und exec 5 - alle bewusst (eingeschränktes eval, exec eigener Blender-Dateien), diese tragen
// "# nosec B307" bzw. "# nosec B102" mit Grund.
export const BANDIT_SCHWER = new Set(['B102', 'B105', 'B106', 'B107', 'B301', 'B302', 'B307', 'B506'])

// ---- Bandit: -f json; Felder laut Anleitung (results[].line_number, issue_severity, issue_confidence, test_id, issue_text).
// uebersprungen: in "metrics" steht keine Datei - Bandit hat sie nicht gelesen.
export function banditLesen(stdout: string): { funde: SFund[]; fehler?: string; uebersprungen?: boolean } {
  const start = stdout.indexOf('{')
  if (start < 0) return { funde: [], fehler: t('keine JSON-Ausgabe', 'no JSON output') }
  let j: any
  try {
    j = JSON.parse(stdout.slice(start))
  } catch {
    return { funde: [], fehler: t('Ausgabe nicht lesbar', 'output not readable') }
  }
  if (!j || !Array.isArray(j.results)) return { funde: [], fehler: t('Ausgabe ohne Ergebnisliste', 'output without result list') }
  const funde: SFund[] = j.results.map((r: any) => {
    const code = String(r.test_id ?? 'B')
    const passwort = BANDIT_PASSWORT.has(code)
    return {
      line: Number(r.line_number) || 0,
      col: Number(r.col_offset) >= 0 ? Number(r.col_offset) + 1 : 0,
      code,
      text: `[${r.issue_severity}/${r.issue_confidence}] ${passwort ? t('möglicherweise eingebautes Passwort (Text verborgen)', 'possible hardcoded password (text hidden)') : rein(String(r.issue_text ?? ''))}`,
      schwer: (r.issue_severity === 'HIGH' && r.issue_confidence === 'HIGH') || BANDIT_SCHWER.has(code),
      scanner: 'Bandit',
      ...(passwort ? { geheim: true } : {}),
    }
  })
  const fehler = Array.isArray(j.errors) && j.errors.length > 0 ? rein(String(j.errors[0]?.reason ?? JSON.stringify(j.errors[0])), 160) : undefined
  const dateien = j.metrics && typeof j.metrics === 'object' ? Object.keys(j.metrics).filter(k => k !== '_totals') : []
  return { funde, fehler, ...(dateien.length === 0 ? { uebersprungen: true } : {}) }
}

// ---- Gitleaks: --report-format json in eine Datei, --redact (das Geheimnis steht nie im Bericht). Gelesen werden nur RuleID,
// Description, StartLine und StartColumn - nie Secret oder Match. generic-api-key zählt nicht (siehe Kopf: 5247 Fehlalarme).
export const GITLEAKS_OHNE = new Set(['generic-api-key'])
// Base64-, Hex- und Prozent-kodierte Geheimnisse entschlüsseln (27.11.2026, Bauplan Punkt 7; ab Werk 0 = aus, Beleg README
// github.com/gitleaks/gitleaks). Gemessen 27.11.2026 über mehrere Projekte eines Entwicklers: mit Tiefe 2 wie ohne 0 Funde (ohne generic-api-key).
export const GITLEAKS_ENTSCHLUESSELN = ['--max-decode-depth', '2']

function gitleaksEintrag(f: any): SFund {
  const line = Number(f.StartLine) || 0
  const col = Number(f.StartColumn) || 0
  const was = rein(String(f.Description ?? f.RuleID ?? ''), 160)
  return {
    line,
    // Gemessen 20.11.2026 (8.30.1): in Zeile 1 stimmt die Spalte, ab Zeile 2 ist sie um 1 zu gross.
    col: line > 1 && col > 0 ? col - 1 : col,
    code: rein(String(f.RuleID ?? 'gitleaks'), 60),
    text: t(`Geheimnis im Klartext (${was})`, `secret in plain text (${was})`),
    schwer: true,
    scanner: 'Gitleaks',
    geheim: true,
  }
}

function gitleaksListe(json: string): { liste: any[]; fehler?: string } {
  let j: any
  try {
    j = JSON.parse(json.trim() === '' ? '[]' : json)
  } catch {
    return { liste: [], fehler: t('Bericht nicht lesbar', 'report not readable') }
  }
  if (!Array.isArray(j)) return { liste: [], fehler: t('Bericht ohne Liste', 'report without list') }
  return { liste: j.filter((f: any) => !GITLEAKS_OHNE.has(String(f.RuleID ?? ''))) }
}

export function gitleaksLesen(json: string): { funde: SFund[]; fehler?: string } {
  const g = gitleaksListe(json)
  return g.fehler ? { funde: [], fehler: g.fehler } : { funde: g.liste.map(gitleaksEintrag) }
}

// ---- Eigene Muster für C#: Harmony 2 (harmony.pardeike.net, gelesen 20.11.2026) und Process.Start.
export const OK_SICHER = /code-waechter:ok\s+SICHERHEIT\b/
const PATCH_ATTR = /\[\s*Harmony(Prefix|Postfix|Transpiler|Finalizer)\s*\]/
const PATCH_NAME = /^(?:Prefix|Postfix|Transpiler|Finalizer)$/
const METHODE = /^\s*(?:\[[^\]]*\]\s*)*((?:(?:public|private|internal|protected|static|unsafe|override|virtual|new|async|extern)\s+)*)[\w<>[\],.?]+\s+(\w+)\s*\(/

// C#-Text für die Strukturprüfung: Kommentare und der Inhalt von Zeichenketten durch Leerzeichen ersetzt (Zeilen, Längen und
// Anführungszeichen bleiben). Kennt wörtliche Texte @"..." (kein Escape, "" ist ein Anführungszeichen) und rohe Texte """...""".
export function csBereinigt(text: string): string {
  const o = text.split('')
  const leer = (a: number, b: number) => {
    for (let k = a; k < b && k < o.length; k++) if (o[k] !== '\n' && o[k] !== '\r') o[k] = ' '
  }
  let i = 0
  while (i < text.length) {
    const c = text[i]
    const d = text[i + 1]
    if (c === '/' && d === '/') {
      const e = text.indexOf('\n', i)
      const s = e === -1 ? text.length : e
      leer(i, s)
      i = s
    } else if (c === '/' && d === '*') {
      const e = text.indexOf('*/', i + 2)
      const s = e === -1 ? text.length : e + 2
      leer(i, s)
      i = s
    } else if (c === '"' && text.startsWith('"""', i)) {
      const e = text.indexOf('"""', i + 3)
      const s = e === -1 ? text.length : e
      leer(i + 3, s)
      i = s + 3
    } else if (c === '"') {
      const woertlich = text[i - 1] === '@' || (text[i - 1] === '$' && text[i - 2] === '@')
      let k = i + 1
      if (woertlich) {
        while (k < text.length && !(text[k] === '"' && text[k + 1] !== '"')) k += text[k] === '"' ? 2 : 1
      } else {
        while (k < text.length && text[k] !== '"' && text[k] !== '\n') k += text[k] === '\\' ? 2 : 1
      }
      leer(i + 1, k)
      i = k + 1
    } else if (c === "'") {
      let k = i + 1
      while (k < text.length && text[k] !== "'" && text[k] !== '\n') k += text[k] === '\\' ? 2 : 1
      leer(i + 1, k)
      i = k + 1
    } else i++
  }
  return o.join('')
}

// Teilt eine Liste an den Kommas der obersten Ebene (nicht in (), [], {} oder <>).
export function teileOben(s: string): string[] {
  const teile: string[] = []
  let tiefe = 0
  let start = 0
  for (let k = 0; k < s.length; k++) {
    const c = s[k]
    if ('([{<'.includes(c)) tiefe++
    else if (')]}>'.includes(c)) tiefe--
    else if (c === ',' && tiefe === 0) {
      teile.push(s.slice(start, k))
      start = k + 1
    }
  }
  teile.push(s.slice(start))
  return teile
}

// Ausdruck ab einer Stelle bis zum Ende auf derselben Ebene (; , ) } ] auf Tiefe 0).
export function ausdruckAb(code: string, von: number): string {
  let tiefe = 0
  for (let k = von; k < code.length; k++) {
    const c = code[k]
    if (c === '(' || c === '[' || c === '{') tiefe++
    else if (c === ')' || c === ']' || c === '}') {
      if (tiefe === 0) return code.slice(von, k)
      tiefe--
    } else if ((c === ';' || c === ',') && tiefe === 0) return code.slice(von, k)
  }
  return code.slice(von)
}

export const zeileVon = (text: string, at: number): number => text.slice(0, at).split('\n').length

// ---- C#: Programmstart mit Text von aussen (27.11.2026, Crashtest Lücke L2). Rot, wenn Programm oder Argumente zusammengesetzt
// sind (+, $"...", string.Format/Concat/Join) oder ein Text-Parameter der Methode direkt hineingeht; fester Text bleibt ein Hinweis.
// Erfasst Process.Start(...), new ProcessStartInfo(...), dessen Initialisierer { FileName = ..., Arguments = ... } und Zuweisungen
// an FileName/Arguments einer ProcessStartInfo-Variable oder von .StartInfo. ArgumentList.Add(...) ist der sichere Weg und bleibt still.
const PS_AUFRUF = /\bProcess\s*\.\s*Start\s*\(|\bnew\s+(?:System\s*\.\s*Diagnostics\s*\.\s*)?ProcessStartInfo\s*(?=[({])/g
const ZUSAMMENGESETZT = /\+|\$\s*@?"|@\$"|\b[Ss]tring\s*\.\s*(?:Format|Concat|Join)\s*\(/
const CS_KEIN_NAME = new Set(['if', 'for', 'foreach', 'while', 'switch', 'catch', 'using', 'lock', 'return', 'new', 'fixed', 'when', 'nameof', 'typeof', 'sizeof', 'default', 'checked', 'unchecked', 'else', 'await', 'throw', 'yield', 'in', 'is', 'as'])
const CS_METHODE = /([\w<>[\],.?]+)\s+(\w+)\s*(?:<[^<>()]*>)?\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?:where\b[^{;]*)?(?:\{|=>)/g
const CS_PARAM = /^\s*(?:\[[^\]]*\]\s*)*(?:(?:this|ref|in|out|params|scoped)\s+)*([\w<>[\],.?]+)\s+(\w+)\s*(?:=[\s\S]*)?$/
const CS_TEXT_TYP = /^(?:string|String|System\.String)\??$/

function csTextParameter(code: string): { start: number; namen: Set<string> }[] {
  const out: { start: number; namen: Set<string> }[] = []
  for (const m of code.matchAll(CS_METHODE)) {
    if (CS_KEIN_NAME.has(m[2] ?? '') || CS_KEIN_NAME.has(m[1] ?? '')) continue
    const namen = new Set<string>()
    for (const teil of teileOben(m[3] ?? '')) {
      const p = CS_PARAM.exec(teil)
      if (p && CS_TEXT_TYP.test(p[1] ?? '')) namen.add(p[2] ?? '')
    }
    out.push({ start: m.index ?? 0, namen })
  }
  return out
}

function prozessRot(text: string): { funde: SFund[]; aufrufe: Set<number> } {
  const code = csBereinigt(text)
  const roh = text.split(/\r?\n/)
  const methoden = csTextParameter(code)
  const parameterBei = (at: number): Set<string> => {
    let n = new Set<string>()
    for (const m of methoden) {
      if (m.start >= at) break
      n = m.namen
    }
    return n
  }
  const funde: SFund[] = []
  const zeilenMitFund = new Set<number>()
  // Ein Ausdruck, der ins Programm oder die Argumente geht: zusammengesetzt oder ein Text-Parameter der Methode.
  const grund = (ausdruck: string, at: number): string | undefined => {
    const a = ausdruck.trim()
    if (a === '') return undefined
    if (ZUSAMMENGESETZT.test(a)) return 'zusammen'
    if (/^@?\w+$/.test(a) && parameterBei(at).has(a.replace(/^@/, ''))) return a.replace(/^@/, '')
    return undefined
  }
  const melden = (at: number, g: string) => {
    const nr = zeileVon(code, at)
    if (zeilenMitFund.has(nr) || OK_SICHER.test(roh[nr - 1] ?? '')) return
    zeilenMitFund.add(nr)
    funde.push({ line: nr, col: at - code.lastIndexOf('\n', at - 1), code: 'PROCESS-START', schwer: true, scanner: t('Muster', 'pattern'),
      text: g === 'zusammen'
        ? t('startet ein Programm mit zusammengesetztem Text als Programm oder Argumente - Text von aussen wird so zum Befehl. Programmpfad fest, jedes Argument einzeln über ProcessStartInfo.ArgumentList.Add.',
          'starts a program with concatenated text as program or arguments - outside text becomes a command. Fixed program path, each argument on its own via ProcessStartInfo.ArgumentList.Add.')
        : t(`startet ein Programm mit dem Parameter «${g}» als Programm oder Argumente - Text des Aufrufers wird so zum Befehl. Programmpfad fest, Argumente einzeln über ProcessStartInfo.ArgumentList.Add und vorher prüfen.`,
          `starts a program with the parameter «${g}» as program or arguments - the caller's text becomes a command. Fixed program path, arguments one by one via ProcessStartInfo.ArgumentList.Add, checked first.`) })
  }
  const initialisierer = (von: number) => {
    // { FileName = ..., Arguments = ... } direkt nach new ProcessStartInfo(...)
    let k = von
    while (k < code.length && /\s/.test(code[k] ?? '')) k++
    if (code[k] !== '{') return
    let tiefe = 0
    let ende = k
    for (; ende < code.length; ende++) {
      if (code[ende] === '{') tiefe++
      else if (code[ende] === '}' && --tiefe === 0) break
    }
    const rumpf = code.slice(k + 1, ende)
    for (const m of rumpf.matchAll(/\b(?:FileName|Arguments)\s*=(?!=)/g)) {
      const at = k + 1 + (m.index ?? 0) + m[0].length
      const g = grund(ausdruckAb(code, at), at)
      if (g) melden(k + 1 + (m.index ?? 0), g)
    }
  }
  // Anfangszeilen roter Aufrufe: dort steht kein zusätzlicher Hinweis (der Fehler kann weiter unten im Initialisierer stehen).
  const aufrufe = new Set<number>()
  for (const m of code.matchAll(PS_AUFRUF)) {
    const at = m.index ?? 0
    const vorher = funde.length
    pruefeAufruf(m, at)
    if (funde.length > vorher) aufrufe.add(zeileVon(code, at))
  }
  function pruefeAufruf(m: RegExpMatchArray, at: number) {
    let offen = at + m[0].length
    if (code[offen - 1] === '(') offen--
    else while (offen < code.length && /\s/.test(code[offen] ?? '')) offen++
    if (code[offen] === '{') {
      // new ProcessStartInfo { ... } ohne Klammern
      initialisierer(offen)
      return
    }
    if (code[offen] !== '(') return
    const args = cArgumente(code, offen)
    for (const a of args) {
      // Process.Start(new ProcessStartInfo(...) { ... }): das prüft der eigene Treffer von new ProcessStartInfo - sonst stünde derselbe
      // Aufruf zweimal da (gemessen 27.11.2026 in zwei Programmen).
      if (/^\s*new\s+(?:System\s*\.\s*Diagnostics\s*\.\s*)?ProcessStartInfo\b/.test(a)) continue
      const g = grund(a, at)
      if (g) {
        melden(at, g)
        break
      }
    }
    if (/ProcessStartInfo/.test(m[0])) {
      let tiefe = 0
      let k = offen
      for (; k < code.length; k++) {
        if (code[k] === '(') tiefe++
        else if (code[k] === ')' && --tiefe === 0) break
      }
      initialisierer(k + 1)
    }
  }
  // FileName/Arguments einer ProcessStartInfo-Variable oder von .StartInfo
  const psi = new Set<string>()
  for (const m of code.matchAll(/\b(?:var|(?:System\s*\.\s*Diagnostics\s*\.\s*)?ProcessStartInfo)\s+(\w+)\s*=\s*new\s+(?:System\s*\.\s*Diagnostics\s*\.\s*)?ProcessStartInfo\b|\bProcessStartInfo\s+(\w+)\s*[;,)=]/g)) psi.add(m[1] ?? m[2] ?? '')
  for (const m of code.matchAll(/\b(\w+)\s*\.\s*(?:(StartInfo)\s*\.\s*)?(?:FileName|Arguments)\s*=(?!=)/g)) {
    if (!m[2] && !psi.has(m[1] ?? '')) continue
    const at = (m.index ?? 0) + m[0].length
    const g = grund(ausdruckAb(code, at), at)
    if (g) melden(m.index ?? 0, g)
  }
  return { funde, aufrufe }
}

export function musterBefunde(text: string, file = ''): SFund[] {
  const zeilen = text.split(/\r?\n/)
  // Prüfprojekte starten absichtlich Programme mit zusammengesetztem Text (gemessen 27.11.2026 in mehreren
  // Prüfprojekten): dort bleibt es beim Hinweis, wie bei den eingebauten Schlüsseln.
  const p = PRUEF_PFAD.test(file) ? { funde: [], aufrufe: new Set<number>() } : prozessRot(text)
  const funde: SFund[] = p.funde
  const rot = new Set([...funde.map(f => f.line), ...p.aufrufe])
  // Programmstart nur im Code, nicht in einem Text oder Kommentar
  const codeZeilen = csBereinigt(text).split(/\r?\n/)
  const harmony = /\bHarmonyLib\b|\[\s*HarmonyPatch\b/.test(text)
  // Art des letzten Patch-Attributs ([HarmonyPrefix] ...), bis die Methode darunter kommt.
  let attr = ''
  for (let i = 0; i < zeilen.length; i++) {
    const roh = zeilen[i]
    if (OK_SICHER.test(roh)) continue
    const z = roh.replace(/\/\/.*$/, '')
    const nr = i + 1
    if (/\.\s*UnpatchAll\s*\(\s*\)/.test(z)) {
      funde.push({ line: nr, col: z.indexOf('UnpatchAll') + 1, code: 'HARMONY-UNPATCH', schwer: true, scanner: t('Muster', 'pattern'),
        text: t('UnpatchAll() ohne Kennung entfernt die Patches ALLER Mods (laut Harmony auch die anderer); UnpatchAll("deine.kennung") verwenden',
          'UnpatchAll() without an id removes the patches of ALL mods (per Harmony including others\'); use UnpatchAll("your.id")') })
    }
    const id = /\bnew\s+Harmony\s*\(\s*"([^"]*)"\s*\)/.exec(z)
    if (id && !id[1].includes('.')) {
      funde.push({ line: nr, col: z.indexOf('new') + 1, code: 'HARMONY-ID', schwer: false, scanner: t('Muster', 'pattern'),
        text: t('Harmony-Kennung soll laut Harmony eindeutig und in umgekehrter Domain-Schreibweise sein (z. B. "com.name.mod")',
          'per Harmony the id should be unique and in reverse domain notation (e.g. "com.name.mod")') })
    }
    if (harmony) {
      const a = PATCH_ATTR.exec(z)
      if (a) attr = a[1]
      const m = METHODE.exec(z.replace(PATCH_ATTR, ''))
      if (m) {
        // Patch-Methode: heisst Prefix/Postfix/Transpiler/Finalizer oder steht unter einem Patch-Attribut.
        const art = PATCH_NAME.test(m[2]) ? m[2] : attr
        if (art !== '' && !/\bstatic\b/.test(m[1])) {
          funde.push({ line: nr, col: 1, code: 'HARMONY-STATISCH', schwer: true, scanner: t('Muster', 'pattern'),
            text: t(`Patch-Methode «${m[2]}» ist nicht static - laut Harmony müssen Patch-Methoden static sein`,
              `patch method «${m[2]}» is not static - per Harmony patch methods must be static`) })
        }
        // Kein Hinweis auf "Prefix mit bool": gemessen 20.11.2026 an 68 echten Dateien waren alle 38 Fundstellen gewollt.
        attr = ''
      }
    }
    if (!rot.has(nr) && /\bProcess\s*\.\s*Start\s*\(|\bnew\s+ProcessStartInfo\b/.test(codeZeilen[i] ?? '')) {
      funde.push({ line: nr, col: 1, code: 'PROCESS-START', schwer: false, scanner: t('Muster', 'pattern'),
        text: t('startet ein anderes Programm: nur mit festem Programmpfad, nie mit Text aus Eingaben, Dateien oder dem Netz',
          'starts another program: only with a fixed program path, never with text from input, files or the network') })
    }
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}

// ---- C/C++: Pufferüberlauf-Funktionen und Formatstrings, die kein fester Text sind (24.11.2026, nach einem Sicherheits-Crashtest).
// Gemessen am 24.11.2026 (DevSkim 1.0.90, Cppcheck 2.22.0): Cppcheck meldet strcpy/sprintf/printf(s) gar nicht; DevSkim meldet strcpy und
// strcat als "Important", aber JEDES printf und fprintf (auch printf("%s", s)) unter derselben Regel DS154189 "Moderate" - eine
// Hochstufung dieser Regel machte jedes printf rot. Darum eigene, genaue Muster. Bewusste Stellen: "code-waechter:ok SICHERHEIT" in der Zeile.
const C_UEBERLAUF = /\b(gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|_mbscpy|_mbscat|_tcscpy|_tcscat|lstrcpy[AW]?|lstrcat[AW]?|StrCpy[AW]?|StrCat[AW]?)\s*\(/g
// Funktion -> Stelle des Formatarguments (0-basiert).
const C_FORMAT: Record<string, number> = { printf: 0, vprintf: 0, wprintf: 0, vwprintf: 0, fprintf: 1, vfprintf: 1, fwprintf: 1, vfwprintf: 1, dprintf: 1, syslog: 1, snprintf: 2, vsnprintf: 2, _snprintf: 2, swprintf: 2 }
const C_FORMAT_RE = new RegExp(`\\b(${Object.keys(C_FORMAT).join('|')})\\s*\\(`, 'g')

// Kommentare und den Inhalt von Zeichenketten und Zeichen durch Leerzeichen ersetzen (Anführungszeichen bleiben, Zeilen und Längen
// auch): so zählt "strcpy(" in einem Text oder Kommentar nicht, und ein festes Formatargument beginnt weiterhin mit ".
function cBereinigt(text: string): string {
  const o = text.split('')
  let i = 0
  const leer = (a: number, b: number) => {
    for (let k = a; k < b && k < o.length; k++) if (o[k] !== '\n' && o[k] !== '\r') o[k] = ' '
  }
  while (i < text.length) {
    const c = text[i]
    const d = text[i + 1]
    if (c === '/' && d === '/') {
      const e = text.indexOf('\n', i)
      const s = e === -1 ? text.length : e
      leer(i, s)
      i = s
    } else if (c === '/' && d === '*') {
      const e = text.indexOf('*/', i + 2)
      const s = e === -1 ? text.length : e + 2
      leer(i, s)
      i = s
    } else if (c === '"' || c === "'") {
      let k = i + 1
      while (k < text.length && text[k] !== c && text[k] !== '\n') k += text[k] === '\\' ? 2 : 1
      leer(i + 1, k)
      i = k + 1
    } else i++
  }
  return o.join('')
}

export function cArgumente(code: string, offen: number): string[] {
  const teile: string[] = []
  let tiefe = 0
  let start = offen + 1
  for (let k = offen; k < code.length; k++) {
    const c = code[k]
    if (c === '(' || c === '[' || c === '{') tiefe++
    else if (c === ')' || c === ']' || c === '}') {
      tiefe--
      if (tiefe === 0) {
        teile.push(code.slice(start, k))
        return teile
      }
    } else if (c === ',' && tiefe === 1) {
      teile.push(code.slice(start, k))
      start = k + 1
    } else if (c === ';' && tiefe <= 1) break
  }
  return []
}

export function cMuster(text: string): SFund[] {
  const code = cBereinigt(text)
  const roh = text.split(/\r?\n/)
  const markiert = (nr: number) => OK_SICHER.test(roh[nr - 1] ?? '')
  const funde: SFund[] = []
  for (const m of code.matchAll(C_UEBERLAUF)) {
    const at = m.index ?? 0
    if (at > 0 && /[\w.>:]/.test(code[at - 1] ?? '')) continue // Methode eines Objekts oder Teil eines Namens
    const nr = zeileVon(code, at)
    if (markiert(nr)) continue
    funde.push({ line: nr, col: at - code.lastIndexOf('\n', at - 1), code: 'C-UEBERLAUF', schwer: true, scanner: t('Muster', 'pattern'),
      text: t(`${m[1]}() prüft die Grösse des Ziels nicht - ein zu langer Text überschreibt Speicher. Die Fassung mit Grösse verwenden (snprintf, strcpy_s/strncpy_s mit Ziellänge, fgets statt gets).`,
        `${m[1]}() does not check the size of the target - a text that is too long overwrites memory. Use the sized version (snprintf, strcpy_s/strncpy_s with target length, fgets instead of gets).`) })
  }
  for (const m of code.matchAll(C_FORMAT_RE)) {
    const at = m.index ?? 0
    if (at > 0 && /[\w.>:]/.test(code[at - 1] ?? '')) continue
    const args = cArgumente(code, at + m[0].length - 1)
    const fmt = (args[C_FORMAT[m[1] ?? ''] ?? 0] ?? '').trim()
    if (fmt === '' || /^(?:L|u8|u|U)?"/.test(fmt) || /^(?:_T|TEXT|__T)\s*\(\s*"/.test(fmt)) continue
    const nr = zeileVon(code, at)
    if (markiert(nr)) continue
    funde.push({ line: nr, col: at - code.lastIndexOf('\n', at - 1), code: 'C-FORMAT', schwer: true, scanner: t('Muster', 'pattern'),
      text: t(`${m[1]}() bekommt als Format keinen festen Text - enthält er %n oder %s, liest oder schreibt das Programm fremden Speicher. Festes Format verwenden, z. B. ${m[1] === 'printf' ? 'printf("%s", text)' : 'ein "%s" als Format'}.`,
        `${m[1]}() gets no fixed text as format - if it contains %n or %s, the program reads or writes foreign memory. Use a fixed format, e.g. ${m[1] === 'printf' ? 'printf("%s", text)' : 'a "%s" format'}.`) })
  }
  return funde
}

// ---- Eingebaute Schlüssel in Code (C#, C/C++, Python): ein Name wie api_key, secret, token, password mit einem langen, zufällig
// aussehenden Text. Gitleaks' Regel generic-api-key bleibt aus: gemessen am 24.11.2026 traf sie in mehreren Programmen 5-mal, alles
// Übersetzungsschlüssel und eine Tastenabfrage (und in einem Spiel-Mod-Projekt 5247-mal). Diese Regel traf in 1492 C#-, C- und
// Python-Dateien 5-mal, alle in Prüfprojekten (darum ausgenommen, siehe PRUEF_PFAD); ausserhalb 0-mal.
const GEHEIM_NAME = /\b[\w.]*?(?:api[_-]?key|apikey|secret|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|client[_-]?secret|passwor[dt]|passwd|kennwort)\w*["']?\s*[:=]\s*@?\$?["']([^"'\s]{16,})["']/gi
export const PLATZHALTER = /dein|your|xxx|placeholder|example|beispiel|changeme|<|\.\.\.|\$\{|\{\{|%s|TODO/i
// Prüf- und Testprojekte haben absichtlich feste Probe-Kennwörter (24.11.2026 gemessen: alle 5 Treffer lagen in Prüfprojekten).
export const PRUEF_PFAD = /\.test\.|[\\/](?:[^\\/]*[._-])?(?:(?:Unit|Integration)?Tests?|Probe|Pruefung)[\\/]/i

export function geheimMuster(text: string, file = ''): SFund[] {
  const funde: SFund[] = []
  if (PRUEF_PFAD.test(file)) return funde
  const zeilen = text.split(/\r?\n/)
  zeilen.forEach((z, i) => {
    if (OK_SICHER.test(z) || /gitleaks:allow/.test(z)) return
    for (const m of z.matchAll(GEHEIM_NAME)) {
      const wert = m[1] ?? ''
      // Ein Schlüssel enthält nie einen Backslash; Übersetzungstexte mit С... schon (gemessen 27.11.2026: 16 Fehlalarme in
      // Login_Password-Texten fremder JavaScript-Dateien).
      if (PLATZHALTER.test(wert) || !/[A-Za-z]/.test(wert) || !/\d/.test(wert) || new Set(wert).size < 10 || wert.includes('\\')) continue
      funde.push({ line: i + 1, col: (m.index ?? 0) + 1, code: 'GEHEIMNIS', schwer: true, scanner: t('Muster', 'pattern'), geheim: true,
        text: t('Schlüssel oder Passwort steht im Quelltext (Wert verborgen) - aus einer geschützten Ablage oder Umgebungsvariable lesen, nie einbauen.',
          'key or password is in the source code (value hidden) - read it from protected storage or an environment variable, never embed it.') })
      return
    }
  })
  return funde
}

// ---- JavaScript/TypeScript: Dateipfad und SQL-Text aus der Anfrage (27.11.2026, Crashtest Lücken L3 und L4).
// Quelle ist req.query, req.params oder req.body - direkt oder über eine Variable, die im selben Block daraus gefüllt wurde.
// Unschädlich gemacht: path.basename(...), Number/parseInt/parseFloat, die Wahl aus einer festen Liste (LISTE[req.query.x]) und eine
// Prüfung LISTE.includes(x) / .has(x) / .indexOf(x) vor der Stelle; für SQL zusätzlich escape(...). Prüfdateien (*.test.*, Tests\)
// enthalten absichtlich solche Beispiele und zählen nicht.

type JsText = { bare: string; texte: { start: number; ende: number; teile: [number, number][] }[] }

// Kommentare und der Inhalt von Zeichenketten und Suchmustern werden Leerzeichen; in `...${x}...` bleibt der Ausdruck x als Code stehen.
export function jsBereinigt(text: string): JsText {
  const o = text.split('')
  const texte: JsText['texte'] = []
  const leer = (a: number, b: number) => {
    for (let k = a; k < b && k < o.length; k++) if (o[k] !== '\n' && o[k] !== '\r') o[k] = ' '
  }
  const VOR_SUCHMUSTER = /(?:^|[(,=:[!&|?{};+\-*%<>~^])\s*$|\b(?:return|typeof|case|in|of|new|delete|void|throw|await|yield)\s*$/
  // Läuft über Code bis zum Ende oder (bisKlammer) bis zur schliessenden } der Ebene; gibt die Stelle danach zurück.
  const code = (von: number, bisKlammer: boolean): number => {
    let i = von
    let tiefe = 0
    while (i < text.length) {
      const c = text[i]
      const d = text[i + 1]
      if (c === '/' && d === '/') {
        const e = text.indexOf('\n', i)
        const s = e === -1 ? text.length : e
        leer(i, s)
        i = s
      } else if (c === '/' && d === '*') {
        const e = text.indexOf('*/', i + 2)
        const s = e === -1 ? text.length : e + 2
        leer(i, s)
        i = s
      } else if (c === '/' && VOR_SUCHMUSTER.test(o.slice(Math.max(0, i - 12), i).join(''))) {
        let k = i + 1
        let klasse = false
        while (k < text.length && text[k] !== '\n' && (klasse || text[k] !== '/')) {
          if (text[k] === '\\') k++
          else if (text[k] === '[') klasse = true
          else if (text[k] === ']') klasse = false
          k++
        }
        leer(i + 1, k)
        i = k + 1
      } else if (c === '"' || c === "'") {
        let k = i + 1
        while (k < text.length && text[k] !== c && text[k] !== '\n') k += text[k] === '\\' ? 2 : 1
        texte.push({ start: i, ende: k + 1, teile: [] })
        leer(i + 1, k)
        i = k + 1
      } else if (c === '`') {
        const eintrag: JsText['texte'][number] = { start: i, ende: i, teile: [] }
        let k = i + 1
        let stueck = k
        while (k < text.length && text[k] !== '`') {
          if (text[k] === '\\') k += 2
          else if (text[k] === '$' && text[k + 1] === '{') {
            leer(stueck, k)
            const nach = code(k + 2, true)
            eintrag.teile.push([k + 2, nach - 1])
            k = nach
            stueck = k
          } else k++
        }
        leer(stueck, k)
        eintrag.ende = k + 1
        texte.push(eintrag)
        i = k + 1
      } else if (bisKlammer && c === '{') {
        tiefe++
        i++
      } else if (bisKlammer && c === '}') {
        if (tiefe === 0) return i + 1
        tiefe--
        i++
      } else i++
    }
    return i
  }
  code(0, false)
  return { bare: o.join(''), texte }
}

export const JS = /\.(?:js|mjs|cjs|jsx|ts|tsx|mts|cts)$/i
const JS_QUELLE = /\breq(?:uest)?\s*\.\s*(?:query|params|body)\b/
const JS_UNSCHAEDLICH = /\b(?:basename|Number|parseInt|parseFloat|Boolean)\s*\(/
const JS_SQL = /\bSELECT\b[\s\S]*\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b[\s\S]*\bSET\b|\bDELETE\s+FROM\b/i
const JS_FS_AUFRUF = /\b(?:fs|fsp|fse|fs\s*\.\s*promises)\s*\.\s*(readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|createWriteStream)\s*\(/g
const JS_FS_NAMEN = new Set(['readFile', 'readFileSync', 'createReadStream', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'createWriteStream'])

export function jsMuster(text: string, file = ''): SFund[] {
  if (PRUEF_PFAD.test(file)) return []
  const { bare, texte } = jsBereinigt(text)
  const roh = text.split(/\r?\n/)
  // Tiefe der geschweiften Klammern an jeder Stelle und das Ende des Blocks, in dem eine Stelle liegt.
  const tiefe = new Int32Array(bare.length + 1)
  for (let k = 0, d = 0; k < bare.length; k++) {
    if (bare[k] === '{') d++
    else if (bare[k] === '}') d = Math.max(0, d - 1)
    tiefe[k + 1] = d
  }
  const blockEnde = (at: number): number => {
    const d = tiefe[at] ?? 0
    for (let k = at; k < bare.length; k++) if ((tiefe[k + 1] ?? 0) < d) return k
    return bare.length
  }
  type Herkunft = { name: string; von: number; bis: number }
  const verdaechtig: Herkunft[] = []
  const geprueft: Herkunft[] = []
  const gilt = (l: Herkunft[], name: string, at: number) => l.some(h => h.name === name && h.von <= at && at < h.bis)
  // Wo die Stelle in eckigen Klammern hinter einem Namen steht (LISTE[...]), wird aus einer festen Liste gewählt.
  const inListe = (at: number): boolean => {
    let d = 0
    for (let k = at - 1; k >= 0; k--) {
      const c = bare[k]
      if (c === ']' || c === ')') d++
      else if (c === '(') {
        if (d === 0) return false
        d--
      } else if (c === '[') {
        if (d > 0) {
          d--
          continue
        }
        const davor = bare.slice(0, k).trimEnd()
        return /[\w$\])]$/.test(davor)
      } else if ((c === ';' || c === '\n') && d === 0) return false
    }
    return false
  }
  // Ob ein Ausdruck (Stelle at..at+länge in bare) Text aus der Anfrage trägt.
  const traegt = (ausdruck: string, at: number, sql = false): boolean => {
    if (JS_UNSCHAEDLICH.test(ausdruck) || (sql && /\bescape(?:Id)?\s*\(/.test(ausdruck))) return false
    for (const m of ausdruck.matchAll(new RegExp(JS_QUELLE.source, 'g'))) if (!inListe(at + (m.index ?? 0))) return true
    for (const m of ausdruck.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)/g)) {
      const pos = at + (m.index ?? 0)
      if (gilt(verdaechtig, m[1] ?? '', pos) && !gilt(geprueft, m[1] ?? '', pos) && !inListe(pos)) return true
    }
    return false
  }
  // Ende eines Ausdrucks ohne Semikolon: Zeilenende auf Tiefe 0, ausser die Zeile endet mit einem Operator oder die nächste beginnt mit einem.
  const rechteSeite = (von: number): string => {
    let d = 0
    for (let k = von; k < bare.length; k++) {
      const c = bare[k]
      if (c === '(' || c === '[' || c === '{') d++
      else if (c === ')' || c === ']' || c === '}') {
        if (d === 0) return bare.slice(von, k)
        d--
      } else if (c === ';' && d === 0) return bare.slice(von, k)
      else if (c === '\n' && d === 0) {
        const vorher = bare.slice(von, k).trimEnd()
        const nachher = bare.slice(k + 1).trimStart()
        if (!/[+\-*/=,(?:&|]$/.test(vorher) && !/^[.+?:&|]/.test(nachher)) return bare.slice(von, k)
      }
    }
    return bare.slice(von)
  }
  const funde: SFund[] = []
  const zeilen = new Set<string>()
  const melden = (at: number, code: string, de: string, en: string) => {
    const nr = zeileVon(bare, at)
    if (zeilen.has(`${code}|${nr}`) || OK_SICHER.test(roh[nr - 1] ?? '')) return
    zeilen.add(`${code}|${nr}`)
    funde.push({ line: nr, col: at - bare.lastIndexOf('\n', at - 1), code, schwer: true, scanner: t('Muster', 'pattern'), text: t(de, en) })
  }
  const sqlFund = (at: number) =>
    melden(at, 'SEC-SQL', 'SQL-Text wird aus der Anfrage zusammengesetzt (SQL-Einschleusung) - Werte als Parameter übergeben (? oder $1), nie in den Text einbauen.',
      'SQL text is built from the request (SQL injection) - pass values as parameters (? or $1), never put them into the text.')
  // Zuweisungen der Reihe nach: const/let/var x = ..., Zerlegung { a, b: c } = ..., x = ...
  const ZUWEISUNG = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])|\b(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=;\n]+)?=(?![=>])|(?<![\w$.])([A-Za-z_$][\w$]*)\s*(\+)?=(?![=>])/g
  const sqlVariablen: Herkunft[] = []
  for (const m of bare.matchAll(ZUWEISUNG)) {
    const at = m.index ?? 0
    const rechts = at + m[0].length
    const ausdruck = rechteSeite(rechts)
    const namen = m[1] ? [m[1]] : m[2] ? teileOben(m[2]).map(n => n.trim().replace(/^\.\.\./, '').split('=')[0].split(':').pop()?.trim() ?? '').filter(Boolean) : [m[3] ?? '']
    const bis = blockEnde(at)
    if (traegt(ausdruck, rechts)) for (const name of namen) verdaechtig.push({ name, von: rechts + ausdruck.length, bis })
    // Variablen, die SQL-Text halten, und Anhängen daran (sql += req.query.x)
    const txt = texte.filter(s => s.start >= rechts && s.ende <= rechts + ausdruck.length).map(s => text.slice(s.start, s.ende)).join(' ')
    if (m[1] && JS_SQL.test(txt)) sqlVariablen.push({ name: m[1], von: rechts, bis })
    if (m[4] && m[3] && gilt(sqlVariablen, m[3], at) && traegt(ausdruck, rechts, true)) sqlFund(at)
  }
  // Prüfung gegen eine feste Liste: ab dort gilt die Variable im Block als geprüft.
  for (const m of bare.matchAll(/\.\s*(?:includes|has|indexOf)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    const at = m.index ?? 0
    geprueft.push({ name: m[1] ?? '', von: at, bis: blockEnde(at) })
  }
  // L3: Dateizugriff mit einem Pfad aus der Anfrage
  const fsNamen = new Set<string>()
  for (const m of text.matchAll(/\bimport\s*\{([^}]*)\}\s*from\s*['"](?:node:)?fs(?:\/promises)?['"]|\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/g)) {
    for (const teil of (m[1] ?? m[2] ?? '').split(',')) {
      const [orig, als] = teil.split(/\s+as\s+|\s*:\s*/).map(x => x.trim())
      if (JS_FS_NAMEN.has(orig ?? '')) fsNamen.add(als || orig || '')
    }
  }
  const aufrufe: { at: number; offen: number }[] = [...bare.matchAll(JS_FS_AUFRUF)].map(m => ({ at: m.index ?? 0, offen: (m.index ?? 0) + m[0].length - 1 }))
  for (const name of fsNamen) {
    for (const m of bare.matchAll(new RegExp(String.raw`(?<![\w$.])${name.replace(/\$/g, '\\$')}\s*\(`, 'g'))) aufrufe.push({ at: m.index ?? 0, offen: (m.index ?? 0) + m[0].length - 1 })
  }
  for (const a of aufrufe) {
    const pfad = cArgumente(bare, a.offen)[0] ?? ''
    if (traegt(pfad, a.offen + 1)) {
      melden(a.at, 'SEC-PFAD', 'Dateipfad kommt aus der Anfrage (req.query/params/body) - so liest, schreibt oder löscht jemand beliebige Dateien (../). Nur den Dateinamen nehmen (path.basename) oder aus einer festen Liste wählen.',
        'file path comes from the request (req.query/params/body) - anyone can read, write or delete any file (../). Take only the file name (path.basename) or pick from a fixed list.')
    }
  }
  // L4: SQL-Text mit + oder ${} aus der Anfrage zusammengesetzt
  for (const s of texte) {
    const inhalt = text.slice(s.start, s.ende)
    if (!JS_SQL.test(inhalt)) continue
    if (s.teile.some(([a, b]) => traegt(bare.slice(a, b), a, true))) {
      sqlFund(s.start)
      continue
    }
    // Kette 'SELECT ... ' + x + ' AND ...' + y: jedes Glied nach einem + und vor dem Text
    let k = s.ende
    let gefunden = false
    for (;;) {
      const plus = /^\s*\+\s*/.exec(bare.slice(k, k + 200))
      if (!plus) break
      k += plus[0].length
      const glied = /^[^+,;)\]}\n]*/.exec(bare.slice(k))?.[0] ?? ''
      if (traegt(glied, k, true)) {
        gefunden = true
        break
      }
      k += glied.length
    }
    const vorher = /([^+,;(=\n]*)\+\s*$/.exec(bare.slice(Math.max(0, s.start - 200), s.start))
    if (gefunden || (vorher && traegt(vorher[1] ?? '', s.start - (vorher[0]?.length ?? 0), true))) sqlFund(s.start)
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}

// ---- Python: Dateipfad direkt aus einer Eingabe (27.11.2026, Crashtest Lücke L6). Gemeldet, wenn open(), Path(...).open/
// read_text/write_text/read_bytes/write_bytes, os.remove/os.unlink einen Pfad bekommen, der in derselben Funktion aus input(), sys.argv
// oder request.args/form/json/files kommt - direkt oder über eine Variable: aus einer Web-Anfrage rot, sonst ein Hinweis (PY_WEB).
// Nicht bei os.path.basename (oder int/float). Variable Pfade ohne diese Herkunft bleiben ungemeldet: gemessen 24.11.2026 öffnen 1102 Stellen in 153 Python-Dateien eines Entwicklers Dateien
// über eine Variable. Prüfdateien zählen nicht.

// Kommentare und der Inhalt von Zeichenketten werden Leerzeichen; in f-Strings bleibt der Ausdruck in {…} als Code stehen.
export function pyBereinigt(text: string): string {
  const o = text.split('')
  const leer = (a: number, b: number) => {
    for (let k = a; k < b && k < o.length; k++) if (o[k] !== '\n' && o[k] !== '\r') o[k] = ' '
  }
  let i = 0
  while (i < text.length) {
    const c = text[i]
    if (c === '#') {
      const e = text.indexOf('\n', i)
      const s = e === -1 ? text.length : e
      leer(i, s)
      i = s
    } else if (c === '"' || c === "'") {
      const vor = /([rRbBuUfF]{0,2})$/.exec(text.slice(Math.max(0, i - 2), i))?.[1] ?? ''
      const istName = /[\w]/.test(text[i - vor.length - 1] ?? '')
      const f = !istName && /[fF]/.test(vor)
      const roh = !istName && /[rR]/.test(vor)
      const drei = text.startsWith(c.repeat(3), i)
      const zu = drei ? c.repeat(3) : c
      let k = i + zu.length
      let stueck = k
      while (k < text.length && !text.startsWith(zu, k) && (drei || text[k] !== '\n')) {
        if (text[k] === '\\' && !roh) k += 2
        else if (f && text[k] === '{' && text[k + 1] === '{') k += 2
        else if (f && text[k] === '{') {
          leer(stueck, k)
          let d = 0
          let j = k
          for (; j < text.length; j++) {
            if (text[j] === '{') d++
            else if (text[j] === '}' && --d === 0) break
          }
          k = j + 1
          stueck = k
        } else k++
      }
      leer(stueck, k)
      i = k + zu.length
    } else i++
  }
  return o.join('')
}

// Web-Anfrage (fremde Leute schicken den Text): Fehler. Befehlszeile und input() (wer das Werkzeug startet, tippt den Pfad selbst):
// Hinweis - 27.11.2026 nach einer Messung über mehrere Projekte (44 Funde, alle in Werkzeugen, die ihre Ordner gewollt über
// die Befehlszeile bekommen).
const PY_WEB = /\brequest\s*\.\s*(?:args|form|json|files|values|get_json)\b/
const PY_LOKAL = /\binput\s*\(|\bsys\s*\.\s*argv\b/
type PyHerkunft = 'web' | 'lokal'
const PY_UNSCHAEDLICH = /\bbasename\s*\(|\b(?:int|float)\s*\(/
const PY_AUFRUF = /(?<![\w.])open\s*\(|\b(?:io|codecs)\s*\.\s*open\s*\(|\bos\s*\.\s*(?:remove|unlink)\s*\(|\b(?:pathlib\s*\.\s*)?Path\s*\(/g
const PY_PFAD_METHODE = /^\s*\)?\s*\.\s*(?:open|read_text|write_text|read_bytes|write_bytes|unlink)\s*\(/

export function pyPfadMuster(text: string, file = ''): SFund[] {
  if (PRUEF_PFAD.test(file)) return []
  const bare = pyBereinigt(text)
  const roh = text.split(/\r?\n/)
  const argvAllein = /^\s*from\s+sys\s+import\s+[^\n]*\bargv\b/m.test(bare)
  const quelle = (s: string): PyHerkunft | undefined =>
    PY_WEB.test(s) ? 'web' : PY_LOKAL.test(s) || (argvAllein && /(?<![\w.])argv\b/.test(s)) ? 'lokal' : undefined
  // Logische Zeilen: eine Anweisung über mehrere Zeilen (offene Klammer, \ am Ende) gehört zusammen.
  const logisch: { start: number; text: string }[] = []
  let start = 0
  let d = 0
  for (let k = 0; k <= bare.length; k++) {
    const c = bare[k]
    if (c === '(' || c === '[' || c === '{') d++
    else if (c === ')' || c === ']' || c === '}') d = Math.max(0, d - 1)
    if (k === bare.length || (c === '\n' && d === 0 && bare[k - 1] !== '\\' && !(bare[k - 1] === '\r' && bare[k - 2] === '\\'))) {
      logisch.push({ start, text: bare.slice(start, k) })
      start = k + 1
    }
  }
  const funde: SFund[] = []
  // Bereiche: Modul und jede Funktion (nach Einrückung). Verdächtig ist eine Variable nur in ihrem Bereich.
  const stapel: { einzug: number; namen: Map<string, PyHerkunft> }[] = [{ einzug: -1, namen: new Map() }]
  // Woher ein Ausdruck seinen Text hat: aus einer Web-Anfrage geht vor der Befehlszeile.
  const traegt = (s: string): PyHerkunft | undefined => {
    if (PY_UNSCHAEDLICH.test(s)) return undefined
    let h = quelle(s)
    if (h === 'web') return h
    const namen = stapel[stapel.length - 1]?.namen ?? new Map<string, PyHerkunft>()
    for (const m of s.matchAll(/(?<![\w.])([A-Za-z_]\w*)\b/g)) {
      const n = namen.get(m[1] ?? '')
      if (n === 'web') return n
      h = h ?? n
    }
    return h
  }
  const melden = (at: number, h: PyHerkunft) => {
    const nr = zeileVon(bare, at)
    if (OK_SICHER.test(roh[nr - 1] ?? '') || funde.some(f => f.line === nr)) return
    funde.push({ line: nr, col: at - bare.lastIndexOf('\n', at - 1), code: 'PY-PFAD', schwer: h === 'web', scanner: t('Muster', 'pattern'),
      text: h === 'web'
        ? t('Dateipfad kommt aus einer Web-Anfrage (request.args/form/json/files) - so wird jede Datei lesbar oder löschbar (../). Nur den Dateinamen nehmen (os.path.basename) und gegen einen festen Ordner prüfen.',
          'file path comes from a web request (request.args/form/json/files) - any file becomes readable or deletable (../). Take only the file name (os.path.basename) and check it against a fixed folder.')
        : t('Dateipfad kommt aus der Befehlszeile oder input() - bei einem eigenen Werkzeug gewollt; kommt der Text von anderen, nur den Dateinamen nehmen (os.path.basename) und gegen einen festen Ordner prüfen.',
          'file path comes from the command line or input() - fine for your own tool; if others supply the text, take only the file name (os.path.basename) and check it against a fixed folder.') })
  }
  for (const z of logisch) {
    if (z.text.trim() === '') continue
    const einzug = /^[ \t]*/.exec(z.text)?.[0].replace(/\t/g, '    ').length ?? 0
    while (stapel.length > 1 && einzug <= (stapel[stapel.length - 1]?.einzug ?? -1)) stapel.pop()
    if (/^\s*(?:async\s+)?def\s+\w+/.test(z.text)) {
      stapel.push({ einzug, namen: new Map() })
      continue
    }
    // Aufrufe mit einem Pfad aus der Eingabe
    for (const m of z.text.matchAll(PY_AUFRUF)) {
      const offen = (m.index ?? 0) + m[0].length - 1
      const args = cArgumente(z.text, offen)
      const pfad = args[0] ?? ''
      if (/Path\s*\($/.test(m[0])) {
        // Path(x) zählt nur mit einer Datei-Methode dahinter: Path(x).read_text(), Path(x).open()
        let tiefe = 0
        let k = offen
        for (; k < z.text.length; k++) {
          if (z.text[k] === '(') tiefe++
          else if (z.text[k] === ')' && --tiefe === 0) break
        }
        if (!PY_PFAD_METHODE.test(z.text.slice(k))) continue
      }
      const h = traegt(pfad)
      if (h) melden(z.start + (m.index ?? 0), h)
    }
    // Methode einer verdächtigen Variable: p.read_text(), p.open()
    for (const m of z.text.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\.\s*(?:open|read_text|write_text|read_bytes|write_bytes|unlink)\s*\(/g)) {
      const h = stapel[stapel.length - 1]?.namen.get(m[1] ?? '')
      if (h) melden(z.start + (m.index ?? 0), h)
    }
    // Zuweisungen: name = ..., a, b = ..., for x in ...:
    const zuw = /^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=\n]+)?=(?!=)([\s\S]*)$/.exec(z.text)
    const fuer = /^\s*(?:async\s+)?for\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+in\s+([\s\S]*):\s*$/.exec(z.text)
    const treffer = zuw ?? fuer
    if (treffer) {
      const namen = (treffer[1] ?? '').split(',').map(n => n.trim())
      const verdacht = traegt(treffer[2] ?? '')
      const bereich = stapel[stapel.length - 1]?.namen
      for (const n of namen) {
        if (verdacht) bereich?.set(n, verdacht)
        else bereich?.delete(n)
      }
    }
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}

// ---- Alle passenden Scanner für eine Datei. Die Scanner laufen gleichzeitig; ein Absturz eines Scanners ist eine Lücke, nie "OK",
// und nimmt den anderen Scannern ihre Funde nicht weg.
export async function scannen(u: Umgebung, file: string, text: string | undefined): Promise<Ergebnis> {
  const wahl = scannerFuer(file)
  const funde: SFund[] = []
  const luecken: string[] = []
  const liefen: string[] = []
  const fehlt = (name: string, befehl: string) =>
    luecken.push(t(`${name} fehlt (einmalig: ${befehl})`, `${name} missing (once: ${befehl})`))
  // Gitleaks schreibt seine Fehlermeldung mit Farbcodes (gemessen 20.11.2026): die gehören nicht in die Meldung.
  const kaputt = (name: string, grund: string) => luecken.push(t(`${name} lief nicht: ${rein(grund, 200)}`, `${name} did not run: ${rein(grund, 200)}`))
  const auftrag = (name: string, job: () => Promise<void>): Promise<void> =>
    job().catch((err: unknown) => {
      kaputt(name, String((err as { message?: string })?.message ?? err))
    })
  const zeilen = zeilenVon(text ?? '')

  const jobs: Promise<void>[] = []
  if (wahl.muster && text !== undefined) {
    funde.push(...eigeneMuster(text, file))
    liefen.push(t('Muster', 'patterns'))
  }
  if (wahl.devskim) {
    jobs.push(auftrag('DevSkim', async () => {
      const exe = await u.exe('devskim')
      if (!exe) return void fehlt('DevSkim', 'dotnet tool install --global Microsoft.CST.DevSkim.CLI')
      const r = await u.run([exe, 'analyze', '-I', file, '-f', 'text', '-o', DEVSKIM_FORMAT, '-g', NIE_AUSGELASSEN], { timeoutMs: 60000 })
      if (!r.ok) return void kaputt('DevSkim', r.reason)
      const d = devskimLesen(`${r.stdout}\n${r.stderr}`)
      if (d.fehler) return void kaputt('DevSkim', daten(d.fehler))
      if (r.exitCode !== 0 && d.funde.length === 0) return void kaputt('DevSkim', t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
      if (r.truncated) return void kaputt('DevSkim', t('Ausgabe zu gross', 'output too large'))
      funde.push(...d.funde.filter(f => !devskimImWort(f, zeilen)))
      liefen.push('DevSkim')
    }))
  }
  if (wahl.cppcheck) {
    jobs.push(auftrag('Cppcheck', async () => {
      const exe = await u.exe('cppcheck')
      if (!exe) return void fehlt('Cppcheck', 'winget install Cppcheck.Cppcheck')
      // .h wird als C++ gelesen: in C++-Projekten (Visual Studio, Unreal) sind .h die Regel, als C meldete Cppcheck dort syntaxError.
      const argv = [exe, '--enable=all', '--inconclusive', '--quiet', '--inline-suppr', `--template=${CPPCHECK_TEMPLATE}`,
        ...CPPCHECK_UNTERDRUECKT.map(s => `--suppress=${s}`), ...(/\.(?:h|hpp|hxx)$/i.test(file) ? ['--language=c++'] : []), file]
      const r = await u.run(argv, { timeoutMs: 120000 })
      if (!r.ok) return void kaputt('Cppcheck', r.reason)
      const c = cppcheckLesen(`${r.stdout}\n${r.stderr}`, file)
      if (r.exitCode !== 0 && c.funde.length === 0) return void kaputt('Cppcheck', t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
      if (r.truncated) return void kaputt('Cppcheck', t('Ausgabe zu gross', 'output too large'))
      funde.push(...c.funde)
      if (c.unvollstaendig.length > 0) kaputt('Cppcheck', t('nicht ganz ausgewertet - ', 'not fully analysed - ') + daten(c.unvollstaendig.join('; '), 240))
      else liefen.push('Cppcheck')
    }))
  }
  if (wahl.bandit) {
    jobs.push(auftrag('Bandit', async () => {
      const r = await u.run([...u.python, '-X', 'utf8', '-m', 'bandit', '-f', 'json', '-q', '-s', BANDIT_AUSGELASSEN, '-x', BANDIT_KEIN_AUSSCHLUSS, file],
        { env: { PYTHONSAFEPATH: '1' }, cwd: await u.workDir(), timeoutMs: 60000 })
      if (!r.ok) return void kaputt('Bandit', r.reason)
      // Der Befehl nennt das Python, das der Wächter benutzt (Einstellung "Python-Befehl"), nicht irgendeins.
      if (/No module named bandit/i.test(`${r.stdout}${r.stderr}`)) return void fehlt('Bandit', `${u.python.join(' ')} -m pip install bandit`)
      const b = banditLesen(r.stdout)
      if (b.fehler && b.funde.length === 0) return void kaputt('Bandit', daten(b.fehler))
      if (r.truncated) return void kaputt('Bandit', t('Ausgabe zu gross', 'output too large'))
      funde.push(...b.funde)
      if (b.uebersprungen) kaputt('Bandit', t('hat die Datei übersprungen', 'skipped the file'))
      else liefen.push('Bandit')
    }))
  }
  if (wahl.gitleaks) {
    jobs.push(auftrag('Gitleaks', async () => {
      const exe = await u.exe('gitleaks')
      if (!exe) return void fehlt('Gitleaks', 'winget install Gitleaks.Gitleaks')
      // Eine Berichtsdatei je Chat genügt: ein Chat prüft immer nur eine Datei zugleich, andere Chats haben ihre eigene.
      const arbeit = await u.workDir()
      const bericht = `${arbeit}\\gitleaks-${u.kennung.replace(/[^\w-]/g, '_').slice(0, 64) || 'chat'}.json`
      await u.write(bericht, GITLEAKS_VORHER)
      // --exit-code 0: Funde enden mit 0, jeder andere Code ist ein Fehler des Scanners. Arbeitsordner = eigener Ordner der Mod:
      // Gitleaks liest .gitleaksignore aus dem Arbeitsordner, der des Chats gehört nicht dazu.
      const r = await u.run([exe, 'dir', file, '--no-banner', '--redact', '--exit-code', '0', ...GITLEAKS_ENTSCHLUESSELN, '--report-format', 'json', '--report-path', bericht],
        { cwd: arbeit, timeoutMs: 60000 })
      if (!r.ok) return void kaputt('Gitleaks', r.reason)
      if (r.exitCode !== 0) return void kaputt('Gitleaks', t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
      const inhalt = await u.read(bericht)
      if (inhalt === undefined || inhalt.trim() === GITLEAKS_VORHER) return void kaputt('Gitleaks', t('kein Bericht geschrieben', 'no report written'))
      const g = gitleaksLesen(inhalt)
      if (g.fehler) return void kaputt('Gitleaks', g.fehler)
      funde.push(...g.funde)
      liefen.push('Gitleaks')
    }))
  }
  // C/C++-Analyse (c_analyse.ts: cl /analyze und clang-tidy) für dieselben Dateiarten wie Cppcheck.
  if (wahl.cppcheck && u.cAnalyse) {
    jobs.push(auftrag('C/C++-Analyse', async () => {
      const e = (await cAnalyse(u, [file], async () => C_ANALYSE_MS)).get(file)
      funde.push(...(e?.funde ?? []))
      luecken.push(...(e?.luecken ?? []))
      liefen.push(...(e?.liefen ?? []))
    }))
  }
  // Bekannte Lücken in Paketen (osv.ts) für Paketdateien.
  if (u.osv && OSV_DATEI.test(file)) {
    jobs.push(auftrag('OSV-Scanner', async () => {
      const e = (await osvPruefen(u, [file], new Map<string, string>(text === undefined ? [] : [[file, text]]), 60000)).get(file)
      funde.push(...(e?.funde ?? []))
      luecken.push(...(e?.luecken ?? []))
      liefen.push(...(e?.liefen ?? []))
    }))
  }
  // Datenfluss mit den eigenen Semgrep-Regeln (semgrep.ts) für Python, C# und JavaScript/TypeScript.
  if (u.semgrep && SEMGREP_DATEI.test(file)) {
    jobs.push(auftrag('Semgrep', async () => {
      const e = (await semgrepPruefen(u, [file], new Map<string, string>(text === undefined ? [] : [[file, text]]), async () => SEMGREP_MS)).get(file)
      funde.push(...(e?.funde ?? []))
      luecken.push(...(e?.luecken ?? []))
      liefen.push(...(e?.liefen ?? []))
    }))
  }
  await Promise.all(jobs)
  funde.sort((a, b) => a.line - b.line || a.col - b.col)
  return { funde, luecken, liefen: liefen.sort() }
}

// ---- Ordner-Scan (27.11.2026, Crashtest Lücke L1: /scan liess alle Sicherheits-Scanner weg). Je Scanner EIN Aufruf über alle
// Dateien, die Funde werden den Dateien zugeordnet; die eigenen Muster laufen je Datei.
// Gemessen 27.11.2026: DevSkim 1.0.90 nimmt nur einen Ordner oder eine Datei (-I), eine Dateiliste nur über --include-globs, die in
// einer Optionsdatei (--options-json) nicht gelesen werden; --include-globs unterscheidet Gross- und Kleinschreibung (x.CS fiel weg).
// Gitleaks 8.30.1 nimmt nur einen Pfad: über den ganzen Ordner eines Spiel-Mod-Projekts (55'589 Dateien, 61 GB) lief es über 10 Minuten.
// Darum ein Spiegelordner im Arbeitsordner der Mod mit genau den Dateien des Scans (<Nummer>\<Name mit kleiner Endung>), über den
// DevSkim, Bandit (-r, kennt .py und .pyw) und Gitleaks laufen; die Funde kommen über die Nummer zur echten Datei zurück. Cppcheck läuft
// auf den echten Dateien (eingebundene Kopfdateien liegen dort) über --file-list, Kopfdateien als C++ in einem eigenen Lauf. Alle vier
// schreiben in eine Datei (-O, --output-file, -o, --report-path), damit viele Funde nie abgeschnitten werden. Der Spiegel enthält den
// Text so, wie der Wächter ihn liest (UTF-8), mit denselben Zeilen; eine Datei über 4 MiB liegt dort Byte für Byte (u.kopieren).
// Fehlt ein Scanner, bricht er ab oder reicht die Zeit nicht, steht das bei jeder betroffenen Datei unter luecken - nie still.
const SPIEGEL_NR = /[\\/]spiegel-[^\\/]+[\\/](\d+)[\\/][^\\/]+$/i

// Ziel einer Kopie in den Spiegel (u.kopieren, Gegenprüfung 28.11.2026): genau <Arbeitsordner>\spiegel-<Kennung>\<Nummer>\<Name>,
// der Name ohne \ / : * ? " < > | und nicht nur aus Punkten - so führt kein Ziel aus dem Spiegel hinaus.
export function spiegelZielOk(arbeitsordner: string, ziel: string): boolean {
  const a = arbeitsordner.replace(/[\\/]+$/, '')
  if (a === '' || !ziel.toLowerCase().startsWith(`${a.toLowerCase()}\\`)) return false
  const [ordner, nr, name, ...mehr] = ziel.slice(a.length + 1).split('\\')
  return mehr.length === 0 && /^spiegel-[\w-]+$/i.test(ordner ?? '') && /^\d+$/.test(nr ?? '') && /^[^\\/:*?"<>|]+$/.test(name ?? '') && !/^\.+$/.test(name ?? '')
}

// Aufruf für u.kopieren (register.tsx): PowerShell mit festem Befehl, die Pfade nur über Umgebungswerte - ein Name mit $ [ ] `
// wird so nie ausgewertet. Liegt das Ziel nicht im Spiegel oder ist die Quelle kein voller Pfad, wird nichts gestartet.
// Echt geprüft mit einer 5-MB-Datei "gr[o]ss $x `y.json" (eigene Probe, 28.11.2026). Am Schluss sieht der Befehl nach,
// ob die Kopie da ist (Code 3 sonst): die Gegenprobe mit -Path statt -LiteralPath meldete Code 0 und kopierte nichts.
export const KOPIER_BEFEHL =
  '$ErrorActionPreference = "Stop"; New-Item -ItemType Directory -Force -Path (Split-Path -LiteralPath $env:CW_NACH) | Out-Null; Copy-Item -LiteralPath $env:CW_VON -Destination $env:CW_NACH -Force; if (-not (Test-Path -LiteralPath $env:CW_NACH -PathType Leaf)) { exit 3 }'
export function kopierAufruf(arbeitsordner: string, von: string, nach: string): { argv: string[]; env: Record<string, string> } | { fehler: string } {
  if (!/^(?:[A-Za-z]:\\|\\\\)/.test(von)) return { fehler: t('Quelle ist kein voller Pfad', 'source is not a full path') }
  if (!spiegelZielOk(arbeitsordner, nach)) return { fehler: t('Ziel liegt nicht im Spiegelordner', 'target is not in the mirror folder') }
  return { argv: ['powershell', '-NoProfile', '-NonInteractive', '-Command', KOPIER_BEFEHL], env: { CW_VON: von, CW_NACH: nach } }
}

// Ab dieser Grösse (UTF-8-Bytes) kopiert der Ordner-Scan eine Datei, wenn $.fs.write sie ablehnt. Die Schnittstelle nennt 4 MiB
// ("a write over 4 MiB rejects"); 3 MiB lässt Platz, falls die Grenze anders gezählt wird. Darunter bleibt ein Schreibfehler ein Fehler.
export const KOPIER_AB = 3 * 1024 * 1024

// Länge eines Textes in UTF-8-Bytes, ohne TextEncoder (ein Ersatzzeichen-Paar zählt 4, ein einzelnes Ersatzzeichen 3 wie U+FFFD).
export function utf8Laenge(s: string): number {
  let n = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x80) n += 1
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4
      i++
    } else n += 3
  }
  return n
}

// Zeilen eines Textes wie text.split(/\r?\n/), aber ohne regulären Ausdruck: der ist in der Laufzeit des Wächters langsam
// (gemessen 28.11.2026 an einem Sammelbericht von 117 KB, 1000-mal: mit /\r?\n/ 5109 ms, mit '\n' 43 ms).
export function zeilenVon(text: string): string[] {
  const z = text.split('\n')
  for (let i = 0; i < z.length - 1; i++) {
    const s = z[i] ?? ''
    if (s.endsWith('\r')) z[i] = s.slice(0, -1)
  }
  return z
}
export const PROZESS_MAX_MS = 600000
const DEVSKIM_GLOBS = '**/*.cs,**/*.c,**/*.cc,**/*.cpp,**/*.cxx,**/*.h,**/*.hpp,**/*.hxx'
export const KOPF = /\.(?:h|hpp|hxx)$/i
const nameMitKleinerEndung = (file: string): string => {
  const name = file.split(/[\\/]/).pop() ?? 'datei'
  const punkt = name.lastIndexOf('.')
  return (punkt > 0 ? name.slice(0, punkt) + name.slice(punkt).toLowerCase() : name).replace(/[<>:"|?*]/g, '_')
}

export async function scannenOrdner(
  u: Umgebung,
  files: string[],
  opts: { restMs?: number; extra?: (file: string, text: string) => SFund[] } = {},
): Promise<Map<string, Ergebnis>> {
  const ergebnis = new Map<string, Ergebnis>()
  const von = (f: string): Ergebnis => {
    let e = ergebnis.get(f)
    if (!e) {
      e = { funde: [], luecken: [], liefen: [] }
      ergebnis.set(f, e)
    }
    return e
  }
  const start = u.jetzt ? await u.jetzt() : 0
  const rest = opts.restMs ?? 15 * 60000
  // Zeit für den nächsten Scanner: was von der Zeitgrenze des Scans übrig ist, höchstens 10 Minuten je Scanner und ganze ms - mehr
  // nimmt $.process.run nicht an (gemessen 27.11.2026: "init.timeoutMs is a whole number of ms, 1 to 600000").
  const frist = async (): Promise<number> => Math.floor(Math.min(PROZESS_MAX_MS, rest - ((u.jetzt ? await u.jetzt() : start) - start)))
  const kennung = u.kennung.replace(/[^\w-]/g, '_').slice(0, 64) || 'chat'
  const arbeit = await u.workDir()
  const spiegel = `${arbeit}\\spiegel-${kennung}`
  const nummer: string[] = [] // Nummer im Spiegel -> echte Datei
  const zeilen = new Map<string, string[]>() // für DevSkim (Wortgrenze bei MD5)
  const unlesbar = new Set<string>()
  const paketTexte = new Map<string, string>() // für den OSV-Scanner (Zeile des Pakets)
  const semgrepTexte = new Map<string, string>() // für Semgrep (Markierung code-waechter:ok SICHERHEIT in der Zeile)
  const spiegelPfad = new Map<string, string>() // echte Datei -> ihre Kopie im Spiegel (Semgrep prüft die Kopie, siehe semgrep.ts)
  // nummer hat Lücken: eine gescheiterte Kopie verbraucht ihre Nummer (unten), ihr Platz bleibt leer.
  const luecke = (liste: string[], text: string) => {
    for (const f of liste) if (f !== undefined) von(f).luecken.push(text)
  }
  const fehlt = (liste: string[], name: string, befehl: string) => luecke(liste, t(`${name} fehlt (einmalig: ${befehl})`, `${name} missing (once: ${befehl})`))
  const kaputt = (liste: string[], name: string, grund: string) => luecke(liste, t(`${name} lief nicht: ${rein(grund, 200)}`, `${name} did not run: ${rein(grund, 200)}`))
  const lief = (liste: string[], name: string) => {
    for (const f of liste) if (f !== undefined) von(f).liefen.push(name)
  }
  const meldung = (x: unknown): string => String((x as { message?: string })?.message ?? x)
  let naechsteNr = 0
  const ausgabe = async (pfad: string): Promise<string | undefined> => {
    const x = await u.read(pfad)
    return x === undefined || x.trim() === GITLEAKS_VORHER ? undefined : x
  }
  try {
    if (u.leeren) await u.leeren(spiegel)
    for (const f of files) {
      const e = von(f)
      const text = await u.read(f)
      if (text === undefined) {
        e.luecken.push(t('Datei nicht lesbar', 'file not readable'))
        unlesbar.add(f)
        continue
      }
      if (scannerFuer(f).muster) {
        e.funde.push(...eigeneMuster(text, f))
        e.liefen.push(t('Muster', 'patterns'))
      }
      if (opts.extra) e.funde.push(...opts.extra(f, text))
      if (OSV_DATEI.test(f)) paketTexte.set(f, text)
      if (SEMGREP_DATEI.test(f)) semgrepTexte.set(f, text)
      try {
        // Jeder Versuch bekommt eine eigene Nummer, auch ein gescheiterter: sonst läge eine halbe Kopie im Ordner der nächsten Datei,
        // und deren Funde gingen an die falsche Datei (vierte Gegenprüfung 28.11.2026).
        const nr = naechsteNr++
        const kopie = `${spiegel}\\${nr}\\${nameMitKleinerEndung(f)}`
        try {
          await u.write(kopie, text)
        } catch (err) {
          // Zu gross für write ($.fs.write lehnt über 4 MiB ab): die Datei selbst kopieren. Jeder andere Schreibfehler bleibt, wie er
          // ist - sonst startete z. B. bei voller Platte jede Datei ein Programm. Ist die Zeit des Scans um, wird nicht mehr kopiert;
          // scheitert das Kopieren, nennt die Lücke beide Gründe.
          if (!u.kopieren || utf8Laenge(text) <= KOPIER_AB) throw err
          const bleibt = await frist()
          if (bleibt <= 0) throw new Error(t('Zeitgrenze des Scans erreicht', 'scan time limit reached'))
          try {
            await u.kopieren(f, kopie, Math.min(120000, bleibt))
          } catch (k) {
            throw new Error(`${meldung(err)}; ${t('Kopieren', 'copy')}: ${meldung(k)}`)
          }
        }
        nummer[nr] = f
        spiegelPfad.set(f, kopie)
        if (scannerFuer(f).devskim) zeilen.set(f, zeilenVon(text))
      } catch (err) {
        // 300 Zeichen: der Kopiergrund ist höchstens 160 Zeichen lang (Fehlertext von PowerShell auf 120, Startfehler auf 160
        // gekürzt) und hat neben einem üblichen Schreibgrund Platz; nur ein sehr langer Schreibgrund kürzt das Ende (sechste
        // Gegenprüfung 28.11.2026).
        e.luecken.push(t(`Kopie nicht anlegbar (${rein(meldung(err), 300)})`, `copy not possible (${rein(meldung(err), 300)})`))
      }
    }
    const zuDatei = (pfad: string): string | undefined => {
      const m = SPIEGEL_NR.exec(pfad.trim())
      return m ? nummer[Number(m[1])] : undefined
    }
    const zeitAus = (liste: string[], name: string) => luecke(liste, t(`${name}: Zeitgrenze des Scans erreicht`, `${name}: scan time limit reached`))

    // DevSkim über den Spiegel
    const ds = nummer.filter(f => scannerFuer(f).devskim)
    if (ds.length > 0) {
      const exe = await u.exe('devskim')
      const zeit = await frist()
      if (!exe) fehlt(ds, 'DevSkim', 'dotnet tool install --global Microsoft.CST.DevSkim.CLI')
      else if (zeit < 1000) zeitAus(ds, 'DevSkim')
      else {
        const aus = `${arbeit}\\devskim-${kennung}.txt`
        await u.write(aus, GITLEAKS_VORHER)
        // --disable-parallel: gemessen 28.11.2026 (DevSkim 1.0.90, 116 Crashtest-Dateien, je 12 Läufe) lieferte die parallele
        // Verarbeitung je Lauf 24 bis 29 Fundzeilen statt 26 und stürzte einmal ab (System.IndexOutOfRangeException, "Arithmetic
        // operation resulted in an overflow"); ohne sie immer 26, kein Absturz, gleich schnell (0,57 statt 0,61 s).
        const r = await u.run([exe, 'analyze', '-I', spiegel, '-f', 'text', '-o', `%F|${DEVSKIM_FORMAT}`, '--absolute-path', '-g', NIE_AUSGELASSEN, '--include-globs', DEVSKIM_GLOBS, '--disable-parallel', '-O', aus], { timeoutMs: zeit })
        const inhalt = r.ok ? await ausgabe(aus) : undefined
        if (!r.ok) kaputt(ds, 'DevSkim', r.reason)
        else if (/\bERR\]/.test(`${r.stdout}${r.stderr}`)) kaputt(ds, 'DevSkim', daten(`${r.stderr}${r.stdout}`))
        else if (r.exitCode !== 0 || inhalt === undefined) kaputt(ds, 'DevSkim', inhalt === undefined ? t('keine Ausgabe geschrieben', 'no output written') : t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
        else {
          for (const z of zeilenVon(inhalt)) {
            const m = /^(.*)\|(\d+)\|(\d+)\|(Critical|Important|Moderate|BestPractice|ManualReview)\|(DS\d+)\|(.*)$/.exec(z.trim())
            const f = m ? zuDatei(m[1] ?? '') : undefined
            if (!m || !f || !scannerFuer(f).devskim) continue
            const fund: SFund = { line: Number(m[2]), col: Number(m[3]) + 1, code: m[5] ?? '', text: `[${m[4]}] ${rein(m[6] ?? '')}`, schwer: m[4] === 'Critical', scanner: 'DevSkim' }
            if (!devskimImWort(fund, zeilen.get(f) ?? [])) von(f).funde.push(fund)
          }
          lief(ds, 'DevSkim')
        }
      }
    }

    // Bandit über den Spiegel
    const py = nummer.filter(f => scannerFuer(f).bandit)
    if (py.length > 0) {
      const zeit = await frist()
      if (zeit < 1000) zeitAus(py, 'Bandit')
      else {
        const aus = `${arbeit}\\bandit-${kennung}.json`
        await u.write(aus, GITLEAKS_VORHER)
        const r = await u.run([...u.python, '-X', 'utf8', '-m', 'bandit', '-f', 'json', '-q', '-s', BANDIT_AUSGELASSEN, '-x', BANDIT_KEIN_AUSSCHLUSS, '-r', spiegel, '-o', aus],
          { env: { PYTHONSAFEPATH: '1' }, cwd: arbeit, timeoutMs: zeit })
        const inhalt = r.ok ? await ausgabe(aus) : undefined
        if (!r.ok) kaputt(py, 'Bandit', r.reason)
        else if (/No module named bandit/i.test(`${r.stdout}${r.stderr}`)) fehlt(py, 'Bandit', `${u.python.join(' ')} -m pip install bandit`)
        else if (inhalt === undefined) kaputt(py, 'Bandit', t('keine Ausgabe geschrieben', 'no output written') + (`${r.stderr}${r.stdout}`.trim() ? `: ${daten(`${r.stderr}${r.stdout}`)}` : ''))
        else {
          let j: any
          try {
            j = JSON.parse(inhalt)
          } catch {
            j = undefined
          }
          if (!j || !Array.isArray(j.results)) kaputt(py, 'Bandit', t('Ausgabe nicht lesbar', 'output not readable'))
          else {
            const gelesen = new Set(Object.keys(j.metrics ?? {}).filter(k => k !== '_totals').map(k => zuDatei(k)).filter((x): x is string => x !== undefined))
            for (const x of j.results) {
              const f = zuDatei(String(x.filename ?? ''))
              if (!f) continue
              const b = banditLesen(JSON.stringify({ results: [x], metrics: { [String(x.filename)]: {} } })).funde
              von(f).funde.push(...b)
            }
            const fehler = new Map<string, string>()
            for (const x of Array.isArray(j.errors) ? j.errors : []) {
              const f = zuDatei(String(x?.filename ?? ''))
              if (f) fehler.set(f, rein(String(x?.reason ?? ''), 160))
            }
            for (const f of py) {
              if (fehler.has(f)) kaputt([f], 'Bandit', daten(fehler.get(f) ?? ''))
              else if (!gelesen.has(f)) kaputt([f], 'Bandit', t('hat die Datei übersprungen', 'skipped the file'))
              else lief([f], 'Bandit')
            }
          }
        }
      }
    }

    // Gitleaks über den Spiegel (jede Datei des Scans)
    if (nummer.length > 0) {
      const exe = await u.exe('gitleaks')
      const zeit = await frist()
      if (!exe) fehlt(nummer, 'Gitleaks', 'winget install Gitleaks.Gitleaks')
      else if (zeit < 1000) zeitAus(nummer, 'Gitleaks')
      else {
        const bericht = `${arbeit}\\gitleaks-${kennung}-ordner.json`
        await u.write(bericht, GITLEAKS_VORHER)
        const r = await u.run([exe, 'dir', spiegel, '--no-banner', '--redact', '--exit-code', '0', ...GITLEAKS_ENTSCHLUESSELN, '--report-format', 'json', '--report-path', bericht], { cwd: arbeit, timeoutMs: zeit })
        const inhalt = r.ok ? await ausgabe(bericht) : undefined
        if (!r.ok) kaputt(nummer, 'Gitleaks', r.reason)
        else if (r.exitCode !== 0) kaputt(nummer, 'Gitleaks', t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
        else if (inhalt === undefined) kaputt(nummer, 'Gitleaks', t('kein Bericht geschrieben', 'no report written'))
        else {
          const g = gitleaksListe(inhalt)
          if (g.fehler) kaputt(nummer, 'Gitleaks', g.fehler)
          else {
            for (const x of g.liste) {
              const f = zuDatei(String(x.File ?? ''))
              if (f) von(f).funde.push(gitleaksEintrag(x))
            }
            lief(nummer, 'Gitleaks')
          }
        }
      }
    }

    // Cppcheck auf den echten Dateien
    const cc = files.filter(f => scannerFuer(f).cppcheck && !unlesbar.has(f))
    const gruppen = [cc.filter(f => !KOPF.test(f)), cc.filter(f => KOPF.test(f))]
    const exe = cc.length > 0 ? await u.exe('cppcheck') : undefined
    for (const [n, liste] of gruppen.entries()) {
      if (liste.length === 0) continue
      const zeit = await frist()
      if (!exe) {
        fehlt(liste, 'Cppcheck', 'winget install Cppcheck.Cppcheck')
        continue
      }
      if (zeit < 1000) {
        zeitAus(liste, 'Cppcheck')
        continue
      }
      const dateiliste = `${arbeit}\\cppcheck-${kennung}-${n}.txt`
      const aus = `${arbeit}\\cppcheck-${kennung}-${n}.out`
      await u.write(dateiliste, liste.join('\r\n'))
      await u.write(aus, GITLEAKS_VORHER)
      const r = await u.run([exe, '--enable=all', '--inconclusive', '--quiet', '--inline-suppr', `--template=${CPPCHECK_TEMPLATE}`, ...CPPCHECK_UNTERDRUECKT.map(s => `--suppress=${s}`),
        ...(n === 1 ? ['--language=c++'] : []), `--file-list=${dateiliste}`, `--output-file=${aus}`], { timeoutMs: zeit })
      const inhalt = r.ok ? await ausgabe(aus) : undefined
      if (!r.ok) {
        kaputt(liste, 'Cppcheck', r.reason)
        continue
      }
      if (inhalt === undefined) {
        kaputt(liste, 'Cppcheck', t('keine Ausgabe geschrieben', 'no output written') + (`${r.stderr}${r.stdout}`.trim() ? `: ${daten(`${r.stderr}${r.stdout}`)}` : ''))
        continue
      }
      const text = inhalt
      if (r.exitCode !== 0 && !/\|\d+\|\d+\|/.test(text)) {
        kaputt(liste, 'Cppcheck', t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
        continue
      }
      // Zeilen nach Datei sortieren, dann je Datei wie beim Einzellauf lesen.
      const jeDatei = new Map<string, string[]>()
      for (const z of text.split(/\r?\n/)) {
        const pfad = z.split('|')[0]?.replace(/\//g, '\\').toLowerCase() ?? ''
        const l = jeDatei.get(pfad) ?? []
        l.push(z)
        jeDatei.set(pfad, l)
      }
      for (const f of liste) {
        const c = cppcheckLesen((jeDatei.get(f.replace(/\//g, '\\').toLowerCase()) ?? []).join('\n'), f)
        von(f).funde.push(...c.funde)
        if (c.unvollstaendig.length > 0) kaputt([f], 'Cppcheck', t('nicht ganz ausgewertet - ', 'not fully analysed - ') + daten(c.unvollstaendig.join('; '), 240))
        else lief([f], 'Cppcheck')
      }
    }

    // C/C++-Analyse (c_analyse.ts) auf denselben echten Dateien wie Cppcheck
    if (u.cAnalyse) {
      for (const [f, e] of await cAnalyse(u, cc, frist, '-ordner')) {
        const z = von(f)
        z.funde.push(...e.funde)
        z.luecken.push(...e.luecken)
        z.liefen.push(...e.liefen)
      }
    }

    // Bekannte Lücken in Paketen (osv.ts): ein Aufruf über alle lesbaren Paketdateien des Scans
    const pk = [...paketTexte.keys()]
    if (u.osv && pk.length > 0) {
      for (const [f, e] of await osvPruefen(u, pk, paketTexte, await frist())) {
        const z = von(f)
        z.funde.push(...e.funde)
        z.luecken.push(...e.luecken)
        z.liefen.push(...e.liefen)
      }
    }

    // Datenfluss (semgrep.ts): ein Aufruf über alle lesbaren Dateien der drei Sprachen (bei sehr vielen in Stapeln)
    const sg = [...semgrepTexte.keys()]
    if (u.semgrep && sg.length > 0) {
      for (const [f, e] of await semgrepPruefen(u, sg, semgrepTexte, frist, '-ordner', spiegelPfad)) {
        const z = von(f)
        z.funde.push(...e.funde)
        z.luecken.push(...e.luecken)
        z.liefen.push(...e.liefen)
      }
    }
  } finally {
    if (u.leeren) {
      try {
        await u.leeren(spiegel)
      } catch {
        // Der Spiegel liegt im Arbeitsordner der Mod; bleibt er stehen, wird er beim nächsten Scan zuerst geleert.
      }
    }
  }
  for (const e of ergebnis.values()) {
    e.funde.sort((a, b) => a.line - b.line || a.col - b.col)
    e.liefen = [...new Set(e.liefen)].sort()
  }
  return ergebnis
}

// Ein Block je Scan im Sammelbericht: Kopfzeile mit dem Scan, darunter je Datei ihre Funde und was nicht geprüft wurde.
export function berichtScanBlock(zeit: string, titel: string, ergebnis: Map<string, Ergebnis>): string[] {
  const liefen = [...new Set([...ergebnis.values()].flatMap(e => e.liefen))].sort()
  const zeilen: string[] = []
  for (const [file, e] of ergebnis) {
    for (const f of e.funde) {
      zeilen.push(`  ${f.schwer ? t('FEHLER ', 'ERROR  ') : t('HINWEIS', 'HINT   ')} ${rein(file, 400)}  ${t('Zeile', 'line')} ${f.line}${f.col > 0 ? `:${f.col}` : ''}  ${f.scanner} ${rein(f.code, 60)}  ${rein(f.text, 300)}`)
    }
    for (const l of [...new Set(e.luecken)]) zeilen.push(`  ${t('NICHT GEPRÜFT', 'NOT CHECKED')}  ${rein(file, 400)}  ${rein(l, 300)}`)
  }
  return [`${zeit}  Scan ${rein(titel, 400)}  (${liefen.join(', ') || t('kein Scanner', 'no scanner')})`, ...zeilen, '']
}

// ---- Sammelbericht security-report.txt: neueste Prüfung oben, höchstens BERICHT_ZEILEN Zeilen.
export const BERICHT_ZEILEN = 3000
const BERICHT_KOPF_DE = 'Code-Wächter: Sicherheitsbericht (neueste Prüfung oben). Funde der Scanner DevSkim, Cppcheck, Bandit, Gitleaks und der eigenen Muster.'
const BERICHT_KOPF_EN = 'Code Guard: security report (newest check on top). Findings of DevSkim, Cppcheck, Bandit, Gitleaks and own patterns.'

export function berichtBlock(zeit: string, file: string, e: Ergebnis): string[] {
  const kopf = `${zeit}  ${rein(file, 400)}  (${e.liefen.join(', ') || t('kein Scanner', 'no scanner')})`
  const zeilen = e.funde.map(f =>
    `  ${f.schwer ? t('FEHLER ', 'ERROR  ') : t('HINWEIS', 'HINT   ')} ${t('Zeile', 'line')} ${f.line}${f.col > 0 ? `:${f.col}` : ''}  ${f.scanner} ${rein(f.code, 60)}  ${rein(f.text, 300)}`)
  const luecken = e.luecken.map(l => `  ${t('NICHT GEPRÜFT', 'NOT CHECKED')}  ${rein(l, 300)}`)
  return [kopf, ...zeilen, ...luecken, '']
}

export function berichtNeu(alt: string | undefined, block: string[]): string {
  const kopf = t(BERICHT_KOPF_DE, BERICHT_KOPF_EN)
  const vorher = alt === undefined ? [] : zeilenVon(alt)
  // Kopf (in welcher Sprache auch immer) und die Leerzeile danach nur einmal.
  const rest = vorher[0] === BERICHT_KOPF_DE || vorher[0] === BERICHT_KOPF_EN ? vorher.slice(vorher[1] === '' ? 2 : 1) : vorher
  return [kopf, '', ...block, ...rest].slice(0, BERICHT_ZEILEN).join('\r\n')
}
