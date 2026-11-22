// Sicherheits-Scanner: nach jedem Schreiben laufen die Scanner, die zur Dateiart passen; alle Funde stehen zusätzlich gebündelt
// in <Ablage>\security-report.txt.
//
//   DevSkim   C#, C, C++ (unsichere Aufrufe, schwache Verschlüsselung, abgeschaltete Zertifikatsprüfung)
//   Cppcheck  C, C++ (Speicherfehler, Pufferüberläufe, Zeigerfehler)
//   Bandit    Python (typische Python-Sicherheitslücken)
//   Gitleaks  jede geprüfte Datei und Einstellungsdateien (Passwörter, Zugangsschlüssel, Token, Webhooks)
//   eigene Muster für C#: Harmony-Patches (aus der Anleitung von Harmony 2) und Process.Start
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
}

// Steht vor dem Lauf in der Berichtsdatei: ist sie danach noch da, hat Gitleaks keinen Bericht geschrieben (nie als "keine Funde").
export const GITLEAKS_VORHER = 'CODE-WAECHTER-KEIN-BERICHT'

const C_CPP = /\.(?:c|cc|cpp|cxx|h|hpp|hxx)$/i
const CS = /\.cs$/i
const PY = /\.pyw?$/i

export function scannerFuer(file: string): { devskim: boolean; cppcheck: boolean; bandit: boolean; gitleaks: boolean; muster: boolean } {
  return { devskim: CS.test(file) || C_CPP.test(file), cppcheck: C_CPP.test(file), bandit: PY.test(file), gitleaks: true, muster: CS.test(file) }
}

// Text aus einem Scanner für Meldung und Bericht: ohne Farbcodes und Steuerzeichen (sonst entstünden falsche Berichtszeilen), gekürzt.
export function rein(s: string, n = 200): string {
  const x = s
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/g, ' ')
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
export function devskimImWort(f: SFund, zeilen: string[]): boolean {
  if (f.code !== 'DS126858') return false
  const vor = (zeilen[f.line - 1] ?? '').charAt(f.col - 2)
  return /[A-Za-z0-9_]/.test(vor)
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
      schwer: r.issue_severity === 'HIGH' && r.issue_confidence === 'HIGH',
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

export function gitleaksLesen(json: string): { funde: SFund[]; fehler?: string } {
  let j: any
  try {
    j = JSON.parse(json.trim() === '' ? '[]' : json)
  } catch {
    return { funde: [], fehler: t('Bericht nicht lesbar', 'report not readable') }
  }
  if (!Array.isArray(j)) return { funde: [], fehler: t('Bericht ohne Liste', 'report without list') }
  return {
    funde: j
      .filter((f: any) => !GITLEAKS_OHNE.has(String(f.RuleID ?? '')))
      .map((f: any) => {
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
      }),
  }
}

// ---- Eigene Muster für C#: Harmony 2 (harmony.pardeike.net, gelesen 20.11.2026) und Process.Start.
const OK_SICHER = /code-waechter:ok\s+SICHERHEIT\b/
const PATCH_ATTR = /\[\s*Harmony(Prefix|Postfix|Transpiler|Finalizer)\s*\]/
const PATCH_NAME = /^(?:Prefix|Postfix|Transpiler|Finalizer)$/
const METHODE = /^\s*(?:\[[^\]]*\]\s*)*((?:(?:public|private|internal|protected|static|unsafe|override|virtual|new|async|extern)\s+)*)[\w<>[\],.?]+\s+(\w+)\s*\(/

export function musterBefunde(text: string): SFund[] {
  const zeilen = text.split(/\r?\n/)
  const funde: SFund[] = []
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
    if (/\bProcess\s*\.\s*Start\s*\(|\bnew\s+ProcessStartInfo\b/.test(z)) {
      funde.push({ line: nr, col: 1, code: 'PROCESS-START', schwer: false, scanner: t('Muster', 'pattern'),
        text: t('startet ein anderes Programm: nur mit festem Programmpfad, nie mit Text aus Eingaben, Dateien oder dem Netz',
          'starts another program: only with a fixed program path, never with text from input, files or the network') })
    }
  }
  return funde
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
  const zeilen = (text ?? '').split(/\r?\n/)

  const jobs: Promise<void>[] = []
  if (wahl.muster && text !== undefined) {
    funde.push(...musterBefunde(text))
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
      const r = await u.run([exe, 'dir', file, '--no-banner', '--redact', '--exit-code', '0', '--report-format', 'json', '--report-path', bericht],
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
  await Promise.all(jobs)
  funde.sort((a, b) => a.line - b.line || a.col - b.col)
  return { funde, luecken, liefen: liefen.sort() }
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
  const vorher = alt === undefined ? [] : alt.split(/\r?\n/)
  // Kopf (in welcher Sprache auch immer) und die Leerzeile danach nur einmal.
  const rest = vorher[0] === BERICHT_KOPF_DE || vorher[0] === BERICHT_KOPF_EN ? vorher.slice(vorher[1] === '' ? 2 : 1) : vorher
  return [kopf, '', ...block, ...rest].slice(0, BERICHT_ZEILEN).join('\r\n')
}
