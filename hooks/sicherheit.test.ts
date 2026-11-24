import { expect, test } from 'claude-code/testing'
import {
  BERICHT_ZEILEN, GITLEAKS_VORHER, banditLesen, berichtBlock, berichtNeu, cppcheckLesen, devskimImWort, devskimLesen, gitleaksLesen,
  cMuster, geheimMuster, musterBefunde, rein, scannen, scannerFuer,
} from './sicherheit'
import type { Lauf, Umgebung } from './sicherheit'

// Ausgabe von DevSkim 1.0.90, gemessen am 20.11.2026 an einer Probedatei (Format -o "%L|%C|%S|%R|%N"; Spalte 0-basiert).
const DEVSKIM_ECHT = [
  '8|16|Critical|DS126858|Weak/Broken Hash Algorithm',
  '9|20|Important|DS148264|Do not use weak/non-cryptographic random number generators',
  '10|39|Critical|DS126187|Disabled certificate validation',
  'For guidance on reported issues visit the relevant page here: https://github.com/microsoft/DevSkim/tree/main/guidance',
].join('\r\n')

test('DevSkim: Zeile, Spalte ab 1, Regel; Critical ist ein Fehler, der Rest ein Hinweis; ERR ist kein OK', () => {
  const d = devskimLesen(DEVSKIM_ECHT)
  expect(d.fehler).toBe(undefined)
  expect(d.funde.map(f => [f.line, f.col, f.code, f.schwer])).toEqual([[8, 17, 'DS126858', true], [9, 21, 'DS148264', false], [10, 40, 'DS126187', true]])
  expect(devskimLesen('[10:44:37 ERR] Error: Not a valid file or directory clean.cs').fehler).toContain('Not a valid file')
  expect(devskimLesen('').funde).toEqual([])
})

test('DevSkim DS126858: md2 mitten in einem Namen ist kein schwacher Hash, MD5 als eigenes Wort schon', () => {
  // Gegenprüfung 20.11.2026: ProbeSchrank.cs Zeile 906 "fremd2" wurde Critical gemeldet.
  const zeilen = ['if (x.TryGet(1, out var fremd2) && fremd2.Ok) { }', 'var h = MD5.Create();']
  const fund = (line: number, col: number) => ({ line, col, code: 'DS126858', text: '', schwer: true, scanner: 'DevSkim' })
  expect(devskimImWort(fund(1, zeilen[0].indexOf('md2') + 1), zeilen)).toBe(true)
  expect(devskimImWort(fund(2, zeilen[1].indexOf('MD5') + 1), zeilen)).toBe(false)
  expect(devskimImWort({ ...fund(1, zeilen[0].indexOf('md2') + 1), code: 'DS148264' }, zeilen)).toBe(false)
})

test('Cppcheck: error ist ein Fehler, unsicher und Stil sind Hinweise; Funde aus eingebundenen Dateien zählen nicht; Konfigurationsfehler sind eine Lücke', () => {
  const datei = 'D:\\c\\probe.cpp'
  const c = cppcheckLesen([
    'D:\\c\\probe.cpp|3|32|error|bufferAccessOutOfBounds||Buffer is accessed out of bounds: buf',
    'D:/c/probe.cpp|5|1|error|memleak|U|Memory leak: p',
    'D:\\c\\probe.cpp|7|9|style|variableScope||The scope of the variable x can be reduced.',
    'D:\\c\\probe.cpp|0|0|information|normalCheckLevelMaxBranches||Limiting analysis of branches.',
    'D:\\c\\kopf.h|12|5|error|nullPointer||Null pointer dereference: p',
    'Checking probe.cpp ...',
  ].join('\n'), datei)
  expect(c.funde.map(x => [x.line, x.code, x.schwer])).toEqual([[3, 'bufferAccessOutOfBounds', true], [5, 'memleak', false], [7, 'variableScope', false]])
  expect(c.funde[1].text).toContain('unsicher')
  expect(c.unvollstaendig).toEqual([])
  const k = cppcheckLesen("D:\\c\\klasse.h|3|1|error|syntaxError||Code 'namespacespiel{' is invalid C code.", 'D:\\c\\klasse.h')
  expect(k.funde).toEqual([])
  expect(k.unvollstaendig[0]).toContain('syntaxError')
})

const BANDIT_JSON = (results: object[], metrics: object = { 'D:/p/a.py': { loc: 5 }, _totals: { loc: 5 } }) =>
  JSON.stringify({ errors: [], generated_at: '2026-11-20T10:00:00Z', metrics, results })

test('Bandit: hohe Schwere mit hoher Sicherheit ist ein Fehler; Passwort-Regeln verbergen den Text; übersprungene Datei; unlesbar ist kein OK', () => {
  const b = banditLesen(BANDIT_JSON([
    { filename: 'a.py', issue_confidence: 'HIGH', issue_severity: 'HIGH', issue_text: 'subprocess call with shell=True identified, security issue.', line_number: 4, col_offset: 4, test_id: 'B602' },
    { filename: 'a.py', issue_confidence: 'MEDIUM', issue_severity: 'LOW', issue_text: "Possible hardcoded password: 'Sommer2026'", line_number: 9, col_offset: 11, test_id: 'B105' },
  ]))
  expect(b.fehler).toBe(undefined)
  expect(b.uebersprungen).toBe(undefined)
  // Seit 24.11.2026 (Sicherheits-Crashtest) ist ein eingebautes Passwort (B105) ein Fehler, nicht mehr ein Hinweis.
  expect(b.funde.map(f => [f.line, f.col, f.code, f.schwer, f.geheim === true])).toEqual([[4, 5, 'B602', true, false], [9, 12, 'B105', true, true]])
  expect(JSON.stringify(b.funde)).not.toContain('Sommer2026')
  // Gemessen 20.11.2026: ohne -x übersprang Bandit eine Datei unter .github - dann steht in "metrics" keine Datei.
  expect(banditLesen(BANDIT_JSON([], { _totals: { loc: 0 } })).uebersprungen).toBe(true)
  expect(banditLesen('Traceback (most recent call last)').fehler).toBeDefined()
  expect(banditLesen('{"results": ').fehler).toBeDefined()
  expect(banditLesen(JSON.stringify({ errors: [{ filename: 'a.py', reason: 'syntax error while parsing AST from file' }], results: [], metrics: {} })).fehler).toContain('syntax error')
})

test('Gitleaks: Funde sind Fehler und geheim, generic-api-key zählt nicht, Spalte ab Zeile 2 berichtigt', () => {
  const g = gitleaksLesen(JSON.stringify([
    { Description: 'GitHub Personal Access Token', StartLine: 1, StartColumn: 10, Secret: 'GEHEIM123', Match: 'token = GEHEIM123', RuleID: 'github-pat' },
    { Description: 'GitHub Personal Access Token', StartLine: 3, StartColumn: 11, Secret: 'REDACTED', RuleID: 'github-pat' },
    // Gegenprüfung 20.11.2026: 5247 solche Funde in einem Spiel-Mod-Projekt, alles Übersetzungsschlüssel
    { Description: 'Detected a Generic API Key', StartLine: 13, StartColumn: 71, Secret: 'REDACTED', RuleID: 'generic-api-key' },
  ]))
  expect(g.funde.map(f => [f.line, f.col, f.code, f.schwer, f.geheim])).toEqual([[1, 10, 'github-pat', true, true], [3, 10, 'github-pat', true, true]])
  expect(JSON.stringify(g.funde)).not.toContain('GEHEIM123')
  expect(gitleaksLesen('[]').funde).toEqual([])
  expect(gitleaksLesen('kaputt').fehler).toBeDefined()
  expect(gitleaksLesen('{}').fehler).toBeDefined()
})

test('Harmony und Process.Start: Regeln aus der Anleitung von Harmony 2, bewusste Stellen bleiben still', () => {
  const art = (text: string) => musterBefunde(text).map(f => `${f.code}${f.schwer ? '!' : ''}@${f.line}`)
  const kopf = 'using HarmonyLib;\n[HarmonyPatch(typeof(Spiel), "Tick")]\nclass P {\n'
  expect(art('harmony.UnpatchAll();')).toEqual(['HARMONY-UNPATCH!@1'])
  expect(art('harmony.UnpatchAll("com.kaese.mod");')).toEqual([])
  expect(art(`${kopf}  static void Prefix() { }\n}`)).toEqual([])
  expect(art(`${kopf}  void Postfix() { }\n}`)).toEqual(['HARMONY-STATISCH!@4'])
  expect(art(`${kopf}  [HarmonyPrefix]\n  public bool VorDemTick() { return false; }\n}`)).toEqual(['HARMONY-STATISCH!@5'])
  expect(art(`${kopf}  static bool Prefix(ref int __result) { return true; }\n}`)).toEqual([])
  // Ohne Harmony in der Datei ist eine Methode "Prefix" keine Patch-Methode.
  expect(art('class Text {\n  string Prefix() { return ""; }\n}')).toEqual([])
  expect(art('var h = new Harmony("meinemod");')).toEqual(['HARMONY-ID@1'])
  expect(art('var h = new Harmony("com.kaese.meinemod");')).toEqual([])
  expect(art('Process.Start("notepad.exe");')).toEqual(['PROCESS-START@1'])
  expect(art('var i = new ProcessStartInfo { FileName = p };')).toEqual(['PROCESS-START@1'])
  expect(art('Process.Start(url); // code-waechter:ok SICHERHEIT Hilfeseite im Browser')).toEqual([])
  expect(art('// Process.Start(x) war früher hier')).toEqual([])
})

test('Auswahl: nur die passenden Scanner je Dateiart', () => {
  expect(scannerFuer('D:\\m\\Patch.cs')).toEqual({ devskim: true, cppcheck: false, bandit: false, gitleaks: true, muster: true })
  // Seit 24.11.2026 laufen eigene Muster auch bei C/C++ (Überlauf, Formatstring) und Python (eingebaute Schlüssel).
  expect(scannerFuer('D:\\c\\a.cpp')).toEqual({ devskim: true, cppcheck: true, bandit: false, gitleaks: true, muster: true })
  expect(scannerFuer('D:\\c\\a.h')).toEqual({ devskim: true, cppcheck: true, bandit: false, gitleaks: true, muster: true })
  expect(scannerFuer('D:\\p\\a.py')).toEqual({ devskim: false, cppcheck: false, bandit: true, gitleaks: true, muster: true })
  expect(scannerFuer('D:\\p\\a.pyw')).toEqual({ devskim: false, cppcheck: false, bandit: true, gitleaks: true, muster: true })
  expect(scannerFuer('D:\\m\\Config\\items.xml')).toEqual({ devskim: false, cppcheck: false, bandit: false, gitleaks: true, muster: false })
})

test('rein: Farbcodes, Zeilenumbrüche und Steuerzeichen kommen nie in Meldung oder Bericht', () => {
  expect(rein('erste\r\n  FEHLER  Zeile 99  erfunden\x1b[31mROT')).toBe('erste FEHLER Zeile 99 erfundenROT')
  expect(rein('x'.repeat(300), 10)).toBe(`${'x'.repeat(9)}…`)
})

// Gespielte Umgebung: welche Programme da sind, was sie ausgeben, was in Dateien steht.
function umgebung(da: Partial<Record<'devskim' | 'cppcheck' | 'gitleaks', string>>, antwort: (argv: string[]) => Lauf, dateien: Record<string, string> = {}, python = ['py']) {
  const aufrufe: { argv: string[]; cwd?: string }[] = []
  const u: Umgebung = {
    run: async (argv, opts) => {
      aufrufe.push({ argv, cwd: opts.cwd })
      return antwort(argv)
    },
    python,
    exe: async name => da[name],
    workDir: async () => 'C:\\Temp\\code-waechter',
    read: async p => dateien[p],
    write: async (p, text) => {
      dateien[p] = text
    },
    kennung: 'chat:1',
  }
  return { u, aufrufe, dateien }
}
const leer: Lauf = { ok: true, exitCode: 0, stdout: '', stderr: '', truncated: false }
// je Chat eine eigene Berichtsdatei (Zeichen ausser Buchstaben, Ziffern, _ und - werden zu _)
const BERICHT = 'C:\\Temp\\code-waechter\\gitleaks-chat_1.json'

test('Scannen: fehlende Scanner stehen offen mit dem Installationsbefehl, nie als OK', async () => {
  const { u, aufrufe } = umgebung({}, () => leer)
  const e = await scannen(u, 'D:\\c\\a.cpp', 'int main() { return 0; }')
  expect(e.funde).toEqual([])
  // Seit 24.11.2026 laufen bei C/C++ die eigenen Muster (kein fremdes Programm) - nur sie, kein Scanner.
  expect(e.liefen).toEqual(['Muster'])
  expect(e.luecken.join(' | ')).toContain('DevSkim fehlt (einmalig: dotnet tool install --global Microsoft.CST.DevSkim.CLI)')
  expect(e.luecken.join(' | ')).toContain('Cppcheck fehlt (einmalig: winget install Cppcheck.Cppcheck)')
  expect(e.luecken.join(' | ')).toContain('Gitleaks fehlt (einmalig: winget install Gitleaks.Gitleaks)')
  expect(aufrufe).toEqual([])
})

test('Scannen: C# läuft durch DevSkim (ohne eigene Ausnahmen), Gitleaks im Ordner der Mod und die Muster; ohne Bericht eine Lücke', async () => {
  const { u, aufrufe } = umgebung({ devskim: 'C:\\t\\devskim.exe', gitleaks: 'C:\\t\\gitleaks.exe' }, argv =>
    argv[0].endsWith('devskim.exe') ? { ...leer, stdout: DEVSKIM_ECHT } : leer)
  const e = await scannen(u, 'D:\\m\\Patch.cs', 'harmony.UnpatchAll();')
  expect(e.liefen).toEqual(['DevSkim', 'Muster'])
  expect(e.funde.map(f => f.code)).toEqual(['HARMONY-UNPATCH', 'DS126858', 'DS148264', 'DS126187'])
  expect(e.luecken).toEqual(['Gitleaks lief nicht: kein Bericht geschrieben'])
  const d = aufrufe.find(a => a.argv[0].endsWith('devskim.exe'))?.argv ?? []
  expect(d[d.indexOf('-g') + 1]).toBe('**/.code-waechter-nie/**') // sonst übersprang DevSkim alles unter \bin\ still
  const g = aufrufe.find(a => a.argv[0].endsWith('gitleaks.exe'))
  expect(g?.argv.slice(1, 3)).toEqual(['dir', 'D:\\m\\Patch.cs'])
  expect(g?.argv).toContain('--redact')
  expect(g?.argv).toContain('--no-banner')
  expect(g?.cwd).toBe('C:\\Temp\\code-waechter') // nicht der Ordner des Chats (.gitleaksignore)
})

test('Scannen: DevSkim mit Fehlercode und ohne Ausgabe ist eine Lücke, kein "DevSkim lief"', async () => {
  const { u } = umgebung({ devskim: 'C:\\t\\devskim.exe' }, argv => (argv[0].endsWith('devskim.exe') ? { ...leer, exitCode: -532462766, stderr: 'Unhandled exception.' } : leer))
  const e = await scannen(u, 'D:\\m\\Patch.cs', 'class A { }')
  expect(e.liefen).not.toContain('DevSkim')
  expect(e.luecken.join(' | ')).toContain('DevSkim lief nicht: Code -532462766')
})

test('Scannen: Gitleaks-Fund wird gelesen; ein Scanner, der abbricht oder wirft, nimmt den anderen nichts weg', async () => {
  const dateien: Record<string, string> = {}
  const { u } = umgebung({ gitleaks: 'C:\\t\\gitleaks.exe' }, argv => {
    if (argv[0].endsWith('gitleaks.exe')) dateien[BERICHT] = JSON.stringify([{ RuleID: 'github-pat', Description: 'GitHub Personal Access Token', StartLine: 2, StartColumn: 5, Secret: 'REDACTED' }])
    if (argv.includes('bandit')) throw new Error('Prozess nicht startbar')
    return leer
  }, dateien)
  const e = await scannen(u, 'D:\\p\\a.py', 'x = 1\n')
  expect(e.funde.map(f => [f.scanner, f.line, f.col, f.schwer])).toEqual([['Gitleaks', 2, 4, true]])
  expect(e.luecken).toEqual(['Bandit lief nicht: Prozess nicht startbar'])
  expect(dateien[BERICHT]).not.toBe(GITLEAKS_VORHER)
})

test('Scannen: Gitleaks-Fehler (Datei fehlt) ist eine Lücke ohne Farbcodes; Bandit lässt dieselben Regeln aus wie Ruff, aber keine Ordner', async () => {
  // Ausgabe von Gitleaks 8.30.1 bei fehlender Datei, gemessen am 20.11.2026 (Code 1, Meldung mit Farbcodes auf stderr)
  const ftl = '\x1b[90m11:15AM\x1b[0m \x1b[31mFTL\x1b[0m \x1b[1mCreateFile D:/p/weg.py: Das System kann die angegebene Datei nicht finden.\x1b[0m\n'
  const { u, aufrufe } = umgebung({ gitleaks: 'C:\\t\\gitleaks.exe' }, argv =>
    (argv[0].endsWith('gitleaks.exe') ? { ...leer, exitCode: 1, stderr: ftl } : { ...leer, stdout: BANDIT_JSON([]) }))
  const e = await scannen(u, 'D:\\p\\weg.py', undefined)
  // Text des Scanners steht als Daten in «…»
  expect(e.luecken).toEqual(['Gitleaks lief nicht: Code 1: «11:15AM FTL CreateFile D:/p/weg.py: Das System kann die angegebene Datei nicht finden.»'])
  const b = aufrufe.find(a => a.argv.includes('bandit'))?.argv ?? []
  expect(b[b.indexOf('-s') + 1]).toBe('B101,B311,B404,B603,B607')
  expect(b[b.indexOf('-x') + 1]).toBe('*.code-waechter-nie')
})

test('Scannen: Bandit fehlt im eingestellten Python - der Befehl nennt genau dieses Python; übersprungene Datei ist eine Lücke', async () => {
  const { u } = umgebung({}, argv => (argv.includes('bandit') ? { ...leer, exitCode: 1, stderr: 'C:\\Python\\python.exe: No module named bandit' } : leer), {}, ['py', '-3.14'])
  const e = await scannen(u, 'D:\\p\\a.py', 'x = 1\n')
  expect(e.luecken).toContain('Bandit fehlt (einmalig: py -3.14 -m pip install bandit)')
  const { u: u2 } = umgebung({}, () => ({ ...leer, stdout: BANDIT_JSON([], { _totals: { loc: 0 } }) }))
  const e2 = await scannen(u2, 'D:\\p\\.github\\a.py', 'x = 1\n')
  expect(e2.luecken).toContain('Bandit lief nicht: hat die Datei übersprungen')
  expect(e2.liefen).not.toContain('Bandit')
})

test('Scannen: .h läuft als C++ durch Cppcheck; ein Syntax-/Konfigurationsfehler ist eine Lücke, kein Rot', async () => {
  const { u, aufrufe } = umgebung({ cppcheck: 'C:\\t\\cppcheck.exe' }, argv =>
    (argv[0].endsWith('cppcheck.exe') ? { ...leer, stderr: "D:\\c\\klasse.h|3|1|error|syntaxError||Code 'namespacespiel{' is invalid C code.\n" } : leer))
  const e = await scannen(u, 'D:\\c\\klasse.h', 'namespace spiel { class A {}; }')
  expect(aufrufe.find(a => a.argv[0].endsWith('cppcheck.exe'))?.argv).toContain('--language=c++')
  expect(e.funde).toEqual([])
  expect(e.luecken.join(' | ')).toContain('Cppcheck lief nicht: nicht ganz ausgewertet - «syntaxError')
})

test('Scannen: DevSkim-Fund mitten in einem Namen fällt weg', async () => {
  const text = 'class A {\n  void F() { if (T(out var fremd2)) { } }\n}'
  const col0 = text.split('\n')[1].indexOf('md2')
  const { u } = umgebung({ devskim: 'C:\\t\\devskim.exe' }, argv => (argv[0].endsWith('devskim.exe') ? { ...leer, stdout: `2|${col0}|Critical|DS126858|Weak/Broken Hash Algorithm\n` } : leer))
  const e = await scannen(u, 'D:\\m\\A.cs', text)
  expect(e.funde).toEqual([])
  expect(e.liefen).toContain('DevSkim')
})

test('Sammelbericht: neueste Prüfung oben, Kopf nur einmal (auch englisch), Text bereinigt, nie länger als die Grenze', () => {
  const e1 = { funde: [{ line: 3, col: 1, code: 'HARMONY-UNPATCH', text: 'UnpatchAll() ohne Kennung\r\n  FEHLER  Zeile 99  erfunden', schwer: true, scanner: 'Muster' }], luecken: ['Gitleaks fehlt'], liefen: ['Muster'] }
  const a = berichtNeu(undefined, berichtBlock('20.11.2026 10:00:00', 'D:\\m\\A.cs', e1))
  const b = berichtNeu(a, berichtBlock('20.11.2026 10:05:00', 'D:\\m\\B.cs', e1))
  const z = b.split('\r\n')
  expect(z[0]).toContain('Sicherheitsbericht')
  expect(z[2]).toContain('10:05:00  D:\\m\\B.cs')
  expect(b.indexOf('B.cs')).toBeLessThan(b.indexOf('A.cs'))
  expect(b).toContain('FEHLER  Zeile 3:1  Muster HARMONY-UNPATCH')
  expect(z.filter(x => x.startsWith('  FEHLER  Zeile 99')).length).toBe(0) // eingeschleuster Zeilenumbruch erzeugt keine Zeile
  expect(b).toContain('NICHT GEPRÜFT  Gitleaks fehlt')
  expect(b.split('Sicherheitsbericht').length).toBe(2) // der Kopf steht nur einmal
  // Ein englischer Bericht davor: auch dessen Kopf wird ersetzt, nicht wiederholt.
  const englisch = `Code Guard: security report (newest check on top). Findings of DevSkim, Cppcheck, Bandit, Gitleaks and own patterns.\r\n\r\n${z.slice(2).join('\r\n')}`
  const c = berichtNeu(englisch, berichtBlock('20.11.2026 10:10:00', 'D:\\m\\C.cs', e1))
  expect(c.split('Code Guard: security report').length).toBe(1)
  expect(c.split('Sicherheitsbericht').length).toBe(2)
  let lang = a
  for (let i = 0; i < 1000; i++) lang = berichtNeu(lang, berichtBlock(`${i}`, 'D:\\m\\A.cs', e1))
  expect(lang.split('\r\n').length).toBeLessThan(BERICHT_ZEILEN + 1)
})

// Sicherheits-Crashtest 24.11.2026: eval, exec, pickle, Pufferüberlauf, Formatstring und eingebaute Schlüssel sind Fehler.
test('Bandit: exec, eval, pickle, marshal, yaml.load und eingebaute Passwörter sind Fehler; import pickle bleibt ein Hinweis', () => {
  const b = banditLesen(BANDIT_JSON([
    { issue_confidence: 'HIGH', issue_severity: 'MEDIUM', issue_text: 'Use of exec detected.', line_number: 2, col_offset: 4, test_id: 'B102' },
    { issue_confidence: 'HIGH', issue_severity: 'MEDIUM', issue_text: 'Use of possibly insecure function - consider using safer ast.literal_eval.', line_number: 3, col_offset: 4, test_id: 'B307' },
    { issue_confidence: 'HIGH', issue_severity: 'MEDIUM', issue_text: 'Pickle and modules that wrap it can be unsafe', line_number: 4, col_offset: 4, test_id: 'B301' },
    { issue_confidence: 'HIGH', issue_severity: 'MEDIUM', issue_text: 'Deserialization with the marshal module is possibly dangerous.', line_number: 5, col_offset: 4, test_id: 'B302' },
    { issue_confidence: 'HIGH', issue_severity: 'MEDIUM', issue_text: 'Use of unsafe yaml load.', line_number: 6, col_offset: 4, test_id: 'B506' },
    { issue_confidence: 'MEDIUM', issue_severity: 'LOW', issue_text: "Possible hardcoded password: 'x'", line_number: 7, col_offset: 4, test_id: 'B106' },
    { issue_confidence: 'HIGH', issue_severity: 'LOW', issue_text: 'Consider possible security implications associated with pickle module.', line_number: 1, col_offset: 0, test_id: 'B403' },
  ]))
  expect(b.funde.map(f => `${f.code}${f.schwer ? '!' : ''}`)).toEqual(['B102!', 'B307!', 'B301!', 'B302!', 'B506!', 'B106!', 'B403'])
})

test('C/C++: Überlauf-Funktionen und Formatstrings ohne festen Text sind Fehler; sichere Formen, Kommentare, Texte und Methoden nicht', () => {
  const art = (text: string) => cMuster(text).map(f => `${f.code}@${f.line}`)
  expect(art('void f(char *d, const char *s)\n{\n  strcpy(d, s);\n  strcat(d, s);\n  gets(d);\n  sprintf(d, "%s", s);\n}\n'))
    .toEqual(['C-UEBERLAUF@3', 'C-UEBERLAUF@4', 'C-UEBERLAUF@5', 'C-UEBERLAUF@6'])
  expect(art('void f(const char *s, char *d, size_t n)\n{\n  printf(s);\n  fprintf(stderr, s);\n  snprintf(d, n, s);\n  syslog(LOG_ERR, s);\n}\n'))
    .toEqual(['C-FORMAT@3', 'C-FORMAT@4', 'C-FORMAT@5', 'C-FORMAT@6'])
  // Sichere Formen: festes Format, auch L"..." und _T("..."); Format über mehrere Zeilen.
  expect(art('void f(const char *s, char *d, size_t n)\n{\n  printf("%s", s);\n  printf("hallo\\n");\n  fprintf(stderr, "Fehler: %s", s);\n  snprintf(d, n, "%s", s);\n  wprintf(L"%ls", w);\n  _tprintf(_T("%s"), s);\n  printf(\n    "%d",\n    n);\n  strncpy(d, s, n);\n}\n')).toEqual([])
  // Im Kommentar, im Text, als Methode eines Objekts, als Teil eines Namens und bewusst markiert: still.
  expect(art('// strcpy(d, s) war hier\n/* printf(s); */\nconst char *t = "strcpy(a, b)";\nobj.strcpy(a, b);\nmy_strcpy(a, b);\nstrcpy(d, s); // code-waechter:ok SICHERHEIT Länge oben geprüft\n')).toEqual([])
})

test('Eingebaute Schlüssel in C#, C und Python sind Fehler (Wert verborgen); Platzhalter, kurze Werte, Prüfprojekte und markierte Stellen nicht', () => {
  const art = (text: string, file = 'D:\\p\\a.py') => geheimMuster(text, file).map(f => `${f.code}@${f.line}`)
  expect(art('API_KEY = "sk-live-4f9a8b7c6d5e4f3a2b1c"\n')).toEqual(['GEHEIMNIS@1'])
  expect(art('x = 1\nprivate const string ApiKey = "AKfy7Hq2LmZ9pRt4Wv8X";\n', 'D:\\p\\A.cs')).toEqual(['GEHEIMNIS@2'])
  expect(art('konfig = {"client_secret": "a8F3kL0pQ7zX2mN5vB9c"}\n')).toEqual(['GEHEIMNIS@1'])
  expect(geheimMuster('API_KEY = "sk-live-4f9a8b7c6d5e4f3a2b1c"\n', 'D:\\p\\a.py')[0].geheim).toBe(true)
  expect(JSON.stringify(geheimMuster('API_KEY = "sk-live-4f9a8b7c6d5e4f3a2b1c"\n', 'D:\\p\\a.py'))).not.toContain('4f9a8b7c')
  // Echte Fehlalarme der Gitleaks-Regel generic-api-key (24.11.2026): Übersetzungsschlüssel bleiben still.
  expect(art('_localization_dazu(text, [{"Key": "khGegenprobeE18Anteil", "english": "Warns at 5 % of the run."}])\n')).toEqual([])
  expect(art('API_KEY = "DEIN-SCHLUESSEL-HIER-1234"\napi_key = "abc123"\npassword = os.environ["PW"]\ntoken_type = "Bearer"\n')).toEqual([])
  expect(art('API_KEY = "sk-live-4f9a8b7c6d5e4f3a2b1c"  # code-waechter:ok SICHERHEIT öffentlicher Probe-Schlüssel\n')).toEqual([])
  expect(art('const string Kennwort = "Sommer2026Herbst!x";\n', 'D:\\p\\App.Pruefung\\Probe.cs')).toEqual([])
  expect(art('const string Kennwort = "Sommer2026Herbst!x";\n', 'D:\\p\\App.Tests\\Probe.cs')).toEqual([])
})

test('Scannen: die eigenen Muster laufen auch bei Python (eingebauter Schlüssel) und C (Überlauf) und machen die Datei rot', async () => {
  const { u } = umgebung({}, () => leer)
  const py = await scannen(u, 'D:\\p\\a.py', 'API_KEY = "sk-live-4f9a8b7c6d5e4f3a2b1c"\n')
  expect(py.funde.map(f => `${f.code}${f.schwer ? '!' : ''}`)).toEqual(['GEHEIMNIS!'])
  const c = await scannen(u, 'D:\\c\\a.c', 'void f(char *d, const char *s) { strcpy(d, s); }\n')
  expect(c.funde.map(f => `${f.code}${f.schwer ? '!' : ''}`)).toEqual(['C-UEBERLAUF!'])
})
