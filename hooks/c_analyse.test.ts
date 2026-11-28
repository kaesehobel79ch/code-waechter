import { expect, test } from 'claude-code/testing'
import { cAnalyse, clangTidyLesen, clangTidyNeben, msvcAnalyseLesen, zuDatei } from './c_analyse'
import type { CWerkzeuge } from './c_analyse'
import { scannen, scannenOrdner } from './sicherheit'
import type { Lauf, Umgebung } from './sicherheit'

// Erwartungen aus dem Auftrag (27.11.2026, Bauplan Code-Wächter): rot nur C6385, C6386, C6200, C6201, C6001 und
// clang-analyzer-security.ArrayBound, -unix.Malloc, -cplusplus.NewDelete, -core.uninitialized.*; C6011 (Nullzeiger) ein Hinweis;
// fehlende Kopfdatei / Übersetzungsfehler kein Fund, sondern "nicht ganz ausgewertet". Die Zeilen unten sind echte Ausgaben vom
// 27.11.2026 (cl 19.52.37029 deutsch, clang-tidy 22.1.3), nur der Ordner davor ist gekürzt (D:\c\ statt des Messordners).

// cl /analyze, C-Aufruf über drei Dateien (eine im Ordner "Bäre", eine mit fehlender Kopfdatei); Umlaute kommen als \uFFFD an.
const CL_C_ECHT = [
  'probe.c',
  'D:\\c\\probe.c(9) : warning C6201: Der Index "10" liegt f\uFFFDr den m\uFFFDglicherweise stapelzugeordneten Puffer "buf" au\uFFFDerhalb des g\uFFFDltigen Indexbereichs von "0" bis "9".',
  'D:\\c\\probe.c(9) : warning C6385: Lesen ung\uFFFDltiger Daten von "buf":  die lesbare Gr\uFFFD\uFFFDe betr\uFFFDgt "40" Byte, es k\uFFFDnnen jedoch "44" Byte gelesen werden.: Lines: 7, 8, 9',
  'D:\\c\\probe.c(15) : warning C6001: Nicht initialisierter Speicher "x" wird verwendet.: Lines: 14, 15',
  'D:\\c\\probe.c(21) : warning C6011: Dereferenzierender NULL-Zeiger "p". : Lines: 20, 21',
  'D:\\c\\probe.c(30) : warning C6001: Nicht initialisierter Speicher "p" wird verwendet.: Lines: 27, 28, 29, 30',
  'probe_umlaut.c',
  'D:\\c\\B\uFFFDre\\probe_umlaut.c(9) : warning C6201: Der Index "10" liegt f\uFFFDr den m\uFFFDglicherweise stapelzugeordneten Puffer "buf" au\uFFFDerhalb des g\uFFFDltigen Indexbereichs von "0" bis "9".',
  'D:\\c\\B\uFFFDre\\probe_umlaut.c(21) : warning C6011: Dereferenzierender NULL-Zeiger "p". : Lines: 20, 21',
  'fehlt.c',
  'D:\\c\\fehlt.c(1): fatal error C1083: Datei (Include) kann nicht ge\uFFFDffnet werden: "fehlt_nicht_da.h": No such file or directory',
  '',
].join('\r\n')
const C_DATEIEN = ['D:\\c\\probe.c', 'D:\\c\\Bäre\\probe_umlaut.c', 'D:\\c\\fehlt.c']

// SARIF von cl (Aufbau wie gemessen: ein "run" je Quelldatei, Adressen klein geschrieben, Umlaute und Leerzeichen roh), gekürzt.
// Das dritte Ergebnis liegt in einer Kopfdatei des Windows-SDK (Artefakt 1) - gebildet nach dem gemessenen Aufbau.
const SARIF_ECHT = JSON.stringify({
  version: '2.1.0',
  runs: [{
    results: [
      { ruleId: 'C6201', message: { text: 'Der Index "10" liegt für den möglicherweise stapelzugeordneten Puffer "buf" außerhalb des gültigen Indexbereichs von "0" bis "9".' },
        locations: [{ physicalLocation: { artifactLocation: { index: 0 }, region: { startLine: 9, startColumn: 12, endLine: 9, endColumn: 16 } } }] },
      { ruleId: 'C6385', message: { text: 'Lesen ungültiger Daten von "buf":  die lesbare Größe beträgt "40" Byte, es können jedoch "44" Byte gelesen werden.' },
        locations: [{ physicalLocation: { artifactLocation: { index: 0 }, region: { startLine: 9, startColumn: 5, endLine: 9, endColumn: 16 } } }] },
      { ruleId: 'C6001', message: { text: 'Nicht initialisierter Speicher "_Expr_val" wird verwendet.' },
        locations: [{ physicalLocation: { artifactLocation: { index: 1 }, region: { startLine: 52, startColumn: 9 } } }] },
    ],
    tool: { driver: { name: 'PREfast', fullName: 'MSVC Code Analysis', version: '14.52.37029.0' } },
    invocations: [{ executionSuccessful: true }],
    artifacts: [
      { location: { uri: 'file:///d:/c/bäre/probe_umlaut.c' }, roles: ['analysisTarget', 'resultFile'] },
      { location: { uri: 'file:///c:/program files (x86)/windows kits/10/include/10.0.26100.0/ucrt/corecrt_memcpy_s.h' }, roles: ['resultFile'] },
    ],
  }],
})

// clang-tidy über probe.c, probe_umlaut.c, probe2.cpp, fehlt.c und uninit.c (stdout, Hinweise und Ausschnitte gekürzt) und stderr.
const TIDY_ECHT = [
  "D:\\c\\Bäre\\probe_umlaut.c:15:14: warning: The left operand of '+' is a garbage value [clang-analyzer-core.UndefinedBinaryOperatorResult]",
  '   15 |     return x + 1;',
  '      |              ^',
  "D:\\c\\Bäre\\probe_umlaut.c:53:9: note: Assuming 'argc' is <= 1",
  'D:\\c\\probe.c:30:10: warning: Use of memory after it is released [clang-analyzer-unix.Malloc]',
  'D:\\c\\probe.c:27:23: note: Memory is allocated',
  "D:\\c\\probe.c:36:5: warning: Call to function 'memcpy' is insecure as it does not provide security checks introduced in the C11 standard. Replace with analogous functions that support length arguments or provides boundary checks such as 'memcpy_s' in case of C11 [clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling]",
  "D:\\c\\probe.c:36:5: warning: the result from calling 'memcpy' is not null-terminated [bugprone-not-null-terminated-result]",
  "D:\\c\\probe.c:37:5: warning: Call to function 'strcpy' is insecure as it does not provide bounding of the memory buffer. Replace unbounded copy functions with analogous functions that support length arguments such as 'strlcpy'. CWE-119 [clang-analyzer-security.insecureAPI.strcpy]",
  "D:\\c\\probe2.cpp:6:5: warning: Out of bound access to memory after the end of 'a' [clang-analyzer-security.ArrayBound]",
  'D:\\c\\probe2.cpp:13:8: warning: Use of memory after it is released [clang-analyzer-cplusplus.NewDelete]',
  "D:\\c\\fehlt.c:1:10: error: 'fehlt_nicht_da.h' file not found [clang-diagnostic-error]",
  'D:\\c\\uninit.c:4:5: warning: Assigned value is uninitialized [clang-analyzer-core.uninitialized.Assign]',
  "D:\\c\\uninit.c:7:18: warning: declaration uses identifier '_binding_language', which is reserved in the global namespace [bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp]",
  '',
  '[1/5] Processing file D:\\c\\probe.c.',
  'Error while processing D:\\c\\fehlt.c.',
].join('\n')
const TIDY_DATEIEN = ['D:\\c\\probe.c', 'D:\\c\\Bäre\\probe_umlaut.c', 'D:\\c\\probe2.cpp', 'D:\\c\\fehlt.c', 'D:\\c\\uninit.c']

const sieh = (funde: { code: string; schwer: boolean; line: number }[]) => funde.map(f => `${f.code}${f.schwer ? '!' : ''}@${f.line}`)

test('MSVC-Leser: echte deutsche Zeilen - C6385/C6201/C6001 rot, C6011 Hinweis, kaputte Umlaute im Pfad, fehlende Kopfdatei ist Lücke', () => {
  const l = msvcAnalyseLesen(CL_C_ECHT, C_DATEIEN)
  expect(l.fehler).toBe(undefined)
  expect(l.fehlend).toEqual([])
  expect(sieh(l.jeDatei.get('D:\\c\\probe.c')?.funde ?? [])).toEqual(['C6201!@9', 'C6385!@9', 'C6001!@15', 'C6011@21', 'C6001!@30'])
  expect(sieh(l.jeDatei.get('D:\\c\\Bäre\\probe_umlaut.c')?.funde ?? [])).toEqual(['C6201!@9', 'C6011@21'])
  // "Lines: 7, 8, 9" (Ablauf) gehört nicht in den Text
  expect(l.jeDatei.get('D:\\c\\probe.c')?.funde[1]?.text).toBe('Lesen ung\uFFFDltiger Daten von "buf": die lesbare Gr\uFFFD\uFFFDe betr\uFFFDgt "40" Byte, es k\uFFFDnnen jedoch "44" Byte gelesen werden.')
  expect(l.jeDatei.get('D:\\c\\fehlt.c')?.funde).toEqual([])
  expect(l.jeDatei.get('D:\\c\\fehlt.c')?.unvollstaendig.join(' ')).toContain('C1083')
  expect(l.jeDatei.get('D:\\c\\probe.c')?.unvollstaendig).toEqual([])
})

test('MSVC-Leser: Funde kommen aus dem SARIF (Umlaute heil, mit Spalte); ein Fund in einer fremden Kopfdatei zählt nicht; SARIF kaputt: Konsole', () => {
  const datei = ['D:\\c\\Bäre\\probe_umlaut.c']
  const l = msvcAnalyseLesen('probe_umlaut.c\r\nD:\\c\\B\uFFFDre\\probe_umlaut.c(9) : warning C6201: Der Index "10" liegt f\uFFFDr den ...\r\n', datei, SARIF_ECHT)
  const funde = l.jeDatei.get(datei[0])?.funde ?? []
  expect(funde.map(f => [f.line, f.col, f.code, f.schwer])).toEqual([[9, 12, 'C6201', true], [9, 5, 'C6385', true]])
  expect(funde[0]?.text).toContain('liegt für den möglicherweise')
  const kaputt = msvcAnalyseLesen('probe_umlaut.c\r\nD:\\c\\B\uFFFDre\\probe_umlaut.c(9) : warning C6201: Der Index\r\n', datei, '{"runs": ')
  expect(sieh(kaputt.jeDatei.get(datei[0])?.funde ?? [])).toEqual(['C6201!@9'])
})

test('MSVC-Leser: Befehlszeilenfehler ist ein Fehler des Laufs; Fehler in einer eingebundenen Datei zeigt deren Text nicht; nicht gemeldete Datei', () => {
  // gemessen 27.11.2026 (stderr)
  expect(msvcAnalyseLesen('cl : Befehlszeile error D8016 : Die Befehlszeilenoptionen /std:c17 und /std:c++latest sind inkompatibel.', ['D:\\c\\a.c']).fehler).toContain('D8016')
  const l = msvcAnalyseLesen('a.c\r\nD:\\fremd\\geheim.h(3): error C2146: Syntaxfehler: Fehlendes ";" vor Bezeichner "Kennwort123"\r\n', ['D:\\c\\a.c', 'D:\\c\\b.c'])
  expect(l.jeDatei.get('D:\\c\\a.c')?.unvollstaendig).toEqual(['C2146 in einer eingebundenen Datei'])
  expect(l.fehlend).toEqual(['D:\\c\\b.c'])
  // Quelldatei nicht lesbar (gemessen): "c1:" ohne Zeile gehört zur Datei, die cl gerade übersetzt
  const c1 = msvcAnalyseLesen('nichtda.c\r\nc1: fatal error C1083: Datei (Quelle) kann nicht ge\uFFFDffnet werden: "D:\\c\\nichtda.c": No such file or directory\r\n', ['D:\\c\\nichtda.c'])
  expect(c1.jeDatei.get('D:\\c\\nichtda.c')?.unvollstaendig.join(' ')).toContain('C1083')
})

test('clang-tidy-Leser: echte Zeilen - ArrayBound, unix.Malloc, NewDelete, core.uninitialized rot, der Rest Hinweis; Fehler ist Lücke', () => {
  const l = clangTidyLesen(TIDY_ECHT, TIDY_DATEIEN)
  expect(l.fehler).toBe(undefined)
  expect(sieh(l.jeDatei.get('D:\\c\\probe.c')?.funde ?? [])).toEqual([
    'clang-analyzer-unix.Malloc!@30', 'clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling@36', 'bugprone-not-null-terminated-result@36',
    'clang-analyzer-security.insecureAPI.strcpy@37',
  ])
  expect(sieh(l.jeDatei.get('D:\\c\\Bäre\\probe_umlaut.c')?.funde ?? [])).toEqual(['clang-analyzer-core.UndefinedBinaryOperatorResult@15'])
  expect(sieh(l.jeDatei.get('D:\\c\\probe2.cpp')?.funde ?? [])).toEqual(['clang-analyzer-security.ArrayBound!@6', 'clang-analyzer-cplusplus.NewDelete!@13'])
  // mehrere Namen für einen Fund: der erste ist die Nummer
  expect(sieh(l.jeDatei.get('D:\\c\\uninit.c')?.funde ?? [])).toEqual(['clang-analyzer-core.uninitialized.Assign!@4', 'bugprone-reserved-identifier@7'])
  expect(l.jeDatei.get('D:\\c\\probe.c')?.funde[0]?.col).toBe(10)
  expect(l.jeDatei.get('D:\\c\\fehlt.c')?.funde).toEqual([])
  expect(l.jeDatei.get('D:\\c\\fehlt.c')?.unvollstaendig).toEqual(["'fehlt_nicht_da.h' file not found"])
  // Datei fehlt (gemessen): Fehler ohne Ort und "Error while processing" - eine Lücke der Datei, kein Fehler des ganzen Laufs
  const weg = clangTidyLesen("error: no such file or directory: 'D:\\c\\nichtda.c' [clang-diagnostic-error]\nError while processing D:\\c\\nichtda.c.\n", ['D:\\c\\uninit.c', 'D:\\c\\nichtda.c'])
  expect(weg.fehler).toBe(undefined)
  expect(weg.jeDatei.get('D:\\c\\nichtda.c')?.unvollstaendig.length).toBe(1)
  expect(weg.jeDatei.get('D:\\c\\uninit.c')?.unvollstaendig).toEqual([])
})

test('clang-tidy-Leser: nach dem ersten Fehler schreibt clang-tidy für jede weitere Datei "Error while processing" - Lücke nur mit eigenem Fehler', () => {
  // echte Ausgabe vom 27.11.2026 (fehlt.c zuerst, danach probe.c und uninit.c; Hinweise und Ausschnitte gekürzt)
  const text = [
    "D:\\c\\fehlt.c:1:10: error: 'fehlt_nicht_da.h' file not found [clang-diagnostic-error]",
    'D:\\c\\probe.c:30:10: warning: Use of memory after it is released [clang-analyzer-unix.Malloc]',
    'D:\\c\\uninit.c:4:5: warning: Assigned value is uninitialized [clang-analyzer-core.uninitialized.Assign]',
    '[1/3] Processing file D:\\c\\fehlt.c.',
    'Error while processing D:\\c\\fehlt.c.',
    '[2/3] Processing file D:\\c\\probe.c.',
    'Error while processing D:\\c\\probe.c.',
    '[3/3] Processing file D:\\c\\uninit.c.',
    'Error while processing D:\\c\\uninit.c.',
  ].join('\n')
  const l = clangTidyLesen(text, ['D:\\c\\fehlt.c', 'D:\\c\\probe.c', 'D:\\c\\uninit.c'])
  expect(l.jeDatei.get('D:\\c\\fehlt.c')?.unvollstaendig).toEqual(["'fehlt_nicht_da.h' file not found"])
  expect(l.jeDatei.get('D:\\c\\probe.c')?.unvollstaendig).toEqual([])
  expect(l.jeDatei.get('D:\\c\\uninit.c')?.unvollstaendig).toEqual([])
  // Fehler in einer eingebundenen fremden Datei (Zeile im gemessenen Format gebildet): die Datei bleibt offen, der fremde Text nicht gezeigt
  const fremd = clangTidyLesen("D:\\fremd\\geheim.h:3:1: error: unknown type name 'Kennwort123' [clang-diagnostic-error]\nError while processing D:\\c\\a.c.\n", ['D:\\c\\a.c'])
  expect(fremd.jeDatei.get('D:\\c\\a.c')?.unvollstaendig).toEqual(['nicht übersetzbar (Fehler in einer eingebundenen Datei oder ohne Ort)'])
  expect(JSON.stringify(fremd.jeDatei.get('D:\\c\\a.c'))).not.toContain('Kennwort123')
})

test('Pfade: kaputte Umlaute finden die Datei, clang-tidy liegt neben cl.exe im selben Visual Studio', () => {
  expect(zuDatei('D:\\c\\B\uFFFDre\\a.c', ['D:\\c\\Kiste\\a.c', 'D:\\c\\Bäre\\a.c'])).toBe('D:\\c\\Bäre\\a.c')
  expect(zuDatei('d:/c/bäre/a.c', ['D:\\c\\Bäre\\a.c'])).toBe('D:\\c\\Bäre\\a.c')
  expect(zuDatei('D:\\c\\b.c', ['D:\\c\\a.c'])).toBe(undefined)
  // Orte aus dem Auftrag: VS = C:\Program Files\Microsoft Visual Studio\18\Community, clang-tidy = VS\VC\Tools\Llvm\x64\bin\clang-tidy.exe
  expect(clangTidyNeben('C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\MSVC\\14.52.37025\\bin\\Hostx64\\x64\\cl.exe'))
    .toBe('C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\Llvm\\x64\\bin\\clang-tidy.exe')
  expect(clangTidyNeben('C:\\anderswo\\cl.exe')).toBe(undefined)
})

// ---- Gespielte Programme
const ARBEIT = 'C:\\Temp\\code-waechter'
const CL = 'C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\MSVC\\14.52.37025\\bin\\Hostx64\\x64\\cl.exe'
const TIDY = 'C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\Llvm\\x64\\bin\\clang-tidy.exe'
const WERKZEUGE: CWerkzeuge = { cl: { cl: CL, include: 'C:\\VS\\include;C:\\Kits\\ucrt' }, clangTidy: TIDY }
const ok = (stdout: string, exitCode = 0, stderr = ''): Lauf => ({ ok: true, exitCode, stdout, stderr, truncated: false })
const istCl = (argv: string[]) => argv[0] === CL
const istTidy = (argv: string[]) => argv[0] === TIDY
const protokoll = (argv: string[]) => argv.find(a => a.startsWith('/analyze:log') && !a.startsWith('/analyze:log:'))?.slice(12) ?? ''

function umgebung(werkzeuge: () => Promise<CWerkzeuge>, antwort: (argv: string[], dateien: Record<string, string>) => Lauf, dateien: Record<string, string> = {}) {
  const aufrufe: { argv: string[]; cwd?: string; env?: Record<string, string>; timeoutMs?: number }[] = []
  const u: Umgebung = {
    run: async (argv, opts) => {
      aufrufe.push({ argv, ...opts })
      return antwort(argv, dateien)
    },
    python: ['py'],
    // DevSkim, Cppcheck und Gitleaks fehlen hier: es laufen nur die eigenen Muster und die C/C++-Analyse.
    exe: async () => undefined,
    workDir: async () => ARBEIT,
    read: async p => dateien[p],
    write: async (p, text) => {
      dateien[p] = text
    },
    kennung: 'chat:1',
    cAnalyse: werkzeuge,
  }
  return { u, aufrufe, dateien }
}

test('Scannen: C-Datei - cl /analyze mit SARIF im Arbeitsordner, clang-tidy ohne Projekt-Einstellungen; Funde, Einstufung, lief', async () => {
  const { u, aufrufe } = umgebung(async () => WERKZEUGE, (argv, d) => {
    if (istCl(argv)) {
      d[protokoll(argv)] = SARIF_ECHT.replace('file:///d:/c/bäre/probe_umlaut.c', 'file:///d:/c/probe.c')
      return ok('probe.c\r\nD:\\c\\probe.c(9) : warning C6201: Der Index "10" liegt f\uFFFDr den ...\r\n')
    }
    if (istTidy(argv)) return ok('D:\\c\\probe.c:30:10: warning: Use of memory after it is released [clang-analyzer-unix.Malloc]\n')
    return ok('')
  })
  const e = await scannen(u, 'D:\\c\\probe.c', 'int main(void) { return 0; }\n')
  expect(e.funde.filter(f => f.scanner !== 'Muster').map(f => `${f.scanner}:${f.code}${f.schwer ? '!' : ''}@${f.line}`))
    .toEqual(['MSVC /analyze:C6385!@9', 'MSVC /analyze:C6201!@9', 'clang-tidy:clang-analyzer-unix.Malloc!@30'])
  expect(e.liefen).toContain('MSVC /analyze')
  expect(e.liefen).toContain('clang-tidy')
  expect(e.luecken.join(' | ')).not.toContain('MSVC /analyze')
  expect(e.luecken.join(' | ')).not.toContain('clang-tidy')
  const cl = aufrufe.find(a => istCl(a.argv))
  // Schalter laut learn.microsoft.com/cpp/build/reference/analyze-code-analysis; nichts im Projektordner
  for (const s of ['/analyze', '/analyze:only', '/analyze:log:format:sarif', '/std:c17', '/nologo', '/c']) expect(cl?.argv).toContain(s)
  expect(protokoll(cl?.argv ?? [])).toBe('C:\\Temp\\code-waechter\\msvc-chat_1-0.sarif')
  expect(cl?.argv.some(a => /EspXEngine/i.test(a))).toBe(false)
  expect(cl?.argv[cl.argv.length - 1]).toBe('D:\\c\\probe.c')
  expect(cl?.cwd).toBe(ARBEIT)
  expect(cl?.env?.INCLUDE).toBe('C:\\VS\\include;C:\\Kits\\ucrt')
  expect(cl?.env?.VSLANG).toBe('1031')
  const ct = aufrufe.find(a => istTidy(a.argv))
  // Prüfungen aus dem Bauplan; --config statt .clang-tidy des Projekts, "--" statt compile_commands.json (gemessen: sonst gelesen)
  expect(ct?.argv).toContain("--config={Checks: '-*,clang-analyzer-*,bugprone-*,cert-*'}")
  expect(ct?.argv).toContain('--header-filter=^$')
  expect(ct?.argv.slice(-2)).toEqual(['D:\\c\\probe.c', '--'])
  expect(ct?.argv.some(a => a.includes('xc++'))).toBe(false)
  expect(ct?.cwd).toBe(ARBEIT)
  expect(ct?.env?.INCLUDE).toBe('C:\\VS\\include;C:\\Kits\\ucrt')
  for (const a of aufrufe) expect(Number.isInteger(a.timeoutMs) && (a.timeoutMs ?? 0) > 0 && (a.timeoutMs ?? 0) <= 600000).toBe(true)
})

test('Scannen: Kopfdatei läuft bei cl als C++ mit /Tp, bei clang-tidy mit -xc++', async () => {
  const { u, aufrufe } = umgebung(async () => WERKZEUGE, argv => (istCl(argv) ? ok('kopf.hpp\r\n') : ok('')))
  const e = await scannen(u, 'D:\\c\\kopf.hpp', 'class A {};\n')
  const cl = aufrufe.find(a => istCl(a.argv))?.argv ?? []
  expect(cl.slice(-2)).toEqual(['/Tp', 'D:\\c\\kopf.hpp'])
  expect(cl).toContain('/std:c++latest')
  expect(cl).toContain('/EHsc')
  expect(cl).not.toContain('/std:c17')
  expect(aufrufe.find(a => istTidy(a.argv))?.argv).toContain('--extra-arg-before=-xc++')
  expect(e.liefen).toContain('MSVC /analyze')
  expect(e.liefen).toContain('clang-tidy')
})

test('Scannen: fehlende Kopfdatei ist bei beiden eine Lücke "nicht ganz ausgewertet", kein Fund, kein "lief"', async () => {
  const { u } = umgebung(async () => WERKZEUGE, argv => {
    if (istCl(argv)) return ok('fehlt.c\r\nD:\\c\\fehlt.c(1): fatal error C1083: Datei (Include) kann nicht ge\uFFFDffnet werden: "fehlt_nicht_da.h": No such file or directory\r\n', 2)
    if (istTidy(argv)) return ok("D:\\c\\fehlt.c:1:10: error: 'fehlt_nicht_da.h' file not found [clang-diagnostic-error]\n", 1, 'Error while processing D:\\c\\fehlt.c.\nFound compiler error(s).\n')
    return ok('')
  })
  const e = await scannen(u, 'D:\\c\\fehlt.c', '#include "fehlt_nicht_da.h"\n')
  expect(e.funde.filter(f => f.scanner !== 'Muster')).toEqual([])
  expect(e.luecken.join(' | ')).toContain('MSVC /analyze lief nicht: nicht ganz ausgewertet - «C1083')
  expect(e.luecken.join(' | ')).toContain("clang-tidy lief nicht: nicht ganz ausgewertet - «'fehlt_nicht_da.h' file not found»")
  expect(e.liefen).not.toContain('MSVC /analyze')
  expect(e.liefen).not.toContain('clang-tidy')
})

test('Scannen: fehlendes Programm, Absturz, Startfehler und Fehler der Umgebung stehen offen, nie als geprüft', async () => {
  const keins = umgebung(async () => ({}), () => ok(''))
  const e1 = await scannen(keins.u, 'D:\\c\\a.c', 'int x;\n')
  expect(e1.luecken).toContain('MSVC /analyze fehlt (einmalig: Visual Studio Installer, eine C++-Arbeitsauslastung wählen)')
  expect(e1.luecken).toContain('clang-tidy fehlt (einmalig: Visual Studio Installer, eine C++-Arbeitsauslastung wählen)')
  expect(keins.aufrufe).toEqual([])
  // Absturz ohne Ausgabe (Code einer Zugriffsverletzung) und ein Programm, das nicht startet
  const absturz = umgebung(async () => WERKZEUGE, argv => (istCl(argv) ? ok('', -1073741819) : { ok: false, reason: 'Prozess nicht startbar' }))
  const e2 = await scannen(absturz.u, 'D:\\c\\a.c', 'int x;\n')
  expect(e2.luecken.join(' | ')).toContain('MSVC /analyze lief nicht: Code -1073741819')
  expect(e2.luecken.join(' | ')).toContain('clang-tidy lief nicht: Prozess nicht startbar')
  expect(e2.liefen).not.toContain('MSVC /analyze')
  expect(e2.liefen).not.toContain('clang-tidy')
  // Die Mod kann die Programme nicht suchen (Fehler der Umgebung)
  const kaputt = umgebung(async () => {
    throw new Error('fs.list verweigert')
  }, () => ok(''))
  const e3 = await scannen(kaputt.u, 'D:\\c\\a.c', 'int x;\n')
  expect(e3.luecken.join(' | ')).toContain('C/C++-Analyse lief nicht: fs.list verweigert')
  // cl meldet die Datei nicht (Ausgabe ohne ihren Namen): nicht ausgewertet
  const still = umgebung(async () => WERKZEUGE, () => ok(''))
  const e4 = await scannen(still.u, 'D:\\c\\a.c', 'int x;\n')
  expect(e4.luecken.join(' | ')).toContain('MSVC /analyze lief nicht: Datei nicht ausgewertet')
  expect(e4.liefen).toContain('clang-tidy')
})

test('Ordner-Scan: je Sprache ein cl-Aufruf, je Gruppe ein clang-tidy-Aufruf über alle Dateien; Funde an die richtige Datei; Zeitgrenze offen', async () => {
  const quelle: Record<string, string> = {
    'D:\\p\\a.c': 'int a;\n', 'D:\\p\\Bäre\\b.c': 'int b;\n', 'D:\\p\\c.cpp': 'int c;\n', 'D:\\p\\k.hpp': 'int k;\n', 'D:\\p\\x.cs': 'class X { }\n',
  }
  const dateien = { ...quelle }
  const { u, aufrufe } = umgebung(async () => WERKZEUGE, argv => {
    if (istCl(argv) && argv.includes('/std:c17')) return ok('a.c\r\nb.c\r\nD:\\p\\B\uFFFDre\\b.c(4) : warning C6386: Puffer\uFFFDberlauf beim Schreiben nach "a": ...: Lines: 3, 4\r\n')
    if (istCl(argv)) return ok('c.cpp\r\nk.hpp\r\nD:\\p\\k.hpp(2) : warning C6011: Dereferenzierender NULL-Zeiger "p". : Lines: 1, 2\r\n')
    if (istTidy(argv) && argv.includes('--extra-arg-before=-xc++')) return ok('')
    if (istTidy(argv)) return ok("D:\\p\\c.cpp:6:5: warning: Out of bound access to memory after the end of 'a' [clang-analyzer-security.ArrayBound]\n")
    return ok('')
  }, dateien)
  const erg = await scannenOrdner(u, Object.keys(quelle), { restMs: 60000 })
  const s = (f: string) => (erg.get(f)?.funde ?? []).filter(x => x.scanner !== 'Muster').map(x => `${x.scanner}:${x.code}${x.schwer ? '!' : ''}@${x.line}`)
  expect(s('D:\\p\\a.c')).toEqual([])
  expect(s('D:\\p\\Bäre\\b.c')).toEqual(['MSVC /analyze:C6386!@4'])
  expect(s('D:\\p\\c.cpp')).toEqual(['clang-tidy:clang-analyzer-security.ArrayBound!@6'])
  expect(s('D:\\p\\k.hpp')).toEqual(['MSVC /analyze:C6011@2'])
  for (const f of ['D:\\p\\a.c', 'D:\\p\\Bäre\\b.c', 'D:\\p\\c.cpp', 'D:\\p\\k.hpp']) {
    expect(erg.get(f)?.liefen).toContain('MSVC /analyze')
    expect(erg.get(f)?.liefen).toContain('clang-tidy')
  }
  expect(erg.get('D:\\p\\x.cs')?.liefen).not.toContain('MSVC /analyze')
  const cl = aufrufe.filter(a => istCl(a.argv))
  expect(cl.length).toBe(2)
  expect(cl[0]?.argv.slice(-2)).toEqual(['D:\\p\\a.c', 'D:\\p\\Bäre\\b.c'])
  expect(cl[1]?.argv.slice(-3)).toEqual(['D:\\p\\c.cpp', '/Tp', 'D:\\p\\k.hpp'])
  expect(protokoll(cl[0]?.argv ?? [])).toBe('C:\\Temp\\code-waechter\\msvc-chat_1-ordner-0.sarif')
  const ct = aufrufe.filter(a => istTidy(a.argv))
  expect(ct.length).toBe(2)
  expect(ct[0]?.argv.slice(-4)).toEqual(['D:\\p\\a.c', 'D:\\p\\Bäre\\b.c', 'D:\\p\\c.cpp', '--'])
  expect(ct[1]?.argv.slice(-2)).toEqual(['D:\\p\\k.hpp', '--'])
  // Keine Zeit mehr: kein Programm startet, jede C/C++-Datei nennt die Zeitgrenze
  const spaet = umgebung(async () => WERKZEUGE, () => ok(''), { ...quelle })
  const e = await scannenOrdner(spaet.u, Object.keys(quelle), { restMs: 0 })
  expect(spaet.aufrufe.filter(a => istCl(a.argv) || istTidy(a.argv)).length).toBe(0)
  expect(e.get('D:\\p\\a.c')?.luecken).toContain('MSVC /analyze: Zeitgrenze des Scans erreicht')
  expect(e.get('D:\\p\\k.hpp')?.luecken).toContain('clang-tidy: Zeitgrenze des Scans erreicht')
})

test('cAnalyse: Umgebung ohne C/C++-Analyse liefert nichts; doppelte Funde (Kopfdatei aus zwei Aufrufen) nur einmal', async () => {
  const { u } = umgebung(async () => WERKZEUGE, () => ok(''))
  const ohne: Umgebung = { ...u, cAnalyse: undefined }
  const leer = await cAnalyse(ohne, ['D:\\c\\a.c'], async () => 60000)
  expect(leer.get('D:\\c\\a.c')).toEqual({ funde: [], luecken: [], liefen: [] })
  const doppelt = umgebung(async () => WERKZEUGE, argv =>
    (istCl(argv) ? ok('k.hpp\r\nD:\\c\\k.hpp(2) : warning C6201: Index\r\nD:\\c\\k.hpp(2) : warning C6201: Index\r\n') : ok('')))
  const d = await cAnalyse(doppelt.u, ['D:\\c\\k.hpp'], async () => 60000)
  expect(sieh(d.get('D:\\c\\k.hpp')?.funde ?? [])).toEqual(['C6201!@2'])
})

// Gegenprüfung 28.11.2026: ein C-Kopf (cKopf, Regel der Übersetzungsprüfung) läuft als C - als C++ bekam ein gültiger C-Kopf Fehler.
test('Scannen: C-Kopfdatei (cKopf) läuft bei cl als C mit /Tc und C17, bei clang-tidy mit -xc; ohne Antwort weiter als C++', async () => {
  const mitC = umgebung(async () => ({ ...WERKZEUGE, cKopf: async (f: string) => f.endsWith('k.h') }), argv => (istCl(argv) ? ok('k.h\r\n') : ok('')))
  await scannen(mitC.u, 'D:\\c\\k.h', 'int summe(int * restrict a, int n);\n')
  const cl = mitC.aufrufe.find(a => istCl(a.argv))?.argv ?? []
  expect(cl.slice(-2)).toEqual(['/Tc', 'D:\\c\\k.h'])
  expect(cl).toContain('/std:c17')
  expect(cl).not.toContain('/std:c++latest')
  const tidy = mitC.aufrufe.find(a => istTidy(a.argv))?.argv ?? []
  expect(tidy).toContain('--extra-arg-before=-xc')
  expect(tidy).not.toContain('--extra-arg-before=-xc++')
  // Die Abfrage scheitert (Ordner nicht lesbar): wie ohne cKopf als C++
  const kaputt = umgebung(async () => ({ ...WERKZEUGE, cKopf: async () => { throw new Error('Ordner nicht lesbar') } }), argv => (istCl(argv) ? ok('k.h\r\n') : ok('')))
  await scannen(kaputt.u, 'D:\\c\\k.h', 'int x;\n')
  expect((kaputt.aufrufe.find(a => istCl(a.argv))?.argv ?? []).slice(-2)).toEqual(['/Tp', 'D:\\c\\k.h'])
  expect(kaputt.aufrufe.find(a => istTidy(a.argv))?.argv).toContain('--extra-arg-before=-xc++')
})
