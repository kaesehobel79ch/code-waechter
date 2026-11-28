// C/C++-Codeanalyse als zusätzliche Sicherheits-Scanner (27.11.2026, Bauplan "Höchstes Niveau"): cl.exe /analyze (Microsoft-Codeanalyse, PREfast) und clang-tidy, beide aus Visual Studio.
//
// Gemessen 27.11.2026 (cl 19.52.37029 aus VS 18 Community, MSVC 14.52.37025; clang-tidy 22.1.3 aus VS\VC\Tools\Llvm\x64\bin) an
// Probedateien mit eingebauten Fehlern:
//   cl /analyze fand C6201/C6385 (Index bzw. Lesen über den Puffer), C6386 (Schreiben über den Puffer), C6001 (uninitialisiert, auch
//   Zugriff nach free/delete) und C6011 (Nullzeiger nach malloc). Mit /analyze:plugin EspXEngine.dll (Bauplan) kamen in C++ nur
//   Warnungen der C++ Core Guidelines dazu (C26400-C26497, 40 davon in Kopfdateien des Windows-SDK), in C und C++ kein weiterer
//   Speicherfehler, und es dauerte länger (C++: 347 statt 193 ms) - darum ohne Plugin.
//   clang-tidy fand clang-analyzer-security.ArrayBound, clang-analyzer-unix.Malloc (Zugriff nach free), clang-analyzer-cplusplus.NewDelete
//   (Zugriff nach delete) sowie memcpy-/strcpy-Hinweise.
//
// Schalter von cl (learn.microsoft.com/cpp/build/reference/analyze-code-analysis, gelesen 27.11.2026):
//   /analyze:only   keine Codeerzeugung (gemessen: keine .obj, keine andere neue Datei ausser dem Protokoll)
//   /analyze:log:format:sarif mit /analyze:log<Datei>   Protokoll als SARIF in den Arbeitsordner der Mod. Ohne /analyze:log legt cl
//                   <name>.nativecodeanalysis.xml in den aktuellen Ordner (gemessen). SARIF ist UTF-8: Texte und Pfade mit Umlauten
//                   stimmen; auf der Konsole schreibt cl im Windows-Zeichensatz ("f�r", "B�re", gemessen). Die Funde kommen darum aus
//                   dem SARIF, Übersetzungsfehler (die stehen nicht im SARIF) von der Konsole.
//   /std:c17 und /std:c++latest zusammen lehnt cl ab (D8016, gemessen): C und C++ laufen in je einem Aufruf.
//   VSLANG wählt die Sprache der Meldungen (gemessen: 1031 deutsch, 1033 englisch, auch im SARIF).
// Schalter von clang-tidy (clang-tidy --help, 22.1.3):
//   --config=...    statt einer .clang-tidy des Projekts, "--" statt compile_commands.json. Gemessen: ohne beides las clang-tidy
//                   ExtraArgs aus .clang-tidy und den Befehl aus compile_commands.json im Projektordner - darüber könnte ein Projekt ein
//                   Compiler-Plugin laden (Sicherheitsregel S02: nichts aus einem fremden Projekt ausführen). Mit beidem nicht.
//   --header-filter=^$   nur Funde der geprüften Datei selbst (gemessen mit Python.h: 6 statt 495 Warnungen, 489 in fremden Köpfen)
//   Kopfdateien laufen als C++ (--extra-arg-before=-xc++) in einem eigenen Aufruf, wie bei Cppcheck. Seit 28.11.2026 (Gegenprüfung):
//   eine .h neben reinen C-Dateien (cKopf, gleiche Regel wie die Übersetzungsprüfung in register.tsx) läuft als C - bei cl mit /Tc
//   im C-Aufruf, bei clang-tidy mit -xc in einem eigenen Aufruf; als C++ gelesen bekam ein gültiger C-Kopf sonst Fehler (restrict).
//
// Rot (schwer) sind nur sichere Speicherfehler: C6385, C6386, C6200, C6201, C6001; clang-analyzer-security.ArrayBound,
// clang-analyzer-unix.Malloc, clang-analyzer-cplusplus.NewDelete, clang-analyzer-core.uninitialized.*. Alles andere ist ein Hinweis
// (auch C6011 Nullzeiger). Übersetzungsfehler (fehlende Kopfdatei C1083, clang-diagnostic-error) sind kein Fund, sondern "nicht ganz
// ausgewertet". Bewusste Stellen: #pragma warning(suppress: 6385) bei cl, // NOLINT(prüfung) bei clang-tidy - beide beachten das selbst.
// Beide Programme laufen mit vollem Pfad im Arbeitsordner der Mod, nie im Projektordner, und führen keinen Code des Projekts aus.

import { getLang, t } from './i18n'
import { GITLEAKS_VORHER, KOPF, daten, rein } from './sicherheit'
import type { Ergebnis, SFund, Umgebung } from './sicherheit'

// Was die Mod für die Analyse findet, je mit vollem Pfad; undefined = nicht da. include: die Kopfdatei-Ordner von Visual Studio und
// Windows-SDK (wie bei der Übersetzungsprüfung mit cl.exe), für clang-tidy dieselben.
// cKopf: ist diese .h ein C-Kopf (Ordner mit .c- und ohne C++-Dateien)? Fehlt es, laufen alle Kopfdateien als C++.
export type CWerkzeuge = { cl?: { cl: string; include: string }; clangTidy?: string; cKopf?: (file: string) => Promise<boolean> }

export type CAuswertung = { funde: SFund[]; unvollstaendig: string[] }
// fehlend: Dateien, die cl gar nicht gemeldet hat (nicht übersetzt); fehler: das Programm lief als Ganzes nicht richtig.
export type CLesung = { jeDatei: Map<string, CAuswertung>; fehlend: string[]; fehler?: string }

export const MSVC_ROT = new Set(['C6385', 'C6386', 'C6200', 'C6201', 'C6001'])
export const CLANG_ROT = new Set(['clang-analyzer-security.ArrayBound', 'clang-analyzer-unix.Malloc', 'clang-analyzer-cplusplus.NewDelete'])
export const CLANG_ROT_ANFANG = 'clang-analyzer-core.uninitialized.'
// Die Prüfungen aus dem Bauplan (gemessen 27.11.2026, 1,0 s an der Probedatei).
export const CLANG_TIDY_PRUEFUNGEN = '-*,clang-analyzer-*,bugprone-*,cert-*'
// Zeitgrenze je Aufruf beim Schreiben einer Datei; gemessen 27.11.2026 je Datei 0,05 bis 1,3 s (cl) und 0,05 bis 0,5 s (clang-tidy).
export const C_ANALYSE_MS = 120000
// Nummern der Codeanalyse (PREfast C6xxx, C26xxx, C28xxx, C33xxx); Compiler-Warnungen C4xxx meldet schon die Übersetzungsprüfung.
const ANALYSE_CODE = /^C(?:6\d{3}|2[68]\d{3}|33\d{3})$/
const MSVC = 'MSVC /analyze'
const TIDY = 'clang-tidy'
const C_DATEI = /\.c$/i

const klein = (p: string): string => p.trim().replace(/\//g, '\\').toLowerCase()
// cl schreibt auf der Konsole im Windows-Zeichensatz; als UTF-8 gelesen wird ein Umlaut zu "\uFFFD" (gemessen: "B�re"). Im Gerüst
// zählen darum alle Zeichen ausserhalb von ASCII als gleich (wie skeleton in register.tsx).
const geruest = (p: string): string => klein(p).replace(/[^\x20-\x7e]/g, '?')
const name = (p: string): string => p.replace(/\//g, '\\').split('\\').pop() ?? p

// Die Datei der Liste zu einem Pfad aus einer Ausgabe: zuerst genau (ohne Gross/Klein), sonst über das Gerüst.
export function zuDatei(pfad: string, files: string[]): string | undefined {
  const k = klein(pfad)
  const g = geruest(pfad)
  return files.find(f => klein(f) === k) ?? files.find(f => geruest(f) === g)
}

// clang-tidy aus demselben Visual Studio wie cl.exe: <VS>\VC\Tools\MSVC\<Fassung>\bin\Hostx64\x64\cl.exe -> <VS>\VC\Tools\Llvm\x64\bin.
export function clangTidyNeben(cl: string): string | undefined {
  const m = /^(.*\\VC\\Tools)\\MSVC\\[^\\]+\\bin\\Hostx64\\x64\\cl\.exe$/i.exec(cl.replace(/\//g, '\\'))
  return m ? `${m[1]}\\Llvm\\x64\\bin\\clang-tidy.exe` : undefined
}

// SARIF-Adresse (file:///c:/a/b%C3%A4re/x.c, gemessen: klein geschrieben, Umlaute teils roh) als Windows-Pfad.
function uriPfad(uri: string): string {
  let p = uri
  try {
    p = decodeURIComponent(uri)
  } catch {
    // ungültige %-Folge: die Adresse bleibt, wie sie ist, und passt dann zu keiner Datei
  }
  if (/^file:\/\/\/[A-Za-z]:/i.test(p)) return p.slice(8).replace(/\//g, '\\')
  if (/^file:\/\//i.test(p)) return `\\\\${p.slice(7).replace(/\//g, '\\')}`
  return p.replace(/\//g, '\\')
}

const msvcFund = (line: number, col: number, code: string, text: string): SFund => ({
  line, col, code, text: rein(text), schwer: MSVC_ROT.has(code), scanner: MSVC,
})

// Funde aus dem SARIF-Protokoll von cl (ein "run" je Quelldatei). undefined: nicht lesbar - dann gelten die Zeilen der Konsole.
export function msvcSarifLesen(json: string, files: string[]): { datei: string; fund: SFund }[] | undefined {
  let j: any
  try {
    j = JSON.parse(json)
  } catch {
    return undefined
  }
  if (!j || !Array.isArray(j.runs)) return undefined
  const out: { datei: string; fund: SFund }[] = []
  for (const run of j.runs) {
    const artefakte: unknown[] = Array.isArray(run?.artifacts) ? run.artifacts : []
    for (const r of Array.isArray(run?.results) ? run.results : []) {
      const code = String(r?.ruleId ?? '')
      if (!ANALYSE_CODE.test(code)) continue
      const ort = r?.locations?.[0]?.physicalLocation
      const nr = Number(ort?.artifactLocation?.index)
      const uri = String(ort?.artifactLocation?.uri ?? (Number.isInteger(nr) ? (artefakte[nr] as any)?.location?.uri : undefined) ?? '')
      const datei = zuDatei(uriPfad(uri), files)
      if (!datei) continue // Fund in einer eingebundenen Datei, die nicht geprüft wird
      out.push({ datei, fund: msvcFund(Number(ort?.region?.startLine) || 0, Number(ort?.region?.startColumn) || 0, code, String(r?.message?.text ?? '')) })
    }
  }
  return out
}

// ---- cl /analyze: Konsole (stdout und stderr) und, falls lesbar, das SARIF-Protokoll. files in der Reihenfolge des Aufrufs: cl nennt
// vor jeder Datei ihren Namen (gemessen, auch bei nur einer Datei), so gehört ein Fehler in einer eingebundenen Datei zur richtigen.
// Zeilen (gemessen 27.11.2026, deutsch):
//   C:\...\probe.c(9) : warning C6385: Lesen ung�ltiger Daten von "buf": ...: Lines: 7, 8, 9
//   C:\...\fehlt.c(1): fatal error C1083: Datei (Include) kann nicht ge�ffnet werden: "fehlt_nicht_da.h": No such file or directory
//   cl : Befehlszeile error D8016 : Die Befehlszeilenoptionen /std:c17 und /std:c++latest sind inkompatibel.
//   c1: fatal error C1083: Datei (Quelle) kann nicht ge�ffnet werden: "D:\c\nichtda.c": No such file or directory
export function msvcAnalyseLesen(text: string, files: string[], sarif?: string): CLesung {
  const jeDatei = new Map<string, CAuswertung>(files.map(f => [f, { funde: [], unvollstaendig: [] }]))
  const gemeldet = new Set<string>()
  const konsole: { datei: string; fund: SFund }[] = []
  let fehler: string | undefined
  let aktuell: string | undefined
  let naechste = 0
  for (const roh of text.split(/\r?\n/)) {
    const z = roh.trim()
    if (z === '') continue
    const allg = /^cl\s*:.*?\berror\s+(D\d{4})\s*:?\s*(.*)$/i.exec(z)
    if (allg) {
      fehler = fehler ?? `${allg[1]}: ${rein(allg[2] ?? '', 160)}`
      continue
    }
    // Fehler eines Teils des Compilers ohne Zeile (Quelldatei nicht lesbar): gehört zur Datei, die cl gerade übersetzt.
    const teil = /^(?:c1|c1xx|c2)\s*:\s*(?:fatal error|error)\s+([A-Z]+\d+)\s*:\s*(.*)$/i.exec(z)
    if (teil) {
      if (aktuell) jeDatei.get(aktuell)?.unvollstaendig.push(`${teil[1]}: ${rein(teil[2] ?? '', 120)}`)
      else fehler = fehler ?? `${teil[1]}: ${rein(teil[2] ?? '', 160)}`
      continue
    }
    const m = /^(.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(fatal error|error|warning)\s+([A-Z]+\d+)\s*:\s*(.*)$/.exec(z)
    if (m) {
      const datei = zuDatei(m[1] ?? '', files)
      const code = m[5] ?? ''
      if (m[4] !== 'warning') {
        // Übersetzungsfehler: die Datei, die cl gerade übersetzt, ist nicht ausgewertet. Den Text nur, wenn er aus ihr selbst stammt -
        // eine Meldung zu einer eingebundenen fremden Datei könnte deren Inhalt zeigen (wie blindOutside in register.tsx).
        const ziel = aktuell ?? datei
        if (ziel) jeDatei.get(ziel)?.unvollstaendig.push(datei === ziel ? `${code}: ${rein(m[6] ?? '', 120)}` : t(`${code} in einer eingebundenen Datei`, `${code} in an included file`))
        continue
      }
      if (datei && ANALYSE_CODE.test(code)) konsole.push({ datei, fund: msvcFund(Number(m[2]), m[3] ? Number(m[3]) : 0, code, (m[6] ?? '').replace(/\s*:\s*Lines:\s*[\d,\s]*$/, '')) })
      continue
    }
    // Name der nächsten Datei, die cl übersetzt
    const n = files.findIndex((f, i) => i >= naechste && geruest(name(f)) === geruest(z))
    if (n >= 0) {
      aktuell = files[n]
      naechste = n + 1
      gemeldet.add(aktuell ?? '')
    }
  }
  const ausSarif = sarif === undefined ? undefined : msvcSarifLesen(sarif, files)
  for (const { datei, fund } of ausSarif ?? konsole) jeDatei.get(datei)?.funde.push(fund)
  return { jeDatei, fehlend: files.filter(f => !gemeldet.has(f)), ...(fehler ? { fehler } : {}) }
}

// ---- clang-tidy: stdout und stderr. Zeilen (gemessen 27.11.2026, 22.1.3):
//   C:\...\probe.c:30:10: warning: Use of memory after it is released [clang-analyzer-unix.Malloc]
//   C:\...\b.c:7:18: warning: declaration uses identifier '_x', which is reserved ... [bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp]
//   C:\...\fehlt.c:1:10: error: 'fehlt_nicht_da.h' file not found [clang-diagnostic-error]
//   Error while processing C:\...\fehlt.c.
//   error: no such file or directory: 'D:\c\nichtda.c' [clang-diagnostic-error]      (ohne Ort, Datei fehlt)
// Hinweise (note:) und Ausschnitte des Quelltexts zählen nicht.
export function clangTidyLesen(text: string, files: string[]): CLesung {
  const jeDatei = new Map<string, CAuswertung>(files.map(f => [f, { funde: [], unvollstaendig: [] }]))
  const abgebrochen = new Set<string>()
  const ohneOrt: string[] = []
  let fremdeFehler = 0
  let fehler: string | undefined
  for (const roh of text.split(/\r?\n/)) {
    const z = roh.trim()
    const ab = /^Error while processing (.+?)\.?$/.exec(z)
    if (ab) {
      const datei = zuDatei(ab[1] ?? '', files)
      if (datei) abgebrochen.add(datei)
      else fehler = fehler ?? rein(z, 160)
      continue
    }
    const m = /^(.+?):(\d+):(\d+):\s+(warning|error|fatal error):\s+(.*?)(?:\s+\[([\w.,+-]+)\])?$/.exec(z)
    if (m) {
      const datei = zuDatei(m[1] ?? '', files)
      if (!datei) {
        // in einer anderen Datei: gehört nicht zur geprüften; ein Fehler dort lässt aber eine Datei der Liste abbrechen
        if (m[4] !== 'warning') fremdeFehler++
        continue
      }
      const ziel = jeDatei.get(datei)
      if (m[4] !== 'warning') {
        ziel?.unvollstaendig.push(rein(m[5] ?? '', 120))
        continue
      }
      const pruefungen = (m[6] ?? '').split(',').filter(p => p !== '' && !p.startsWith('-'))
      if (pruefungen.length === 0) continue
      ziel?.funde.push({
        line: Number(m[2]), col: Number(m[3]), code: pruefungen[0] ?? '', text: rein(m[5] ?? ''), scanner: TIDY,
        schwer: pruefungen.some(p => CLANG_ROT.has(p) || p.startsWith(CLANG_ROT_ANFANG)),
      })
      continue
    }
    const allg = /^error:\s*(.*)$/i.exec(z)
    if (allg) ohneOrt.push(rein(allg[1] ?? '', 160))
  }
  // Abgebrochen ohne eigene Fehlerzeile: der Fehler stand in einer eingebundenen Datei (ihr Text wird nicht gezeigt) oder hatte keinen
  // Ort (gemessen bei einer fehlenden Datei). Aber: nach dem ersten Fehler schreibt clang-tidy 22 "Error while processing" für JEDE
  // weitere Datei des Aufrufs (gemessen 27.11.2026: fehlt.c zuerst, danach probe.c und uninit.c ohne eigenen Fehler, vollständig
  // ausgewertet). Darum zählt eine solche Datei nur, wenn es Fehler gibt, die keiner Datei der Liste gehören. Fehler ohne Ort ohne
  // abgebrochene Datei: der Lauf als Ganzes ging schief.
  if (fremdeFehler + ohneOrt.length > 0) {
    for (const f of abgebrochen) {
      const e = jeDatei.get(f)
      if (e && e.unvollstaendig.length === 0) e.unvollstaendig.push(t('nicht übersetzbar (Fehler in einer eingebundenen Datei oder ohne Ort)', 'not compilable (error in an included file or without location)'))
    }
  }
  if (abgebrochen.size === 0 && ohneOrt.length > 0) fehler = fehler ?? ohneOrt[0]
  return { jeDatei, fehlend: [], ...(fehler ? { fehler } : {}) }
}

// ---- Beide Scanner über eine Liste von C/C++-Dateien: cl in je einem Aufruf für C und für C++ (Kopfdateien mit /Tp), clang-tidy in je
// einem für die Quelldateien und für die Kopfdateien. Nacheinander, damit der Rechner nie mit mehreren Analysen zugleich belastet wird.
// frist: Zeit für den nächsten Aufruf in ganzen ms (höchstens 600000, siehe PROZESS_MAX_MS); art unterscheidet die Hilfsdateien von
// Sofortprüfung und Ordner-Scan. Was fehlt, abbricht oder nicht ganz ausgewertet ist, steht bei jeder betroffenen Datei unter luecken.
export async function cAnalyse(u: Umgebung, files: string[], frist: () => Promise<number>, art = ''): Promise<Map<string, Ergebnis>> {
  const erg = new Map<string, Ergebnis>(files.map(f => [f, { funde: [], luecken: [], liefen: [] }]))
  if (files.length === 0 || !u.cAnalyse) return erg
  const luecke = (liste: string[], text: string) => {
    for (const f of liste) erg.get(f)?.luecken.push(text)
  }
  const kaputt = (liste: string[], wer: string, grund: string) => luecke(liste, t(`${wer} lief nicht: ${rein(grund, 200)}`, `${wer} did not run: ${rein(grund, 200)}`))
  // Clang-Tidy gehört laut Microsoft zu jeder C++-Arbeitsauslastung (learn.microsoft.com/cpp/code-quality/clang-tidy).
  const fehlt = (liste: string[], wer: string) =>
    luecke(liste, t(`${wer} fehlt (einmalig: Visual Studio Installer, eine C++-Arbeitsauslastung wählen)`, `${wer} missing (once: Visual Studio Installer, choose a C++ workload)`))
  const meldung = (err: unknown): string => String((err as { message?: string })?.message ?? err)
  let w: CWerkzeuge
  let arbeit: string
  try {
    w = await u.cAnalyse()
    arbeit = await u.workDir()
  } catch (err) {
    kaputt(files, 'C/C++-Analyse', meldung(err))
    return erg
  }
  const kennung = u.kennung.replace(/[^\w-]/g, '_').slice(0, 64) || 'chat'
  // Eine Gruppe: Funde übernehmen, dann je Datei "lief" oder die Lücke.
  const auswerten = (liste: string[], wer: string, l: CLesung, r: { exitCode: number; stdout: string; stderr: string; truncated: boolean }, codeOk: number[]) => {
    for (const f of liste) erg.get(f)?.funde.push(...(l.jeDatei.get(f)?.funde ?? []))
    const irgendeinFehler = [...l.jeDatei.values()].some(a => a.unvollstaendig.length > 0)
    if (l.fehler) return kaputt(liste, wer, daten(l.fehler))
    if (!codeOk.includes(r.exitCode) || (r.exitCode !== 0 && !irgendeinFehler)) return kaputt(liste, wer, t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(`${r.stderr}${r.stdout}`))
    if (r.truncated) return kaputt(liste, wer, t('Ausgabe zu gross', 'output too large'))
    for (const f of liste) {
      const a = l.jeDatei.get(f)
      if (a && a.unvollstaendig.length > 0) kaputt([f], wer, t('nicht ganz ausgewertet - ', 'not fully analysed - ') + daten(a.unvollstaendig.join('; '), 240))
      else if (l.fehlend.includes(f)) kaputt([f], wer, t('Datei nicht ausgewertet', 'file not analysed'))
      else erg.get(f)?.liefen.push(wer)
    }
  }

  // C-Kopfdateien (siehe Kopf, cKopf): ein Fehler der Abfrage zählt wie "kein C-Kopf" (dann wie bisher als C++).
  const cKoepfe = new Set<string>()
  if (w.cKopf) {
    for (const f of files) if (/\.h$/i.test(f) && (await w.cKopf(f).catch(() => false))) cKoepfe.add(f)
  }
  const alsC = (f: string): boolean => C_DATEI.test(f) || cKoepfe.has(f)
  // cl /analyze: C (C17, C-Kopfdateien mit /Tc) und C++ (aktueller Standard, Kopfdateien mit /Tp) getrennt (D8016, siehe Kopf)
  const gruppenCl = [files.filter(alsC), files.filter(f => !alsC(f))]
  for (const [n, liste] of gruppenCl.entries()) {
    if (liste.length === 0) continue
    const cl = w.cl
    if (!cl) {
      fehlt(liste, MSVC)
      continue
    }
    const zeit = await frist()
    if (zeit < 1000) {
      luecke(liste, t(`${MSVC}: Zeitgrenze des Scans erreicht`, `${MSVC}: scan time limit reached`))
      continue
    }
    const sarif = `${arbeit}\\msvc-${kennung}${art}-${n}.sarif`
    try {
      await u.write(sarif, GITLEAKS_VORHER)
      const argv = [cl.cl, '/nologo', '/c', '/analyze', '/analyze:only', '/analyze:log:format:sarif', `/analyze:log${sarif}`,
        ...(n === 0 ? ['/std:c17'] : ['/EHsc', '/std:c++latest']), ...liste.flatMap(f => (KOPF.test(f) ? [n === 0 ? '/Tc' : '/Tp', f] : [f]))]
      const r = await u.run(argv, { cwd: arbeit, env: { INCLUDE: cl.include, VSLANG: getLang() === 'en' ? '1033' : '1031' }, timeoutMs: zeit })
      if (!r.ok) {
        kaputt(liste, MSVC, r.reason)
        continue
      }
      // cl löscht das Protokoll vor dem Lauf (gemessen) und schreibt keins, wenn keine Datei übersetzt wurde.
      const inhalt = await u.read(sarif)
      const l = msvcAnalyseLesen(`${r.stdout}\n${r.stderr}`, liste, inhalt === undefined || inhalt.trim() === GITLEAKS_VORHER ? undefined : inhalt)
      // Code 2: mindestens eine Datei hatte einen Übersetzungsfehler (gemessen), die anderen sind trotzdem ausgewertet.
      auswerten(liste, MSVC, l, r, [0, 2])
    } catch (err) {
      kaputt(liste, MSVC, meldung(err))
    }
  }

  // clang-tidy: Quelldateien zusammen, C-Kopfdateien als C und die übrigen Kopfdateien als C++ je für sich
  const gruppenTidy = [files.filter(f => !KOPF.test(f)), files.filter(f => KOPF.test(f) && cKoepfe.has(f)), files.filter(f => KOPF.test(f) && !cKoepfe.has(f))]
  for (const [n, liste] of gruppenTidy.entries()) {
    if (liste.length === 0) continue
    if (!w.clangTidy) {
      fehlt(liste, TIDY)
      continue
    }
    const zeit = await frist()
    if (zeit < 1000) {
      luecke(liste, t(`${TIDY}: Zeitgrenze des Scans erreicht`, `${TIDY}: scan time limit reached`))
      continue
    }
    const argv = [w.clangTidy, `--config={Checks: '${CLANG_TIDY_PRUEFUNGEN}'}`, '--quiet', '--header-filter=^$', ...(n === 1 ? ['--extra-arg-before=-xc'] : n === 2 ? ['--extra-arg-before=-xc++'] : []), ...liste, '--']
    try {
      const r = await u.run(argv, { cwd: arbeit, ...(w.cl ? { env: { INCLUDE: w.cl.include } } : {}), timeoutMs: zeit })
      if (!r.ok) {
        kaputt(liste, TIDY, r.reason)
        continue
      }
      // Code 1: Übersetzungsfehler in mindestens einer Datei (gemessen), die anderen sind ausgewertet.
      auswerten(liste, TIDY, clangTidyLesen(`${r.stdout}\n${r.stderr}`, liste), r, [0, 1])
    } catch (err) {
      kaputt(liste, TIDY, meldung(err))
    }
  }

  for (const e of erg.values()) {
    const gesehen = new Set<string>()
    e.funde = e.funde
      .filter(f => {
        const k = `${f.scanner}|${f.line}|${f.col}|${f.code}`
        if (gesehen.has(k)) return false
        gesehen.add(k)
        return true
      })
      .sort((a, b) => a.line - b.line || a.col - b.col)
  }
  return erg
}
