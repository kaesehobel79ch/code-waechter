// Pakete mit bekannten Lücken (Bauplan "höchstes Niveau" Stufe 2 Punkt 11, 27.11.2026).
// Der OSV-Scanner (Google, https://google.github.io/osv-scanner/) vergleicht die Pakete einer Paketdatei mit der Lückendatenbank
// OSV - hier nur OFFLINE mit der einmal geladenen Datenbank (--offline-vulnerabilities): bei der Prüfung geht nichts ins Netz.
// Die Datenbank lädt "osv-scanner scan source --offline-vulnerabilities --download-offline-databases -L <Datei>" je Quelle einmal
// (Grösse 27.11.2026: NuGet 2,8 MB, PyPI 38 MB, npm 223 MB; Ablage %LOCALAPPDATA%\osv-scalibr).
//
// Gemessen 27.11.2026 mit OSV-Scanner 2.7.1:
//   gelesen werden .csproj, packages.lock.json, packages.config und requirements.txt; NICHT Directory.Packages.props (0 Pakete),
//   package.json und pyproject.toml ("could not determine extractor suitable to this file") - dafür die Sperrdatei nehmen.
//   Newtonsoft.Json 12.0.1 ergab GHSA-5crp-9r3c-p9vr (CVE-2024-21907, max_severity 7.5); Rückgabewert 1 bei Funden, 0 ohne.
//   Fehlt die Datenbank einer Quelle: "could not load db for PyPI ecosystem: ... no offline version of the OSV database is available".
//   Fünf Paketdateien mehrerer Programme (69 Pakete): 0,5 s, keine bekannte Lücke.
// Einstufung: höchste Schwere (CVSS) ab 7.0 ist ein Fehler (High und Critical nach CVSS v3.1, https://www.first.org/cvss/v3-1/
// specification-document Abschnitt 5), darunter oder ohne Wert ein Hinweis.

import { t } from './i18n'
import { daten, rein } from './sicherheit'
import type { Ergebnis, SFund, Umgebung } from './sicherheit'

export const OSV_DATEI =
  /(?:\.(?:cs|vb|fs)proj|(?:^|[\\/])(?:packages\.lock\.json|packages\.config|requirements[^\\/]*\.txt|poetry\.lock|Pipfile\.lock|pdm\.lock|uv\.lock|package-lock\.json|yarn\.lock|pnpm-lock\.yaml))$/i
export const OSV_ROT_AB = 7.0
export const OSV_BEFEHL = 'winget install Google.OSVScanner'

// Quelle der Pakete je Dateiart (für die Meldung "Datenbank fehlt").
const QUELLE: [RegExp, string][] = [
  [/\.(?:cs|vb|fs)proj$|packages\.(?:lock\.json|config)$/i, 'NuGet'],
  [/requirements[^\\/]*\.txt$|poetry\.lock$|Pipfile\.lock$|pdm\.lock$|uv\.lock$/i, 'PyPI'],
  [/package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$/i, 'npm'],
]
const quelleVon = (file: string): string | undefined => QUELLE.find(([re]) => re.test(file))?.[1]

// --offline schaltet alles ab, was ins Netz geht; --no-resolve die Auflösung weiterer Pakete einer Paketliste (die liefe sonst über
// deps.dev). Gemessen 27.11.2026: dieselben Funde wie mit --offline-vulnerabilities allein (Newtonsoft.Json 12.0.1: 3 GHSA).
// --config <leere Datei>: gemessen 28.11.2026 (2.7.1) blendete eine osv-scanner.toml neben der Paketdatei die Lücke aus ("Loaded filter
// from ...", "has been filtered out", 0 Funde, Rückgabe 0); mit --config auf eine leere Datei war sie wieder da (Rückgabe 1). Ein Projekt
// darf die Prüfung so nicht still abschalten (wie --config bei clang-tidy, siehe c_analyse.ts).
export function osvArgv(exe: string, dateien: string[], config?: string): string[] {
  return [exe, 'scan', 'source', '--offline', '--offline-vulnerabilities', '--no-resolve', ...(config ? ['--config', config] : []), '--format', 'json',
    ...dateien.flatMap(f => ['-L', f])]
}

// Inhalt der leeren Einstellungsdatei im Arbeitsordner der Mod (ein Kommentar ist gültiges TOML).
export const OSV_LEER = '# Code-Wächter: leere OSV-Einstellung - keine osv-scanner.toml eines Projekts blendet Funde aus\n'
// Zeilen auf stderr, die der Wächter kennt und einer Datei zuordnet; jede andere Fehlerzeile bei einem Code ausser 0/1 macht den Lauf
// ungültig (Gegenprüfung 28.11.2026: sonst verdeckte eine bekannte Lücke einen zweiten, unbekannten Fehler).
const BEKANNTE_ZEILE = /could not load db for \w+ ecosystem|could not determine extractor suitable to this file/i
const FEHLER_ZEILE = /\b(?:error|failed|could not|unable)\b/i

const schluessel = (p: string): string => p.replace(/\//g, '\\').toLowerCase()

// Zeile, in der der Paketname steht (als ganzes Wort, Gross/Klein egal); sonst Zeile 1.
function zeileDes(text: string | undefined, name: string): number {
  if (!text) return 1
  const re = new RegExp(`(?<![\\w.-])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w.-])`, 'i')
  const zeilen = text.split(/\r?\n/)
  const i = zeilen.findIndex(z => re.test(z))
  return i === -1 ? 1 : i + 1
}

export type OsvErgebnis = { funde: Map<string, SFund[]>; luecken: Map<string, string[]>; fehler?: string }

// stdout: JSON des OSV-Scanners; stderr: seine Meldungen; dateien: wie übergeben; texte: Inhalt je Datei (für die Zeile).
export function osvLesen(stdout: string, stderr: string, dateien: string[], texte: Map<string, string>): OsvErgebnis {
  const funde = new Map<string, SFund[]>()
  const luecken = new Map<string, string[]>()
  const luecke = (f: string, text: string) => luecken.set(f, [...(luecken.get(f) ?? []), text])
  let daten: any
  try {
    daten = JSON.parse(stdout)
  } catch {
    // Keine JSON-Ausgabe: der Scanner lief nicht durch - die Meldung kommt als Lücke, nie als "keine Funde".
    return { funde, luecken, fehler: (stderr.trim().split(/\r?\n/).pop() ?? '').slice(0, 200) || t('keine Ausgabe', 'no output') }
  }
  const nachPfad = new Map(dateien.map(f => [schluessel(f), f]))
  for (const r of Array.isArray(daten?.results) ? daten.results : []) {
    const f = nachPfad.get(schluessel(String(r?.source?.path ?? '')))
    if (!f) continue
    for (const p of Array.isArray(r.packages) ? r.packages : []) {
      const name = String(p?.package?.name ?? '?')
      const fassung = String(p?.package?.version ?? '?')
      for (const g of Array.isArray(p.groups) ? p.groups : []) {
        const ids: string[] = Array.isArray(g?.ids) ? g.ids.map(String) : []
        const alias: string[] = Array.isArray(g?.aliases) ? g.aliases.map(String).filter((a: string) => /^CVE-/.test(a)) : []
        const schwere = Number.parseFloat(String(g?.max_severity ?? ''))
        const id = ids[0] ?? alias[0] ?? '?'
        const wert = Number.isFinite(schwere) ? ` ${schwere.toFixed(1)}` : ''
        const kennung = [...ids, ...alias.filter(a => !ids.includes(a))].join(', ')
        const liste = funde.get(f) ?? []
        liste.push({
          line: zeileDes(texte.get(f), name), col: 1, code: id, schwer: Number.isFinite(schwere) && schwere >= OSV_ROT_AB, scanner: 'OSV-Scanner',
          text: t(`${name} ${fassung} hat eine bekannte Lücke (${kennung}, Schwere${wert || ' unbekannt'}) - auf eine Fassung ohne Lücke wechseln (https://osv.dev/${id})`,
            `${name} ${fassung} has a known vulnerability (${kennung}, severity${wert || ' unknown'}) - move to a version without it (https://osv.dev/${id})`),
        })
        funde.set(f, liste)
      }
    }
  }
  // Datenbank fehlt für eine Quelle: jede Datei dieser Quelle ist für bekannte Lücken nicht geprüft.
  for (const m of stderr.matchAll(/could not load db for (\w+) ecosystem/gi)) {
    for (const f of dateien.filter(x => quelleVon(x)?.toLowerCase() === m[1].toLowerCase())) {
      luecke(f, t(`OSV-Datenbank für ${m[1]} fehlt (einmalig laden: osv-scanner scan source --offline-vulnerabilities --download-offline-databases -L "${f}")`,
        `OSV database for ${m[1]} missing (load once: osv-scanner scan source --offline-vulnerabilities --download-offline-databases -L "${f}")`))
    }
  }
  for (const m of stderr.matchAll(/could not determine extractor suitable to this file: "([^"]+)"/gi)) {
    const f = nachPfad.get(schluessel(m[1].replace(/\\\\/g, '\\')))
    if (f) luecke(f, t('OSV-Scanner kann diese Paketdatei nicht lesen (dafür die Sperrdatei nehmen)', 'OSV-Scanner cannot read this package file (use the lock file)'))
  }
  return { funde, luecken }
}

// Ein Aufruf für alle Paketdateien (beim Schreiben eine, im /scan alle). Gemessen 27.11.2026 (2.7.1): Rückgabe 0 ohne Funde, 1 mit
// Funden; 128 und "No package sources found", wenn keine Datei ein Paket nennt (dann gibt es nichts zu prüfen); 127 bei einem Fehler,
// etwa der fehlenden Datenbank einer Quelle (die Lücke steht dann bei den Dateien dieser Quelle, die anderen sind geprüft).
// Ohne u.osv gehört die Prüfung nicht zur Umgebung; fehlt das Programm, lief es nicht oder reicht die Zeit nicht: Lücke bei jeder Datei.
export async function osvPruefen(u: Umgebung, dateien: string[], texte: Map<string, string>, timeoutMs: number): Promise<Map<string, Ergebnis>> {
  const erg = new Map<string, Ergebnis>(dateien.map(f => [f, { funde: [], luecken: [], liefen: [] }]))
  const alle = (text: string) => {
    for (const e of erg.values()) e.luecken.push(text)
  }
  const kaputt = (grund: string) => alle(t(`OSV-Scanner lief nicht: ${grund}`, `OSV-Scanner did not run: ${grund}`))
  if (!u.osv || dateien.length === 0) return erg
  const exe = await u.osv()
  if (!exe) {
    alle(t(`OSV-Scanner fehlt (einmalig: ${OSV_BEFEHL})`, `OSV-Scanner missing (once: ${OSV_BEFEHL})`))
    return erg
  }
  if (timeoutMs < 1000) {
    alle(t('OSV-Scanner: Zeitgrenze des Scans erreicht', 'OSV-Scanner: scan time limit reached'))
    return erg
  }
  let arbeit: string
  let leer: string
  try {
    arbeit = await u.workDir()
    leer = `${arbeit}\\osv-scanner-leer.toml`
    await u.write(leer, OSV_LEER)
  } catch (err) {
    kaputt(rein(String((err as { message?: string })?.message ?? err)))
    return erg
  }
  const r = await u.run(osvArgv(exe, dateien, leer), { cwd: arbeit, timeoutMs })
  if (!r.ok) {
    kaputt(rein(r.reason))
    return erg
  }
  if (r.truncated) {
    kaputt(t('Ausgabe zu gross', 'output too large'))
    return erg
  }
  if (r.exitCode === 128 && /No package sources found/i.test(r.stderr)) {
    for (const e of erg.values()) e.liefen.push('OSV-Scanner')
    return erg
  }
  const l = osvLesen(r.stdout, r.stderr, dateien, texte)
  if (l.fehler !== undefined) {
    kaputt(daten(l.fehler))
    return erg
  }
  // Ein anderer Code als 0/1 ohne erkannte Ursache oder mit einer weiteren, unbekannten Fehlerzeile: nie als "geprüft" werten.
  // Die Pfade der geprüften Dateien zählen nicht als Fehlerwort: "Scanned D:\p\Error-Logger\App.csproj file and found 3 packages" ist
  // eine normale Zeile (Schlussprüfung 28.11.2026). Schrägstrich und Gross/Klein wie beim Scanner egal.
  const ohnePfade = (z: string): string =>
    dateien.reduce((s, f) => s.replace(new RegExp(f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\\/g, '[\\\\/]'), 'gi'), ' '), z)
  const unbekannt = r.stderr.split(/\r?\n/).filter(z => FEHLER_ZEILE.test(ohnePfade(z)) && !BEKANNTE_ZEILE.test(z))
  if (r.exitCode !== 0 && r.exitCode !== 1 && (l.luecken.size === 0 || unbekannt.length > 0)) {
    kaputt(t(`Code ${r.exitCode}: `, `code ${r.exitCode}: `) + daten(unbekannt[0] ?? r.stderr.trim().split(/\r?\n/).pop() ?? ''))
    return erg
  }
  // Rückgabe 1 heisst "Funde" (gemessen 27.11.2026). Gehört keiner zu einer geprüften Datei, stimmt die Zuordnung nicht: nie "geprüft".
  if (r.exitCode === 1 && ![...l.funde.values()].some(x => x.length > 0)) {
    kaputt(t('Rückgabe 1 (Funde), aber kein Fund gehört zu einer geprüften Datei', 'exit code 1 (findings), but no finding belongs to a checked file'))
    return erg
  }
  for (const [f, e] of erg) {
    e.funde.push(...(l.funde.get(f) ?? []))
    const lu = l.luecken.get(f) ?? []
    e.luecken.push(...lu)
    if (lu.length === 0) e.liefen.push('OSV-Scanner')
  }
  return erg
}
