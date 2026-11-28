import { expect, test } from 'claude-code/testing'
import { setLang } from './i18n'
import { OSV_DATEI, osvArgv, osvLesen, osvPruefen } from './osv'
import { scannen, scannenOrdner } from './sicherheit'
import type { Lauf, Umgebung } from './sicherheit'

// Erwartungen aus dem Bauplan (Stufe 2 Punkt 11) und aus der Messung vom 27.11.2026 (OSV-Scanner 2.7.1, Kopf von osv.ts).

const CSPROJ = 'D:\\p\\App\\App.csproj'
const REQ = 'D:\\p\\werkzeug\\requirements.txt'
const PROJEKT = '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />\n  </ItemGroup>\n</Project>\n'

// Ausgabe wie gemessen (gekürzt auf die Felder, die der Leser braucht), Pfad mit / wie beim echten Scanner
const ausgabe = (schwere: string, pfad = 'D:/p/App/App.csproj') => JSON.stringify({
  results: [{ source: { path: pfad, type: 'lockfile' }, packages: [{
    package: { name: 'Newtonsoft.Json', version: '12.0.1', ecosystem: 'NuGet' },
    vulnerabilities: [{ id: 'GHSA-5crp-9r3c-p9vr', aliases: ['CVE-2024-21907'] }],
    groups: [{ ids: ['GHSA-5crp-9r3c-p9vr'], aliases: ['CVE-2024-21907', 'GHSA-5crp-9r3c-p9vr'], max_severity: schwere }],
  }] }],
})

test('OSV: Lücke ab Schwere 7.0 ist ein Fehler in der Zeile des Pakets, mit Kennung, CVE und Adresse', () => {
  setLang('de')
  const e = osvLesen(ausgabe('7.5'), '', [CSPROJ], new Map([[CSPROJ, PROJEKT]]))
  const f = e.funde.get(CSPROJ) ?? []
  expect(f.length).toBe(1)
  expect(f[0].schwer).toBe(true)
  expect(f[0].line).toBe(3)
  expect(f[0].code).toBe('GHSA-5crp-9r3c-p9vr')
  expect(f[0].text).toContain('Newtonsoft.Json 12.0.1')
  expect(f[0].text).toContain('CVE-2024-21907')
  expect(f[0].text).toContain('https://osv.dev/GHSA-5crp-9r3c-p9vr')
  expect(e.fehler).toBe(undefined)
})

test('OSV: Schwere unter 7.0 oder ohne Wert ist ein Hinweis; ohne Inhalt steht der Fund in Zeile 1', () => {
  expect((osvLesen(ausgabe('6.9'), '', [CSPROJ], new Map()).funde.get(CSPROJ) ?? [])[0]?.schwer).toBe(false)
  const ohne = osvLesen(ausgabe(''), '', [CSPROJ], new Map()).funde.get(CSPROJ) ?? []
  expect(ohne[0]?.schwer).toBe(false)
  expect(ohne[0]?.text).toContain('Schwere unbekannt')
  expect(ohne[0]?.line).toBe(1)
})

test('OSV: der Pfad aus der Ausgabe wird der übergebenen Datei zugeordnet (Schrägstrich, Gross/Klein), fremde Pfade nicht', () => {
  expect(osvLesen(ausgabe('9.8', 'd:/P/app/APP.csproj'), '', [CSPROJ], new Map()).funde.get(CSPROJ)?.length).toBe(1)
  expect(osvLesen(ausgabe('9.8', 'D:/anders/App.csproj'), '', [CSPROJ], new Map()).funde.size).toBe(0)
})

test('OSV: fehlt die Datenbank einer Quelle, ist jede Datei dieser Quelle eine Lücke mit dem Ladebefehl - die anderen nicht', () => {
  setLang('de')
  const fehler = 'Scanned D:\\p\\werkzeug\\requirements.txt file and found 2 packages\ncould not load db for PyPI ecosystem: unable to fetch OSV database: no offline version of the OSV database is available\n'
  const e = osvLesen('{"results": []}', fehler, [CSPROJ, REQ], new Map())
  expect(e.luecken.get(REQ)?.[0]).toContain('OSV-Datenbank für PyPI fehlt')
  expect(e.luecken.get(REQ)?.[0]).toContain('--download-offline-databases')
  expect(e.luecken.has(CSPROJ)).toBe(false)
})

test('OSV: eine Datei, die der Scanner nicht lesen kann, ist eine Lücke; keine JSON-Ausgabe ist ein Fehler des Laufs, nie "keine Funde"', () => {
  const pj = 'D:\\p\\web\\package-lock.json'
  const e = osvLesen('{"results": []}', `could not determine extractor suitable to this file: "D:\\\\p\\\\web\\\\package-lock.json"\n`, [pj], new Map())
  expect(e.luecken.get(pj)?.length).toBe(1)
  const kaputt = osvLesen('panic: kaputt', 'Fehler beim Start\n', [CSPROJ], new Map())
  expect(kaputt.fehler).toBe('Fehler beim Start')
  expect(kaputt.funde.size).toBe(0)
})

test('OSV: Paketdateien, die er liest - nicht package.json, pyproject.toml und Directory.Packages.props (gemessen: kein Leser bzw. 0 Pakete)', () => {
  for (const f of ['D:\\a\\App.csproj', 'D:\\a\\Lib.vbproj', 'D:\\a\\packages.lock.json', 'D:\\a\\packages.config', 'D:\\a\\requirements.txt',
    'D:\\a\\requirements-dev.txt', 'D:\\a\\poetry.lock', 'D:\\a\\package-lock.json', 'D:\\a\\pnpm-lock.yaml']) {
    expect(OSV_DATEI.test(f)).toBe(true)
  }
  for (const f of ['D:\\a\\package.json', 'D:\\a\\pyproject.toml', 'D:\\a\\Directory.Packages.props', 'D:\\a\\notiz.txt', 'D:\\a\\App.cs']) {
    expect(OSV_DATEI.test(f)).toBe(false)
  }
  // Vorgabe "bei der Prüfung geht nichts ins Netz": --offline und --no-resolve (ohne sie löst der Scanner Paketlisten über deps.dev auf).
  expect(osvArgv('C:\\osv.exe', ['D:\\a\\A.csproj', 'D:\\b\\B.csproj'])).toEqual(
    ['C:\\osv.exe', 'scan', 'source', '--offline', '--offline-vulnerabilities', '--no-resolve', '--format', 'json', '-L', 'D:\\a\\A.csproj', '-L', 'D:\\b\\B.csproj'])
})

test('OSV: Meldung auf Englisch, wenn Englisch eingestellt ist', () => {
  setLang('en')
  const f = osvLesen(ausgabe('7.5'), '', [CSPROJ], new Map()).funde.get(CSPROJ) ?? []
  expect(f[0]?.text).toContain('has a known vulnerability')
  setLang('de')
})

// ---- Lauf des Scanners (osvPruefen) und Einbau in scannen/scannenOrdner. Rückgabewerte wie am 27.11.2026 gemessen (Kopf von osvPruefen).
const OSV_EXE = 'C:\\osv\\osv-scanner.exe'
// Leere Einstellungsdatei im Arbeitsordner der Mod (osvUmgebung: workDir C:\Temp\code-waechter)
const LEER = 'C:\\Temp\\code-waechter\\osv-scanner-leer.toml'
const lauf = (exitCode: number, stdout: string, stderr = ''): Lauf => ({ ok: true, exitCode, stdout, stderr, truncated: false })

// exe null = Programm fehlt (undefined nähme den Vorgabewert).
function osvUmgebung(antwort: Lauf | undefined, exe: string | null = OSV_EXE, texte: Record<string, string> = {}) {
  const aufrufe: { argv: string[]; cwd?: string }[] = []
  const u: Umgebung = {
    run: async (argv, opts) => {
      aufrufe.push({ argv, cwd: opts.cwd })
      return antwort ?? { ok: false, reason: 'kein Lauf erwartet' }
    },
    python: ['py'],
    exe: async () => undefined,
    workDir: async () => 'C:\\Temp\\code-waechter',
    read: async p => texte[p],
    write: async () => undefined,
    kennung: 'probe',
    osv: async () => exe ?? undefined,
  }
  return { u, aufrufe }
}

test('OSV-Lauf: Funde (Rückgabe 1) kommen zur Datei, der Aufruf ist offline, im Arbeitsordner, mit vollem Pfad', async () => {
  setLang('de')
  const { u, aufrufe } = osvUmgebung(lauf(1, ausgabe('7.5')))
  const e = (await osvPruefen(u, [CSPROJ], new Map([[CSPROJ, PROJEKT]]), 60000)).get(CSPROJ)
  expect(e?.funde.length).toBe(1)
  expect(e?.funde[0].schwer).toBe(true)
  expect(e?.liefen).toEqual(['OSV-Scanner'])
  expect(e?.luecken).toEqual([])
  expect(aufrufe.length).toBe(1)
  // Feste Liste aus der Vorgabe (nichts ins Netz, keine Einstellung des Projekts; Messung 28.11.2026 im Kopf von osvArgv)
  expect(aufrufe[0].argv).toEqual([OSV_EXE, 'scan', 'source', '--offline', '--offline-vulnerabilities', '--no-resolve', '--config', LEER, '--format', 'json', '-L', CSPROJ])
  expect(aufrufe[0].cwd).toBe('C:\\Temp\\code-waechter')
})

test('OSV-Lauf: eine Paketdatei ohne Pakete (Rückgabe 128, "No package sources found") ist geprüft, ohne Lücke', async () => {
  const { u } = osvUmgebung(lauf(128, '', 'Scanned D:\\p\\App\\App.csproj file and found 0 packages\nNo package sources found, --help for usage information.\n'))
  const e = (await osvPruefen(u, [CSPROJ], new Map(), 60000)).get(CSPROJ)
  expect(e?.liefen).toEqual(['OSV-Scanner'])
  expect(e?.luecken).toEqual([])
})

test('OSV-Lauf: fehlendes Programm, Absturz, Zeitgrenze, unbekannter Rückgabewert sind Lücken, nie "geprüft"', async () => {
  setLang('de')
  const fehlt = osvUmgebung(undefined, null)
  const a = (await osvPruefen(fehlt.u, [CSPROJ], new Map(), 60000)).get(CSPROJ)
  expect(a?.luecken[0]).toContain('OSV-Scanner fehlt (einmalig: winget install Google.OSVScanner)')
  expect(a?.liefen).toEqual([])
  expect(fehlt.aufrufe.length).toBe(0)
  const weg = osvUmgebung({ ok: false, reason: 'abgestürzt' })
  expect((await osvPruefen(weg.u, [CSPROJ], new Map(), 60000)).get(CSPROJ)?.luecken[0]).toContain('OSV-Scanner lief nicht: abgestürzt')
  const zeit = osvUmgebung(lauf(0, '{"results": []}'))
  expect((await osvPruefen(zeit.u, [CSPROJ], new Map(), 500)).get(CSPROJ)?.luecken[0]).toContain('Zeitgrenze')
  expect(zeit.aufrufe.length).toBe(0)
  const code = osvUmgebung(lauf(2, '{"results": []}', 'etwas ging schief\n'))
  const c = (await osvPruefen(code.u, [CSPROJ], new Map(), 60000)).get(CSPROJ)
  expect(c?.luecken[0]).toContain('Code 2')
  expect(c?.liefen).toEqual([])
})

test('OSV-Lauf: fehlt die PyPI-Datenbank (Rückgabe 127), ist nur die requirements.txt offen, die .csproj geprüft', async () => {
  const fehler = 'could not load db for PyPI ecosystem: unable to fetch OSV database: no offline version of the OSV database is available\n'
  const { u, aufrufe } = osvUmgebung(lauf(127, '{"results": []}', fehler))
  const erg = await osvPruefen(u, [CSPROJ, REQ], new Map(), 60000)
  expect(aufrufe.length).toBe(1)
  expect(erg.get(CSPROJ)?.liefen).toEqual(['OSV-Scanner'])
  expect(erg.get(REQ)?.liefen).toEqual([])
  expect(erg.get(REQ)?.luecken[0]).toContain('OSV-Datenbank für PyPI fehlt')
})

test('OSV-Einbau: scannen prüft eine .csproj mit dem OSV-Scanner, eine .cs-Datei nicht; ohne Feld osv läuft nichts', async () => {
  const { u, aufrufe } = osvUmgebung(lauf(1, ausgabe('9.8')))
  const e = await scannen(u, CSPROJ, PROJEKT)
  expect(e.funde.some(f => f.scanner === 'OSV-Scanner' && f.schwer && f.line === 3)).toBe(true)
  expect(e.liefen).toContain('OSV-Scanner')
  await scannen(u, 'D:\\p\\App\\Program.cs', 'class P {}\n')
  expect(aufrufe.filter(a => a.argv[0] === OSV_EXE).length).toBe(1)
  const ohne = osvUmgebung(lauf(1, ausgabe('9.8')))
  delete ohne.u.osv
  const o = await scannen(ohne.u, CSPROJ, PROJEKT)
  expect(o.liefen).not.toContain('OSV-Scanner')
  expect(ohne.aufrufe.length).toBe(0)
})

test('OSV-Einbau: scannenOrdner prüft alle Paketdateien in EINEM Aufruf und ordnet die Funde zu', async () => {
  const REQ_TEXT = 'requests==2.32.3\n'
  const { u, aufrufe } = osvUmgebung(lauf(1, ausgabe('7.5')), OSV_EXE, { [CSPROJ]: PROJEKT, [REQ]: REQ_TEXT, 'D:\\p\\App\\Program.cs': 'class P {}\n' })
  const erg = await scannenOrdner(u, [CSPROJ, REQ, 'D:\\p\\App\\Program.cs'])
  const osv = aufrufe.filter(a => a.argv[0] === OSV_EXE)
  expect(osv.length).toBe(1)
  expect(osv[0].argv).toEqual([OSV_EXE, 'scan', 'source', '--offline', '--offline-vulnerabilities', '--no-resolve', '--config', LEER, '--format', 'json', '-L', CSPROJ, '-L', REQ])
  expect(erg.get(CSPROJ)?.funde.some(f => f.scanner === 'OSV-Scanner' && f.line === 3)).toBe(true)
  expect(erg.get(REQ)?.liefen).toContain('OSV-Scanner')
  expect(erg.get('D:\\p\\App\\Program.cs')?.liefen).not.toContain('OSV-Scanner')
})

// ---- Gegenprüfung 28.11.2026
// Gemessen: eine osv-scanner.toml neben der Paketdatei blendete die Lücke aus; mit --config auf eine leere Datei nicht.
test('OSV-Lauf: vor dem Aufruf schreibt der Wächter die leere Einstellungsdatei in seinen Arbeitsordner und gibt sie mit --config mit', async () => {
  const { u, aufrufe } = osvUmgebung(lauf(1, ausgabe('7.5')))
  const folge: string[] = []
  const lauf0 = u.run
  u.run = async (argv, opts) => {
    folge.push('Lauf')
    return lauf0(argv, opts)
  }
  let inhalt = ''
  u.write = async (p, text) => {
    folge.push(`schreiben ${p}`)
    inhalt = text
  }
  await osvPruefen(u, [CSPROJ], new Map(), 60000)
  expect(folge).toEqual([`schreiben ${LEER}`, 'Lauf'])
  const argv = aufrufe[0]?.argv ?? []
  expect(argv[argv.indexOf('--config') + 1]).toBe(LEER)
  // Vorgabe "leer" (Schlussprüfung 28.11.2026: nicht gegen die Konstante selbst prüfen): nur Kommentarzeilen, keine Einstellung
  expect(inhalt.length).toBeGreaterThan(0)
  expect(inhalt.split('\n').every(z => z.trim() === '' || z.trim().startsWith('#'))).toBe(true)
  expect(inhalt).not.toContain('[')
  expect(inhalt).not.toContain('=')
})

test('OSV-Lauf: Rückgabe 1 ohne einen Fund bei einer geprüften Datei ist eine Lücke, nie "geprüft"', async () => {
  setLang('de')
  const { u } = osvUmgebung(lauf(1, ausgabe('9.8', 'D:/anders/App.csproj')))
  const e = (await osvPruefen(u, [CSPROJ], new Map(), 60000)).get(CSPROJ)
  expect(e?.liefen).toEqual([])
  expect(e?.funde).toEqual([])
  expect(e?.luecken.join(' | ')).toContain('OSV-Scanner lief nicht: Rückgabe 1 (Funde), aber kein Fund gehört zu einer geprüften Datei')
})

test('OSV-Lauf: Rückgabe 127 mit fehlender PyPI-Datenbank UND einem weiteren, unbekannten Fehler macht den ganzen Lauf ungültig', async () => {
  setLang('de')
  const fehler = 'could not load db for PyPI ecosystem: unable to fetch OSV database: no offline version of the OSV database is available\n'
    + 'failed to read lockfile D:\\p\\App\\App.csproj: zip: not a valid zip file\n'
  const { u } = osvUmgebung(lauf(127, JSON.stringify({ results: [] }), fehler))
  const erg = await osvPruefen(u, [CSPROJ, REQ], new Map(), 60000)
  for (const f of [CSPROJ, REQ]) {
    expect(erg.get(f)?.liefen).toEqual([])
    expect(erg.get(f)?.luecken.join(' | ')).toContain('OSV-Scanner lief nicht: Code 127: «failed to read lockfile')
  }
})

// Schlussprüfung 28.11.2026: ein Fehlerwort im PFAD einer geprüften Datei macht die normale Zeile "Scanned ..." nicht zum Fehler.
test('OSV-Lauf: ein Ordner "Error-Logger" im Pfad zählt nicht als Fehlerzeile; die .csproj ist geprüft, nur die PyPI-Datei offen', async () => {
  setLang('de')
  const csproj = 'D:\\p\\Error-Logger\\App.csproj'
  const fehler = 'Scanned D:\\p\\Error-Logger\\App.csproj file and found 1 package\n'
    + 'Scanned D:/p/werkzeug/requirements.txt file and found 2 packages\n'
    + 'could not load db for PyPI ecosystem: unable to fetch OSV database: no offline version of the OSV database is available\n'
  const { u } = osvUmgebung(lauf(127, JSON.stringify({ results: [] }), fehler))
  const erg = await osvPruefen(u, [csproj, REQ], new Map(), 60000)
  expect(erg.get(csproj)?.liefen).toEqual(['OSV-Scanner'])
  expect(erg.get(csproj)?.luecken).toEqual([])
  expect(erg.get(REQ)?.liefen).toEqual([])
  expect(erg.get(REQ)?.luecken.join(' | ')).toContain('OSV-Datenbank für PyPI fehlt')
})
