import { expect, test } from 'claude-code/testing'
import { istPaketDatei, nameGueltig, neuePakete, paketePruefen, pep508 } from './pakete'
import type { Paket, PaketUmgebung } from './pakete'
import type { Lauf } from './sicherheit'

// Erwartungen aus dem Auftrag (27.11.2026, Regel "neue Pakete prüfen"), feste Zahlen und Adressen aus der Vorgabe und der Doku
// der Paketquellen - nie aus den Konstanten von pakete.ts.

const kurz = (l: Paket[]) => l.map(p => `${p.oekosystem}:${p.name}@${p.version}#${p.zeile}`)

test('Paketlisten: nur die Dateiarten aus dem Auftrag', () => {
  for (const f of ['D:\\p\\A.csproj', 'D:\\p\\A.vbproj', 'D:\\p\\A.fsproj', 'D:\\p\\Directory.Packages.props', 'D:\\p\\packages.config', 'D:\\p\\requirements.txt',
    'D:\\p\\requirements-dev.txt', 'D:\\p\\pyproject.toml', 'D:\\p\\package.json']) expect(istPaketDatei(f)).toBe(true)
  for (const f of ['D:\\p\\A.cs', 'D:\\p\\notizen.txt', 'D:\\p\\Directory.Build.props', 'D:\\p\\package-lock.json', 'D:\\p\\tsconfig.json']) expect(istPaketDatei(f)).toBe(false)
})

test('.csproj: PackageReference mit Include/Update und Version (Attribut oder Element), Kommentare zählen nicht, nur neue', () => {
  const alt = '<Project>\n  <ItemGroup>\n    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n  </ItemGroup>\n</Project>'
  const neu = [
    '<Project>',
    '  <ItemGroup>',
    '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />',
    '    <!-- <PackageReference Include="Auskommentiert" Version="1.0" /> -->',
    '    <PackageReference Include="Serilog">',
    '      <Version>4.1.0</Version>',
    '    </PackageReference>',
    '    <PackageReference Update="Meziantou.Analyzer" Version="2.0.1" Condition="\'$(X)\' > \'1\'" />',
    '    <PackageReference Update="Nur.Angaben" PrivateAssets="all" />',
    '    <PackageReference Include="Eins;Zwei" Version="1.0" />',
    '  </ItemGroup>',
    '</Project>',
  ].join('\r\n')
  expect(kurz(neuePakete(alt, neu, 'D:\\p\\A.csproj'))).toEqual(['nuget:Serilog@4.1.0#5', 'nuget:Meziantou.Analyzer@2.0.1#8', 'nuget:Eins@1.0#10', 'nuget:Zwei@1.0#10'])
  // alt undefined: alle; andere Fassung desselben Pakets zählt als neu
  expect(neuePakete(undefined, alt, 'D:\\p\\A.csproj').map(p => p.name)).toEqual(['Newtonsoft.Json'])
  expect(kurz(neuePakete(alt, alt.replace('13.0.3', '13.0.4'), 'D:\\p\\A.csproj'))).toEqual(['nuget:Newtonsoft.Json@13.0.4#3'])
  // Gross/Klein spielt bei NuGet keine Rolle
  expect(neuePakete(alt, alt.replace('Newtonsoft.Json', 'newtonsoft.json'), 'D:\\p\\A.csproj')).toEqual([])
  // kaputte Zeichennummer: keine Ausnahme
  expect(neuePakete(undefined, '<Project><ItemGroup><PackageReference Include="A&#99999999;" Version="1" /></ItemGroup></Project>', 'D:\\p\\A.csproj').map(p => p.name)).toEqual(['A'])
  // ManagePackageVersionsCentrally in der Projektdatei selbst
  expect(neuePakete(undefined, '<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageReference Include="A" /></ItemGroup></Project>', 'D:\\p\\A.csproj')[0]?.zentral).toBe(true)
})

test('Directory.Packages.props und packages.config', () => {
  const props = '<Project>\n  <ItemGroup>\n    <PackageVersion Include="PackageA" Version="1.0.0" />\n    <GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.5.109" />\n    <PackageReference Include="NichtHier" Version="1" />\n  </ItemGroup>\n</Project>'
  expect(kurz(neuePakete(undefined, props, 'D:\\p\\Directory.Packages.props'))).toEqual(['nuget:PackageA@1.0.0#3', 'nuget:Nerdbank.GitVersioning@3.5.109#4'])
  const cfg = '<?xml version="1.0" encoding="utf-8"?>\n<packages>\n  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />\n  <package id="Ohne" />\n</packages>'
  expect(kurz(neuePakete(undefined, cfg, 'D:\\p\\packages.config'))).toEqual(['nuget:Newtonsoft.Json@13.0.1#3', 'nuget:Ohne@#4'])
})

test('requirements*.txt: -r und Einstellungen ignoriert, Kommentare, Marker, Zusätze, Fortsetzung, Adressen und Pfade sind keine Pakete', () => {
  const txt = [
    '# Kopf',
    '-r basis.txt',
    'requests[security] >= 2.8.1, == 2.8.* ; python_version < "2.7"',
    'pillow==13.0.0  # Bilder',
    'numpy \\',
    '  >=2.0',
    'urllib3 @ https://github.com/urllib3/urllib3/archive/refs/tags/1.26.8.zip',
    'git+https://github.com/x/y.git#egg=y',
    './lokal',
    'paket-1.0.tar.gz',
    'flask --hash=sha256:abc',
    'Django (>=4.0)',
    '-e ../editierbar',
  ].join('\n')
  expect(kurz(neuePakete(undefined, txt, 'D:\\p\\requirements-dev.txt'))).toEqual([
    'pypi:requests@>= 2.8.1, == 2.8.*#3', 'pypi:pillow@==13.0.0#4', 'pypi:numpy@>=2.0#5', 'pypi:flask@#11', 'pypi:Django@>=4.0#12'])
  expect(neuePakete(undefined, txt, 'D:\\p\\requirements.txt').some(p => p.eigeneQuelle)).toBe(false)
  expect(neuePakete(undefined, `--extra-index-url https://intern.example/simple\n${txt}`, 'D:\\p\\requirements.txt').every(p => p.eigeneQuelle === true)).toBe(true)
  // PyPI-Namen gleich nach PEP 503: Gross/Klein und - _ . sind derselbe Name
  expect(neuePakete('Pillow==13.0.0', 'pillow==13.0.0', 'D:\\p\\requirements.txt')).toEqual([])
  expect(neuePakete('zope.interface', 'Zope_Interface', 'D:\\p\\requirements.txt')).toEqual([])
  expect(pep508('name @ file:///x')).toBe(undefined)
})

test('pyproject.toml: [project] dependencies, [project.optional-dependencies], [tool.poetry.dependencies]', () => {
  const toml = [
    '[project]',
    'name = "werkzeug"',
    'dependencies = [',
    '  "httpx>=0.27",  # Netz',
    "  'rich',",
    ']',
    'optional-dependencies = { bild = ["pillow>=13"] }',
    '',
    '[project.optional-dependencies]',
    'test = ["pytest>=8", "pytest-cov"]',
    '',
    '[tool.poetry.dependencies]',
    'python = "^3.12"',
    'requests = "^2.31"',
    'lokal = { path = "../lokal" }',
    'tomli = { version = "^2.0", optional = true }',
    '"quoted-name" = "1.0"',
    '',
    '[tool.poetry.dependencies.untertabelle]',
    'version = "3.0"',
    '',
    '[tool.poetry.dependencies.ordner]',
    'path = "../ordner"',
  ].join('\n')
  expect(kurz(neuePakete(undefined, toml, 'D:\\p\\pyproject.toml'))).toEqual([
    'pypi:httpx@>=0.27#4', 'pypi:rich@#5', 'pypi:pillow@>=13#7', 'pypi:pytest@>=8#10', 'pypi:pytest-cov@#10', 'pypi:requests@^2.31#14', 'pypi:tomli@^2.0#16', 'pypi:quoted-name@1.0#17',
    'pypi:untertabelle@3.0#20'])
  // eigene Quelle (Poetry, uv): 404 ist dann kein sicherer Beweis
  expect(neuePakete(undefined, `${toml}\n\n[[tool.poetry.source]]\nname = "intern"\nurl = "https://intern.example/simple"`, 'D:\\p\\pyproject.toml').every(p => p.eigeneQuelle === true)).toBe(true)
  // Schreibfehler: es wird nicht weitergelesen, nie ein Absturz
  expect(kurz(neuePakete(undefined, '[project]\ndependencies = ["a",\n', 'D:\\p\\pyproject.toml'))).toEqual([])
  expect(kurz(neuePakete(undefined, '[project]\ndependencies = ["b\\UFFFFFFFFc>=1"]\n', 'D:\\p\\pyproject.toml'))).toEqual(['pypi:bc@>=1#2'])
})

test('package.json: vier Abhängigkeitslisten, Decknamen, nur Pakete aus der Paketquelle; Unity-Pakete und kaputtes JSON liefern keine', () => {
  const pj = JSON.stringify({
    name: 'meins',
    dependencies: { express: '^4.21.0', '@types/node': '22.0.0', lokal: 'file:../lokal', gh: 'github:user/repo', kurz: 'user/repo', ws: 'workspace:*', alias: 'npm:lodash@^4.17.21' },
    devDependencies: { typescript: '5.6.3' },
    peerDependencies: { react: '>=18' },
    optionalDependencies: { fsevents: '*' },
  }, null, 2)
  expect(kurz(neuePakete(undefined, pj, 'D:\\p\\package.json'))).toEqual([
    'npm:express@^4.21.0#4', 'npm:@types/node@22.0.0#5', 'npm:lodash@^4.17.21#10', 'npm:typescript@5.6.3#13', 'npm:react@>=18#16', 'npm:fsevents@*#19'])
  expect(neuePakete(undefined, JSON.stringify({ name: 'com.beispiel.werkzeug', dependencies: { 'com.unity.modules.ui': '1.0.0' } }), 'D:\\u\\Packages\\com.beispiel.werkzeug\\package.json')).toEqual([])
  expect(neuePakete(undefined, '{ "dependencies": { "a": "1" ', 'D:\\p\\package.json')).toEqual([])
})

test('Namensregeln der Quellen: nur solche Namen kommen in eine Adresse', () => {
  expect(nameGueltig('nuget', 'Newtonsoft.Json')).toBe(true)
  expect(nameGueltig('nuget', 'a'.repeat(101))).toBe(false)
  expect(nameGueltig('nuget', 'Foo Bar')).toBe(false)
  expect(nameGueltig('nuget', 'x/../y')).toBe(false)
  expect(nameGueltig('pypi', 'zope.interface')).toBe(true)
  expect(nameGueltig('pypi', 'foo.')).toBe(false)
  expect(nameGueltig('npm', '@types/node')).toBe(true)
  expect(nameGueltig('npm', '.versteckt')).toBe(false)
  expect(nameGueltig('npm', 'a?b=c')).toBe(false)
  expect(nameGueltig('npm', 'node_modules')).toBe(false)
  expect(nameGueltig('npm', 'a'.repeat(215))).toBe(false)
})

// Gespielte Umgebung: welche Ordner es gibt und was curl antwortet (kein echtes Netz).
function umgebung(antwort: (url: string) => Lauf, da: string[] = []) {
  const aufrufe: { argv: string[]; timeoutMs?: number }[] = []
  const vorhanden = new Set(da.map(x => x.toLowerCase()))
  const u: PaketUmgebung = {
    run: async (argv, opts) => {
      aufrufe.push({ argv, timeoutMs: opts.timeoutMs })
      return antwort(argv[argv.length - 1] ?? '')
    },
    nugetOrdner: 'C:\\Users\\k\\.nuget\\packages',
    exists: async p => vorhanden.has(p.toLowerCase()),
  }
  return { u, aufrufe }
}
const http = (code: string): Lauf => ({ ok: true, exitCode: 0, stdout: code, stderr: '', truncated: false })
const paket = (oekosystem: Paket['oekosystem'], name: string, version = '1.0.0', zeile = 1, datei = 'D:\\p\\A.csproj'): Paket => ({ oekosystem, name, version, zeile, datei })

test('Prüfen: 404 ist rot PAKET-UNBEKANNT, 200 nichts; curl mit vollem Pfad und genau den Angaben aus dem Auftrag; nur der Name geht ins Netz', async () => {
  const { u, aufrufe } = umgebung(url => (url.includes('gibtsnicht') ? http('404') : http('200')))
  const r = await paketePruefen(u, [paket('nuget', 'Erfunden.GibtsNicht', '1.0.0', 7), paket('pypi', 'Requests', '', 2, 'D:\\p\\requirements.txt'), paket('npm', '@types/node', '22.0.0', 3, 'D:\\p\\package.json')])
  expect(r.luecken).toEqual([])
  expect(r.funde.map(f => [f.code, f.line, f.schwer])).toEqual([['PAKET-UNBEKANNT', 7, true]])
  expect(r.funde[0]?.text).toContain('«Erfunden.GibtsNicht»')
  expect(r.funde[0]?.text).toContain('erfundener Name')
  expect(aufrufe.map(a => a.argv)).toEqual([
    ['C:\\Windows\\System32\\curl.exe', '-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '10', 'https://api.nuget.org/v3-flatcontainer/erfunden.gibtsnicht/index.json'],
    ['C:\\Windows\\System32\\curl.exe', '-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '10', 'https://pypi.org/pypi/requests/json'],
    ['C:\\Windows\\System32\\curl.exe', '-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '10', '-H', 'Accept: application/vnd.npm.install-v1+json', 'https://registry.npmjs.org/@types%2fnode'],
  ])
  // Zeitgrenze ganzzahlig, höchstens 600000 ms
  for (const a of aufrufe) expect(Number.isInteger(a.timeoutMs) && (a.timeoutMs ?? 0) > 0 && (a.timeoutMs ?? 0) <= 600000).toBe(true)
})

test('Prüfen: NuGet-Paket im eigenen Paketordner braucht keine Abfrage', async () => {
  const { u, aufrufe } = umgebung(() => http('404'), ['C:\\Users\\k\\.nuget\\packages\\newtonsoft.json'])
  const r = await paketePruefen(u, [paket('nuget', 'Newtonsoft.Json')])
  expect(r).toEqual({ funde: [], luecken: [] })
  expect(aufrufe).toEqual([])
})

test('Prüfen: Quelle nicht erreichbar ist eine Lücke, nie OK; danach fragt der Wächter dieselbe Quelle nicht weiter', async () => {
  const { u, aufrufe } = umgebung(url => (url.includes('pypi') ? { ok: true, exitCode: 6, stdout: '000', stderr: '', truncated: false } : http('500')))
  const r = await paketePruefen(u, [paket('pypi', 'a', ''), paket('pypi', 'b', ''), paket('npm', 'c')])
  expect(r.funde).toEqual([])
  expect(r.luecken.length).toBe(2)
  expect(r.luecken[0]).toContain('Paketquelle PyPI nicht erreichbar')
  expect(r.luecken[0]).toContain('2 Paket(e) nicht geprüft')
  expect(r.luecken[1]).toContain('Paketquelle npm nicht erreichbar')
  expect(aufrufe.length).toBe(2)
  const z = umgebung(() => ({ ok: false, reason: 'Prozess nicht startbar' }))
  const r2 = await paketePruefen(z.u, [paket('npm', 'express')])
  expect(r2.luecken[0]).toContain('nicht erreichbar')
  const w = umgebung(() => {
    throw new Error('kaputt')
  })
  expect((await paketePruefen(w.u, [paket('npm', 'express')])).luecken[0]).toContain('nicht erreichbar')
})

test('Prüfen: höchstens 20 Abfragen je Aufruf, der Rest ist eine Lücke', async () => {
  const { u, aufrufe } = umgebung(() => http('200'))
  const liste = Array.from({ length: 23 }, (_x, i) => paket('npm', `paket${i}`))
  const r = await paketePruefen(u, liste)
  expect(aufrufe.length).toBe(20)
  expect(r.luecken).toEqual(['zu viele neue Pakete, nur die ersten 20 geprüft (3 weitere nicht)'])
})

test('Prüfen: unzulässiger Name wird nie abgefragt (Hinweis PAKET-NAME), MSBuild-Angabe ist eine Lücke, gleicher Name nur einmal', async () => {
  const { u, aufrufe } = umgebung(() => http('404'))
  const r = await paketePruefen(u, [paket('npm', 'x?y=1', '1', 4, 'D:\\p\\package.json'), paket('nuget', '$(MeinPaket)', '1.0', 5), paket('pypi', 'Gleich', '1', 6, 'D:\\p\\requirements.txt'), paket('pypi', 'gleich', '2', 7, 'D:\\p\\requirements.txt')])
  expect(r.funde.map(f => [f.code, f.line, f.schwer])).toEqual([['PAKET-NAME', 4, false], ['PAKET-UNBEKANNT', 6, true], ['PAKET-UNBEKANNT', 7, true]])
  expect(r.luecken[0]).toContain('MSBuild')
  expect(aufrufe.map(a => a.argv[a.argv.length - 1])).toEqual(['https://pypi.org/pypi/gleich/json'])
})

test('Prüfen: eigene Paketquelle in der Datei - 404 auf PyPI ist dann ein Hinweis, kein Fehler', async () => {
  const { u } = umgebung(() => http('404'))
  const r = await paketePruefen(u, [{ ...paket('pypi', 'intern-werkzeug', '', 3, 'D:\\p\\requirements.txt'), eigeneQuelle: true }])
  expect(r.funde.map(f => [f.code, f.schwer])).toEqual([['PAKET-UNBEKANNT', false]])
  expect(r.funde[0]?.text).toContain('eigene Paketquelle')
})

test('PAKET-VERSION (NuGet): * und fehlende Fassung und Bereich ohne Obergrenze sind Hinweise; zentrale Fassungen nicht', async () => {
  const da = ['C:\\Users\\k\\.nuget\\packages\\a']
  const pruefe = async (p: Paket, ordner: string[] = []) => (await paketePruefen(umgebung(() => http('200'), [...da, ...ordner]).u, [p])).funde.map(f => `${f.code}${f.schwer ? '!' : ''}`)
  expect(await pruefe(paket('nuget', 'A', '6.*'))).toEqual(['PAKET-VERSION'])
  expect(await pruefe(paket('nuget', 'A', ''))).toEqual(['PAKET-VERSION'])
  expect(await pruefe(paket('nuget', 'A', '[1.0,)'))).toEqual(['PAKET-VERSION'])
  expect(await pruefe(paket('nuget', 'A', '(4.1.3, )'))).toEqual(['PAKET-VERSION'])
  expect(await pruefe(paket('nuget', 'A', '1.0'))).toEqual([])
  expect(await pruefe(paket('nuget', 'A', '[1.0,2.0)'))).toEqual([])
  // Directory.Packages.props im Ordner darüber: die Fassung fehlt in der .csproj absichtlich
  expect(await pruefe(paket('nuget', 'A', '', 1, 'D:\\repo\\src\\App\\App.csproj'), ['D:\\repo\\Directory.Packages.props'])).toEqual([])
  expect(await pruefe({ ...paket('nuget', 'A', '', 1, 'D:\\repo\\App.csproj'), zentral: true })).toEqual([])
  // ausdrücklich ausgeschaltet: dann zählt die Datei darüber nicht
  expect(await pruefe({ ...paket('nuget', 'A', '', 1, 'D:\\repo\\src\\App.csproj'), zentral: false }, ['D:\\repo\\Directory.Packages.props'])).toEqual(['PAKET-VERSION'])
  // in der zentralen Datei selbst und in packages.config muss die Fassung stehen
  expect(await pruefe(paket('nuget', 'A', '', 1, 'D:\\repo\\Directory.Packages.props'), ['D:\\repo\\Directory.Packages.props'])).toEqual(['PAKET-VERSION'])
  // andere Quellen: keine Fassungsregel
  expect((await paketePruefen(umgebung(() => http('200')).u, [paket('pypi', 'requests', '', 1, 'D:\\p\\requirements.txt'), paket('npm', 'x', '*', 1, 'D:\\p\\package.json')])).funde).toEqual([])
})
