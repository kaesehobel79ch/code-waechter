import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'
import { TOOLS } from './werkzeuge'

// Bauplan "höchstes Niveau" Stufe 2 Punkt 12 (27.11.2026 "Alle drei Stufen"): Meziantou.Analyzer für C# (Regex ohne
// Zeitlimit, async-Fehler) und eslint-plugin-no-unsanitized für JavaScript, über /waechter-werkzeuge mit fester Fassung und
// Prüfsumme. Erwartete Werte aus der Vorgabe und aus der Messung vom 28.11.2026 (Download, Prüfsumme, echter Bau mit
// dotnet 11.0.100, echter ESLint-Lauf 10.13.0), nie aus dem geprüften Code.

const VERTRAUT = { options: { freigegebene_ordner: 'D:\\', sprache: 'de', werkzeug_ordner: 'C:\\Werkzeuge' } }
const withTemp = (on: On) => on('env.get', (_$, e) => ({ value: e.name === 'TEMP' ? 'C:\\Temp' : undefined }))
const done = { exitCode: 0, stdout: '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false }
const toolAnswer = { result: {}, text: 'ok' }
const projectList = [{ name: 'Mod.csproj', kind: 'file' as const, size: 1, mtimeMs: 0, isLink: false }]
const write = async ($: any, file: string): Promise<string> => ((await $.tool.call({ tool: 'Write', file_path: file, content: 'x' })).context ?? []).join('\n')

// ====================================================================================== Werkzeugeinträge
test('Zusatzregeln: Meziantou.Analyzer 3.0.342 und no-unsanitized 4.1.5 mit fester Adresse, SHA-256 und den behaltenen Teilen', () => {
  const ma = TOOLS.find(d => d.id === 'meziantou')
  expect(ma?.version).toBe('3.0.342')
  expect(ma?.quelle).toEqual({
    art: 'tar',
    url: 'https://api.nuget.org/v3-flatcontainer/meziantou.analyzer/3.0.342/meziantou.analyzer.3.0.342.nupkg',
    sha256: '6b20dc076d961a0a0378c7898149da76394da0401cae0ac9691196c91092855e',
    name: 'meziantou.zip',
    teile: [
      'analyzers/dotnet/roslyn5.0/cs/Meziantou.Analyzer.dll',
      'analyzers/dotnet/roslyn5.6/cs/Meziantou.Analyzer.dll',
      'analyzers/dotnet/roslyn5.9/cs/Meziantou.Analyzer.dll',
      'configuration/none.editorconfig',
      'LICENSE.txt',
    ],
    strip: 0,
  })
  expect(ma?.exe).toBe('meziantou\\analyzers\\dotnet\\roslyn5.9\\cs\\Meziantou.Analyzer.dll')
  expect(ma?.braucht).toBeUndefined()

  const nu = TOOLS.find(d => d.id === 'nounsanitized')
  expect(nu?.version).toBe('4.1.5')
  expect(nu?.quelle).toEqual({
    art: 'tar',
    url: 'https://registry.npmjs.org/eslint-plugin-no-unsanitized/-/eslint-plugin-no-unsanitized-4.1.5.tgz',
    sha256: '0041e63a9a2e58b23bc6bcf1aea6b1f32898be2cc78e6d59dfcc5c37c2a49d36',
    name: 'nounsanitized.tgz',
    teile: [],
    strip: 1,
  })
  expect(nu?.exe).toBe('nounsanitized\\index.js')
  // Ohne ESLint nützt der Plugin nichts: ESLint (und damit Node.js) wird zuerst geladen.
  expect(nu?.braucht).toEqual(['eslint'])
})

test('Zusatzregeln: /waechter-werkzeuge zeigt Meziantou.Analyzer und no-unsanitized in der Übersicht', VERTRAUT, async ($, on) => {
  mock.clock(on)
  on('fs.exists', (_$, e) => ({ value: /\\meziantou\\/i.test(String(e.path)) }))
  on('fs.read', () => ({ value: 'code-waechter 3.0.342\n' }))
  on('env.get', () => ({ value: 'C:\\Users\\Probe\\AppData\\Local' }))

  const r = await $.command.run({ command: 'waechter-werkzeuge', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 120 } })
  const text = String((r as { text?: string }).text ?? '')

  expect(text).toContain('✔ meziantou  Meziantou.Analyzer (C#) 3.0.342')
  expect(text).toContain('✖ nounsanitized eslint-plugin-no-unsanitized (Mozilla) 4.1.5')
})

test('Zusatzregeln: install meziantou und install nounsanitized laden mit Adresse, Prüfsumme, Teilen und Fassung der Vorgabe', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  on('tool.call', () => toolAnswer as never)
  on('fs.exists', () => ({ value: false }))
  on('fs.write', () => ({ value: undefined }))
  on('session.send', () => ({ isDelivered: true }))
  // Die Meldung am Ende jedes Ladens: erst danach darf das nächste beginnen.
  let fertig = 0
  on('ui.toast', () => {
    fertig++
    return { value: undefined }
  })
  const laeufe: Record<string, string>[] = []
  on('process.run', (_$, e) => {
    if (e.argv.includes('-Command') && e.init?.env?.CW_ID) laeufe.push({ ...e.init.env } as Record<string, string>)
    return { value: done }
  })
  const von = (id: string) => laeufe.find(x => x.CW_ID === id && x.CW_URL !== undefined)

  await $.command.run({ command: 'waechter-werkzeuge', args: 'install meziantou' } as never)
  for (let i = 0; i < 20 && fertig < 1; i++) await write($, 'D:\\t\\warten.txt')
  expect(fertig).toBe(1)
  expect(von('meziantou')).toMatchObject({
    CW_URL: 'https://api.nuget.org/v3-flatcontainer/meziantou.analyzer/3.0.342/meziantou.analyzer.3.0.342.nupkg',
    CW_SHA: '6b20dc076d961a0a0378c7898149da76394da0401cae0ac9691196c91092855e',
    CW_ART: 'tar',
    CW_NAME: 'meziantou.zip',
    CW_TEILE:
      'analyzers/dotnet/roslyn5.0/cs/Meziantou.Analyzer.dll|analyzers/dotnet/roslyn5.6/cs/Meziantou.Analyzer.dll|analyzers/dotnet/roslyn5.9/cs/Meziantou.Analyzer.dll|configuration/none.editorconfig|LICENSE.txt',
    CW_STRIP: '0',
    CW_VER: '3.0.342',
    CW_ZIEL: 'C:\\Werkzeuge\\meziantou',
  })

  await $.command.run({ command: 'waechter-werkzeuge', args: 'install nounsanitized' } as never)
  for (let i = 0; i < 20 && fertig < 2; i++) await write($, 'D:\\t\\warten.txt')
  expect(fertig).toBe(2)
  expect(von('nounsanitized')).toMatchObject({
    CW_URL: 'https://registry.npmjs.org/eslint-plugin-no-unsanitized/-/eslint-plugin-no-unsanitized-4.1.5.tgz',
    CW_SHA: '0041e63a9a2e58b23bc6bcf1aea6b1f32898be2cc78e6d59dfcc5c37c2a49d36',
    CW_ART: 'tar',
    CW_NAME: 'nounsanitized.tgz',
    CW_TEILE: '',
    CW_STRIP: '1',
    CW_VER: '4.1.5',
    CW_ZIEL: 'C:\\Werkzeuge\\nounsanitized',
  })
  // Node.js kommt vor dem Plugin (Abhängigkeit über ESLint).
  const ids = laeufe.map(x => x.CW_ID)
  expect(ids.indexOf('node')).toBeGreaterThan(-1)
  expect(ids.indexOf('node')).toBeLessThan(ids.lastIndexOf('nounsanitized'))
})

// ====================================================================================== C#: Meziantou.Analyzer im Projektbau
const eben = (p: string): string => p.replace(/\\/g, '/').toLowerCase()
const PROPS_SCHALTER = '-p:CustomBeforeMicrosoftCommonProps='
const propsVon = (argv: readonly string[], geschrieben: Record<string, string>): string =>
  geschrieben[eben(argv.find(x => x.startsWith(PROPS_SCHALTER))?.slice(PROPS_SCHALTER.length) ?? '')] ?? ''
// Die eigene .globalconfig: der erste Include-Eintrag der Einstellungsdatei.
const regelnVon = (argv: readonly string[], geschrieben: Record<string, string>): string =>
  geschrieben[eben(/Include="([^"]+)"/.exec(propsVon(argv, geschrieben))?.[1] ?? '')] ?? ''

// Gespieltes C#-Projekt D:\Proj mit A.cs; da(pfad) beantwortet fs.exists (damit: ist Meziantou geladen?), ausgabe ist die Antwort
// des Baus.
function bauProjekt(on: On, da: (p: string) => boolean, ausgabe = '') {
  on('tool.call', () => toolAnswer as never)
  on('fs.list', () => ({ value: projectList }))
  on('fs.read', () => ({ value: 'class A { }\n' }))
  on('fs.exists', (_$, e) => ({ value: da(String(e.path)) }))
  const geschrieben: Record<string, string> = {}
  on('fs.write', (_$, e) => {
    geschrieben[eben(e.path)] = String(e.text)
    return { value: undefined }
  })
  const baue: string[][] = []
  on('process.run', (_$, e) => {
    const a = e.argv.map(String)
    if (a[0] === 'cmd') return { value: { ...done, stdout: 'C:\\Temp\r\n' } }
    if (a.includes('msbuild')) return { value: { ...done, stdout: JSON.stringify({ Items: { Compile: [{ FullPath: 'D:\\Proj\\A.cs' }] } }) } }
    if (a.includes('build') && a.includes('--no-restore')) {
      baue.push(a)
      return { value: { ...done, stdout: ausgabe } }
    }
    return { value: done }
  })
  return { geschrieben, baue }
}

const MA_DLL = (w: string, v: string) => `${w}\\meziantou\\analyzers\\dotnet\\roslyn${v}\\cs\\Meziantou.Analyzer.dll`
// Gemessen 28.11.2026 mit dotnet msbuild -getItem:Analyzer: roslyn5.12 und 5.9 -> roslyn5.9, 5.8 und 5.6 -> roslyn5.6,
// 5.5 und 5.0 -> roslyn5.0, roslyn4.14, leer oder fremder Wert -> keine DLL.
const MA_API = '$(CompilerApiVersion.Substring(6))'
const MA_EINTRAEGE = (w: string) => [
  `<ItemGroup Condition="'$(Language)' == 'C#' and $(CompilerApiVersion.StartsWith('roslyn'))">`,
  `<GlobalAnalyzerConfigFiles Include="${w}\\meziantou\\configuration\\none.editorconfig" />`,
  `<Analyzer Include="${MA_DLL(w, '5.9')}" Condition="$([MSBuild]::VersionGreaterThanOrEquals(${MA_API}, '5.9'))" />`,
  `<Analyzer Include="${MA_DLL(w, '5.6')}" Condition="$([MSBuild]::VersionGreaterThanOrEquals(${MA_API}, '5.6')) and $([MSBuild]::VersionLessThan(${MA_API}, '5.9'))" />`,
  `<Analyzer Include="${MA_DLL(w, '5.0')}" Condition="$([MSBuild]::VersionGreaterThanOrEquals(${MA_API}, '5.0')) and $([MSBuild]::VersionLessThan(${MA_API}, '5.6'))" />`,
]
const MA_AN = ['MA0009', 'MA0022', 'MA0042', 'MA0100', 'MA0129', 'MA0134', 'MA0147']

test('Zusatzregeln C#: ist Meziantou geladen, liest der Bau die DLL je Roslyn-Fassung und schaltet nur die sieben Regeln ein', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const { geschrieben, baue } = bauProjekt(on, p => /\\meziantou\\/i.test(p))

  const text = await write($, 'D:\\Proj\\A.cs')

  expect(text).toContain('✔ «A.cs»')
  expect(baue.length).toBe(1)
  const props = propsVon(baue[0] ?? [], geschrieben)
  for (const z of MA_EINTRAEGE('C:\\Werkzeuge')) expect(props).toContain(z)
  const regeln = regelnVon(baue[0] ?? [], geschrieben)
  for (const r of MA_AN) expect(regeln).toContain(`dotnet_diagnostic.${r}.severity = warning`)
  // Die zwei langsamen Regeln bleiben wie bisher eingestellt, die eigene Datei schaltet nichts ab (das macht none.editorconfig).
  expect(regeln).toContain('dotnet_code_quality.CA5390.interprocedural_analysis_kind = None')
  expect(regeln).toContain('dotnet_code_quality.CA5403.excluded_symbol_names = <Main>$')
  expect(regeln).not.toContain('severity = none')
  expect(regeln).not.toContain('MA0155')
  expect(regeln.trim().split('\n').length).toBe(12)
})

test('Zusatzregeln C#: ohne geladenes Meziantou und ohne none.editorconfig bleibt der Bau wie bisher (Gegenprobe)', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  let da = (_p: string) => false
  const { geschrieben, baue } = bauProjekt(on, p => da(p))

  // Beide Baue schreiben dieselben Dateien: den Stand gleich nach jedem Bau festhalten (Gegenprüfung 28.11.2026 - vorher prüfte der
  // Prüfsatz zweimal den zweiten Bau)
  const stand: { props: string; regeln: string }[] = []
  expect(await write($, 'D:\\Proj\\A.cs')).toContain('✔ «A.cs»')
  stand.push({ props: propsVon(baue[0] ?? [], geschrieben), regeln: regelnVon(baue[0] ?? [], geschrieben) })
  // Nur die DLL, die Datei, die alle anderen Regeln ausschaltet, fehlt: dann auch keine DLL (sonst liefen alle MA-Regeln).
  da = p => /\\meziantou\\analyzers\\/i.test(p)
  expect(await write($, 'D:\\Proj\\A.cs')).toContain('✔ «A.cs»')
  stand.push({ props: propsVon(baue[1] ?? [], geschrieben), regeln: regelnVon(baue[1] ?? [], geschrieben) })

  expect(baue.length).toBe(2)
  for (const s of stand) {
    expect(s.props).toContain('GlobalAnalyzerConfigFiles')
    expect(s.props).not.toContain('<Analyzer')
    expect(s.props).not.toContain('meziantou')
    expect(s.regeln).not.toContain('MA0')
    expect(s.regeln.trim().split('\n').length).toBe(5)
  }
})

// Gegenprüfung 28.11.2026: bindet ein Projekt Meziantou selbst ein, ohne dass der Wächter es geladen hat, zeigt der Wächter dessen
// MA-Meldungen nicht (die eingeschalteten MA-Regeln gelten nur mit dem eigenen, geladenen Werkzeug).
test('Zusatzregeln C#: ohne geladenes Meziantou zeigt der Wächter keine MA-Meldung, auch wenn der Bau sie ausgibt', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const ausgabe = 'D:\\Proj\\A.cs(3,5): warning MA0009: Regular expressions should not be vulnerable to Denial of Service attacks [D:\\Proj\\Mod.csproj]\r\n'
  bauProjekt(on, () => false, ausgabe)
  const text = await write($, 'D:\\Proj\\A.cs')
  expect(text).toContain('✔ «A.cs»')
  expect(text).not.toContain('MA0009')
})

// Gegenprüfung 28.11.2026: RunAnalyzers=false in der Projektdatei schaltete sonst jede Analyse-Regel ab, auch die roten.
test('Zusatzregeln C#: der Bau erzwingt die Analyse (RunAnalyzers, RunAnalyzersDuringBuild), ein Projekt kann sie nicht abschalten', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const { baue } = bauProjekt(on, () => false)
  await write($, 'D:\\Proj\\A.cs')
  expect(baue.length).toBe(1)
  expect(baue[0]).toContain('-p:RunAnalyzers=true')
  expect(baue[0]).toContain('-p:RunAnalyzersDuringBuild=true')
})

test('Zusatzregeln C#: ein Werkzeugordner mit ; % $ @ wird für MSBuild maskiert', { options: { ...VERTRAUT.options, werkzeug_ordner: 'C:\\W;1%$@' } }, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const { geschrieben, baue } = bauProjekt(on, p => /\\meziantou\\/i.test(p))

  await write($, 'D:\\Proj\\A.cs')

  const props = propsVon(baue[0] ?? [], geschrieben)
  expect(props).toContain('<Analyzer Include="C:\\W%3B1%25%24%40\\meziantou\\analyzers\\dotnet\\roslyn5.9\\cs\\Meziantou.Analyzer.dll"')
  expect(props).toContain('<GlobalAnalyzerConfigFiles Include="C:\\W%3B1%25%24%40\\meziantou\\configuration\\none.editorconfig" />')
})

test('Zusatzregeln C#: die sieben MA-Regeln sind Vorschläge (kein Fehler), MA0155 und andere MA-Regeln erscheinen nicht', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const zeile = (n: number, code: string, msg: string) => `D:\\Proj\\A.cs(${n},5): warning ${code}: ${msg} (https://github.com/meziantou/Meziantou.Analyzer/blob/main/docs/Rules/${code}.md) [D:\\Proj\\Mod.csproj]\r\n`
  const ausgabe =
    zeile(3, 'MA0009', 'Regular expressions should not be vulnerable to Denial of Service attacks') +
    zeile(4, 'MA0022', 'Return Task.FromResult instead of returning null') +
    zeile(5, 'MA0042', "Use await instead of 'Result'") +
    zeile(6, 'MA0100', 'Await task before disposing of resources') +
    zeile(7, 'MA0129', 'Await task in using statement') +
    zeile(8, 'MA0134', 'Observe result of async calls') +
    zeile(9, 'MA0147', 'Avoid async void method for delegate') +
    zeile(10, 'MA0155', 'Do not use async void methods') +
    zeile(11, 'MA0001', 'StringComparison is missing')
  bauProjekt(on, p => /\\meziantou\\/i.test(p), ausgabe)

  const text = await write($, 'D:\\Proj\\A.cs')

  expect(text).toContain('✔ «A.cs»')
  expect(text).not.toContain('✖')
  expect(text).toContain('7 Verbesserungsvorschläge')
  for (const r of ['MA0009', 'MA0022', 'MA0042', 'MA0100', 'MA0129']) expect(text).toContain(r)
  expect(text).not.toContain('MA0155')
  expect(text).not.toContain('MA0001')
})

// ====================================================================================== JavaScript: eslint-plugin-no-unsanitized
// Die Einstellungsdatei bis 27.11.2026 (ohne Plugin muss sie Zeichen für Zeichen gleich bleiben).
const ESLINT_ALT = [
  "import js from '@eslint/js'",
  "import globals from 'globals'",
  'export default [',
  '  js.configs.recommended,',
  '  {',
  "    languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: { ...globals.browser, ...globals.node } },",
  "    rules: { 'no-unused-vars': 'warn', 'no-undef': 'warn', 'prefer-const': 'warn', 'no-var': 'warn', eqeqeq: ['warn', 'smart'] },",
  '  },',
  ']',
  '',
].join('\n')
const KONFIG = 'C:\\Werkzeuge\\eslint\\code-waechter.eslint.config.mjs'

function eslintLauf(on: On, da: (p: string) => boolean, ruleId: string) {
  on('tool.call', () => toolAnswer as never)
  on('fs.exists', (_$, e) => ({ value: da(String(e.path)) }))
  on('fs.read', () => ({ value: 'const el = document.body\nel.innerHTML = name\n' }))
  const geschrieben: Record<string, string> = {}
  on('fs.write', (_$, e) => {
    geschrieben[String(e.path)] = String(e.text)
    return { value: undefined }
  })
  const meldung = JSON.stringify([{ messages: [{ ruleId, message: 'Unsafe assignment to innerHTML', line: 2, column: 1, severity: 1 }] }])
  const laeufe: string[][] = []
  on('process.run', (_$, e) => {
    if (!e.argv.includes('-c')) return { value: done }
    laeufe.push(e.argv.map(String))
    return { value: { ...done, exitCode: 1, stdout: meldung } }
  })
  return { geschrieben, laeufe }
}

test('Zusatzregeln JS: mit no-unsanitized lädt die Einstellungsdatei den Plugin neben ESLint, seine Meldung ist ein Vorschlag mit Regelnamen', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const { geschrieben, laeufe } = eslintLauf(on, () => true, 'no-unsanitized/property')

  const text = await write($, 'D:\\j\\x.js')

  expect(text).toContain('✔ «x.js»')
  expect(text).not.toContain('✖')
  expect(text).toContain('Zeile 2: no-unsanitized/property «Unsafe assignment to innerHTML»')
  for (const grenze of ['ESLint endete', 'ESLint lief nicht', 'ESLint-Einstellungsdatei', 'ESLint-Ausgabe']) expect(text).not.toContain(grenze)
  expect(laeufe.length).toBe(1)
  expect(laeufe[0]).toContain(KONFIG)
  const konfig = geschrieben[KONFIG] ?? ''
  expect(konfig).toContain("import noUnsanitized from '../nounsanitized/index.js'")
  expect(konfig).toContain("plugins: { 'no-unsanitized': noUnsanitized },")
  expect(konfig).toContain("'no-unsanitized/method': 'warn', 'no-unsanitized/property': 'warn'")
  // Der feste relative Pfad trifft den Ort des Plugins: beide liegen im selben Werkzeugordner.
  expect(TOOLS.find(d => d.id === 'eslint')?.exe).toBe('eslint\\node_modules\\eslint\\bin\\eslint.js')
  expect(TOOLS.find(d => d.id === 'nounsanitized')?.exe).toBe('nounsanitized\\index.js')
})

test('Zusatzregeln JS: auch no-unsanitized/method ist ein Vorschlag mit Regelnamen', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  eslintLauf(on, () => true, 'no-unsanitized/method')

  const text = await write($, 'D:\\j\\m.js')

  expect(text).toContain('✔ «m.js»')
  expect(text).toContain('Zeile 2: no-unsanitized/method «Unsafe assignment to innerHTML»')
})

test('Zusatzregeln JS: ohne no-unsanitized läuft ESLint wie bisher, ein Plugin-Name aus der Datei wird nicht als Regel übernommen', VERTRAUT, async ($, on) => {
  withTemp(on)
  mock.clock(on)
  const { geschrieben, laeufe } = eslintLauf(on, p => !/\\nounsanitized\\/i.test(p), 'no-unsanitized/method')

  const text = await write($, 'D:\\j\\y.js')

  expect(laeufe.length).toBe(1)
  expect(geschrieben[KONFIG]).toBe(ESLINT_ALT)
  expect(text).toContain('✔ «y.js»')
  // ESLint lief durch: keine Grenze von ESLint (die gespielte Umgebung hat kein Gitleaks, das steht dort offen).
  for (const grenze of ['ESLint endete', 'ESLint lief nicht', 'ESLint-Einstellungsdatei', 'ESLint-Ausgabe']) expect(text).not.toContain(grenze)
  expect(text).not.toContain('no-unsanitized/method')
  expect(text).toContain('Zeile 2: ESLint «Unsafe assignment to innerHTML»')
})
