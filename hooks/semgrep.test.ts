import { expect, test } from 'claude-code/testing'
import { setLang } from './i18n'
import { semgrepLesen, semgrepPruefen, semgrepRegelText, semgrepRegeln, semgrepText, stapeln } from './semgrep'
import { scannen, scannenOrdner } from './sicherheit'
import type { Lauf, Umgebung } from './sicherheit'

// Erwartungen aus dem Bauplan (Stufe 2 Punkt 10: Quellen Datei, Befehlszeile, Netz, Worker-Anfrage; Ziele SQL, Programmstart, Pfad,
// Deserialisierung, Protokoll), aus dem Auftrag vom 28.11.2026 (Netz rot, lokal Hinweis, SQL nur das Abfrage-Argument, Bereiniger),
// aus der Schlussprüfung vom 28.11.2026 (Befunde 1-9: kein shlex.quote, kein basename, Befehl als Text, Shell als Programm, Anfrage in
// Variable und als Parameter, args ohne Main, ZipFile aus Bytes, server, \r und \n zusammen, StreamReader/StreamWriter) und aus der
// Messung mit Semgrep 1.186.0 am 28.11.2026 (Kopf von semgrep.ts). Das Verhalten der Regeln prüft die echte Messung:
// einer eigenen Regelprobe (regelprobe.py, 33 Regeln, jede schlechte Probe gefunden,
// keine gute gemeldet; mit --gegenprobe jeder Fehler aus gegenproben.json rot); hier steht, was in den Regeln stehen muss.

const SPRACHEN = ['PY', 'CS', 'JS']
const ZIELE = ['SQL', 'PROGRAMM', 'CODE', 'PFAD', 'DESER', 'PROTOKOLL']
const regel = (id: string): any => semgrepRegeln().find(r => r.id === id)
const teil = (id: string, feld: string): string => JSON.stringify(regel(id)?.[feld] ?? null)
// Ein Muster muss als ganzer Text dastehen; mit ~ davor genügt ein Teil (Namen in einer Liste von Methoden).
const hat = (json: string, w: string): boolean => (w.startsWith('~') ? json.includes(JSON.stringify(w.slice(1)).slice(1, -1)) : json.includes(JSON.stringify(w)))
const pruefe = (art: string, json: string, worte: string[]) => {
  for (const w of worte) expect(`${art}: ${hat(json, w) ? w : `fehlt ${w}`}`).toBe(`${art}: ${w}`)
}
// Der reguläre Ausdruck einer Metavariablen in einem Muster (erster Treffer); "(?i)" am Anfang wird zum Schalter i.
function regexVon(x: any, mv: string): RegExp | undefined {
  if (Array.isArray(x)) {
    for (const y of x) {
      const r = regexVon(y, mv)
      if (r) return r
    }
    return undefined
  }
  if (!x || typeof x !== 'object') return undefined
  const m = x['metavariable-regex']
  if (m?.metavariable === mv) {
    const f = /^\(\?([is]+)\)/.exec(m.regex)
    return f ? new RegExp(m.regex.slice(f[0].length), f[1]) : new RegExp(m.regex)
  }
  for (const y of Object.values(x)) {
    const r = regexVon(y, mv)
    if (r) return r
  }
  return undefined
}
// Ziele bzw. Bereiniger einer Regel, deren Text alle Teile enthält
const mitTeil = (id: string, feld: string, ...teile: string[]): any[] =>
  ((regel(id)?.[feld] ?? []) as any[]).filter(z => teile.every(w => JSON.stringify(z).includes(JSON.stringify(w).slice(1, -1))))

test('Semgrep-Regeln: je Sprache jedes Ziel aus dem Netz und lokal, das Protokoll nur aus dem Netz - 33 Regeln', () => {
  const soll: string[] = []
  for (const s of SPRACHEN) for (const z of ZIELE) for (const h of ['NETZ', 'LOKAL']) if (!(z === 'PROTOKOLL' && h === 'LOKAL')) soll.push(`FLUSS-${s}-${z}-${h}`)
  const ist = semgrepRegeln().map(r => r.id)
  expect(ist.length).toBe(33)
  expect([...ist].sort()).toEqual([...soll].sort())
  for (const r of semgrepRegeln()) {
    expect(r.mode).toBe('taint')
    expect(r.languages).toEqual(r.id.startsWith('FLUSS-PY') ? ['python'] : r.id.startsWith('FLUSS-CS') ? ['csharp'] : ['javascript', 'typescript'])
  }
})

test('Semgrep-Regeln: aus dem Netz ein Fehler (ERROR), lokal und das Protokoll ein Hinweis (WARNING)', () => {
  for (const r of semgrepRegeln()) {
    expect(`${r.id} ${r.severity}`).toBe(`${r.id} ${r.id.endsWith('-NETZ') && !r.id.includes('-PROTOKOLL-') ? 'ERROR' : 'WARNING'}`)
  }
})

test('Semgrep-Regeln: Quellen aus dem Bauplan (Netz, Worker-Anfrage, Befehlszeile, Konsole, Datei), jede nur als Ganzes', () => {
  const soll: Record<string, string[]> = {
    'PY-NETZ': ['flask.request.$P', '~request$', '~GET', '~BaseHTTPRequestHandler', 'self.path', '$S.recv(...)', 'requests.$M(...)', 'urllib.request.urlopen(...)'],
    'PY-LOKAL': ['sys.argv', 'sys.argv[$A:]', '$P.parse_args(...)', 'input(...)', 'sys.stdin', 'open(...)', '$P.read_text(...)'],
    'CS-NETZ': ['Request.$P', '$C.Request.$P', '~Query', '~Form', '~Headers', '~RawUrl', '$S.Receive($B, ...)', '$T.GetStream()', '~GetStringAsync', '~ReadAsStringAsync', '~DownloadString',
      // Schlussprüfung Befund 3: Anfrage in einer Variablen (HttpListener-Beispiel der Microsoft-Doku) und als Parameter
      '$T $V = $C.Request;\n...', 'var $V = $C.Request;\n...', '$R $M(..., HttpRequest $V, ...) { ... }', '$R $M(..., HttpListenerRequest $V, ...) { ... }',
      '(..., HttpRequest $V, ...) => $B', '$V.$P'],
    'CS-LOKAL': ['~Main(string[] $A)', '~StartupEventArgs', 'Environment.GetCommandLineArgs()', 'Console.ReadLine()', '~ReadAllText',
      // Schlussprüfung Befund 3: args im Programm ohne Main, nicht in Methoden, Klassen und Lambdas mit eigenem args
      'args', '$R $M(...) { ... }', 'class $K { ... }', '(..., args, ...) => $B'],
    'JS-NETZ': ['$REQ.$P', '$REQ.$M(...)', '~(req|request)', '~query', '~body', '~params', '~headers', '~|url|', '~|json|', "~$S.on('data'", "~'message'", 'fetch(...)', 'axios(...)',
      // Schlussprüfung Befund 7: Cloudflare-WebSocket "server", Durable Object webSocketMessage
      '~|client|server|', 'class $K { ... async webSocketMessage($W, $D) { ... } ... }'],
    'JS-LOKAL': ['process.argv', '$RL.question(...)', 'fs.readFileSync(...)', '~fs/promises'],
  }
  for (const [art, worte] of Object.entries(soll)) {
    const [s, h] = art.split('-')
    for (const z of ZIELE) {
      if (z === 'PROTOKOLL' && h === 'LOKAL') continue
      pruefe(`${art} ${z}`, teil(`FLUSS-${s}-${z}-${h}`, 'pattern-sources'), worte)
    }
  }
  // Ohne exact zählte Semgrep jeden Teil einer Quelle mit (gemessen: open("fest.txt") wurde ein Pfad aus einer Datei).
  for (const r of semgrepRegeln()) {
    for (const q of r['pattern-sources'] as any[]) expect(q['by-side-effect'] === true || q.exact === true).toBe(true)
  }
})

test('Semgrep-Regeln: Ziele aus dem Bauplan (SQL, Programmstart, Code, Pfad, Deserialisierung, Protokoll)', () => {
  const soll: Record<string, string[]> = {
    'PY-SQL': ['$C.execute($X, ...)', '$C.executemany($X, ...)', 'sqlalchemy.text($X, ...)'],
    // Schlussprüfung Befund 2: Befehl als Text auch ohne shell=True, Shell als erstes Element einer Liste bzw. als Programm
    'PY-PROGRAMM': ['os.system($X)', 'subprocess.$F($X, ..., shell=True, ...)', 'os.popen($X, ...)', 'subprocess.$F($X, ...)',
      'subprocess.$F([$CMD, ..., $X, ...], ...)', 'asyncio.create_subprocess_exec($CMD, ..., $X, ...)'],
    'PY-CODE': ['eval($X, ...)', 'exec($X, ...)'], // code-waechter:ok SEC-EVAL (erwartetes Muster)
    'PY-PFAD': ['open($X, ...)', 'os.$F($X, ...)', '~remove', 'shutil.$F($X, ...)', '~read_text'],
    'PY-DESER': ['pickle.$F($X, ...)', 'yaml.load($X, ...)', 'yaml.load($X, Loader=yaml.SafeLoader)', 'marshal.$F($X, ...)'],
    'PY-PROTOKOLL': ['logging.$M(...)', '~info'],
    'CS-SQL': ['$C.CommandText = $X', '~SqlCommand', '~SqliteCommand', '~FromSqlRaw', '~ExecuteSqlRaw'],
    'CS-PROGRAMM': ['Process.Start($X, ...)', 'Process.Start($A, $X)', 'new ProcessStartInfo($X, ...)', '~FileName = $X', '~Arguments = $X'],
    'CS-CODE': ['Assembly.$M($X, ...)', 'CSharpScript.$M($X, ...)'],
    // Schlussprüfung Befund 9: new StreamReader(pfad), new StreamWriter(pfad)
    'CS-PFAD': ['File.$M($X, ...)', '~ReadAllText', '~Delete', 'Directory.$M($X, ...)', '~FileStream', '~(StreamReader|StreamWriter)$'],
    'CS-DESER': ['~BinaryFormatter', '~TypeNameHandling'],
    'CS-PROTOKOLL': ['~Log(Trace|Debug|Information', 'Log.$M(...)'],
    'JS-SQL': ['$DB.$M($X, ...)', '~(prepare|', '~exec', '~query'],
    'JS-PROGRAMM': ['child_process.$F($X, ...)', '~(exec|execSync|', '~shell: true', 'child_process.$F($CMD, [..., $X, ...], ...)', 'child_process.$F($CMD, $X, ...)'],
    'JS-CODE': ['eval($X)', 'new Function(...)', 'vm.$F($X, ...)'], // code-waechter:ok SEC-EVAL (erwartetes Muster)
    'JS-PFAD': ['fs.$M($X, ...)', '~writeFileSync', '~readFile', '~unlink', '~sendFile'],
    'JS-DESER': ['$S.unserialize($X, ...)', 'v8.deserialize($X)'],
    'JS-PROTOKOLL': ['console.$M(...)', '~log'],
  }
  for (const [art, worte] of Object.entries(soll)) {
    const [s, z] = art.split('-')
    for (const h of z === 'PROTOKOLL' ? ['NETZ'] : ['NETZ', 'LOKAL']) pruefe(`${art}-${h}`, teil(`FLUSS-${s}-${z}-${h}`, 'pattern-sinks'), worte)
  }
})

test('Semgrep-Regeln: eine Text-Methode wie replace ist kein Pfad (gemessen: 9 falsche Hinweise wie f.read().replace(...)), read_text schon', () => {
  for (const h of ['NETZ', 'LOKAL']) {
    const ziel = (regel(`FLUSS-PY-PFAD-${h}`)['pattern-sinks'] as any[]).find(z => JSON.stringify(z).includes('"$X.$M(...)"'))
    const methoden = new RegExp(ziel.patterns.find((x: any) => x['metavariable-regex'])['metavariable-regex'].regex)
    expect(methoden.test('replace')).toBe(false)
    expect(methoden.test('read_text')).toBe(true)
    expect(methoden.test('unlink')).toBe(true)
  }
})

test('Semgrep-Regeln: open und rename nur an einem pathlib-Pfad, ZipFile aus Bytes ist kein Pfad (Schlussprüfung Befund 5)', () => {
  for (const h of ['NETZ', 'LOKAL']) {
    const id = `FLUSS-PY-PFAD-${h}`
    // Jeder Empfänger: nur Namen, die allein pathlib hat (z.open("manifest.json") auf einem ZipFile, df.rename(columns=...))
    const jeder = mitTeil(id, 'pattern-sinks', '$X.$M(...)').filter(z => !JSON.stringify(z).includes('pathlib'))
    expect(jeder.length).toBe(1)
    const m = regexVon(jeder[0], '$M')
    for (const [name, soll] of [['open', false], ['rename', false], ['replace', false], ['read_text', true], ['unlink', true]] as [string, boolean][]) {
      expect(`${id} jeder Empfänger ${name}: ${m?.test(name)}`).toBe(`${id} jeder Empfänger ${name}: ${soll}`)
    }
    // pathlib.Path(...), a / b und p = Path(...): auch open, rename, rmdir
    const pfad = mitTeil(id, 'pattern-sinks', '$X.$M(...)', 'pathlib.Path(...)', '$X = pathlib.Path(...)\n...', '$X = $A / $B\n...')
    expect(pfad.length).toBe(1)
    const mp = regexVon(pfad[0], '$M')
    for (const name of ['open', 'rename', 'rmdir']) expect(`${id} pathlib ${name}: ${mp?.test(name)}`).toBe(`${id} pathlib ${name}: true`)
    // ZipFile: nicht über io.BytesIO(...) und nicht über eine Variable aus io.BytesIO(...)
    const zip = mitTeil(id, 'pattern-sinks', 'zipfile.ZipFile($X, ...)')
    expect(zip.length).toBe(1)
    pruefe(`${id} ZipFile`, JSON.stringify(zip[0]), ['zipfile.ZipFile(io.BytesIO(...), ...)', '$X = io.BytesIO(...)\n...'])
  }
})

test('Semgrep-Regeln: SQL prüft nur das Abfrage-Argument (focus-metavariable $X), Parameter daneben bleiben sicher', () => {
  for (const s of SPRACHEN) {
    for (const h of ['NETZ', 'LOKAL']) {
      for (const ziel of regel(`FLUSS-${s}-SQL-${h}`)['pattern-sinks'] as any[]) {
        expect(JSON.stringify(ziel)).toContain('"focus-metavariable":"$X"')
      }
    }
  }
})

test('Semgrep-Regeln: Bereiniger aus Auftrag und Schlussprüfung (Zahl, Prüfung gegen den Ordner, encodeURIComponent; kein shlex.quote, kein basename)', () => {
  const soll: Record<string, string[]> = {
    'PY-SQL': ['int(...)', 'float(...)'],
    'PY-PROGRAMM': ['int(...)'],
    'PY-PFAD': ['int(...)', 'werkzeug.utils.secure_filename(...)', '$P = os.path.$N(...)\n...', '$P.startswith(...)', 'os.path.$N($P).startswith(...)',
      '~^(realpath|abspath|normpath)$', '$P = $Q.resolve(...)\n...', '$P.is_relative_to(...)'],
    'CS-SQL': ['$T.Parse(...)', '~int|long'],
    'CS-PFAD': ['$T.Parse(...)', 'var $P = Path.GetFullPath(...);\n...', '$T $P = Path.GetFullPath(...);\n...', '$P.StartsWith(...)', 'Path.GetFullPath($P).StartsWith(...)'],
    'JS-SQL': ['Number(...)', 'parseInt(...)'],
    'JS-PROGRAMM': ['encodeURIComponent(...)'],
    'JS-PFAD': ['Number(...)', 'parseInt(...)', '$P = path.$N(...)\n...', '$P.startsWith(...)', 'path.$N(..., $P).startsWith(...)', '~^(resolve|normalize|join)$'],
  }
  for (const [art, worte] of Object.entries(soll)) {
    const [s, z] = art.split('-')
    for (const h of ['NETZ', 'LOKAL']) pruefe(`${art}-${h}`, teil(`FLUSS-${s}-${z}-${h}`, 'pattern-sanitizers'), worte)
  }
  // Schlussprüfung Befund 1: shlex.quote schützt unter Windows nicht (Python-Doku shlex), als Programm nie.
  // Befund 4: basename, Path(...).name, Path.GetFileName(WithoutExtension), path.basename und encodeURIComponent geben ".." zurück.
  const verboten: Record<string, string[]> = {
    'PY-PROGRAMM': ['shlex.quote'], 'PY-PFAD': ['basename', '.name"'], 'CS-PFAD': ['GetFileName'], 'JS-PFAD': ['basename', 'encodeURIComponent'],
  }
  for (const [art, worte] of Object.entries(verboten)) {
    const [s, z] = art.split('-')
    for (const h of ['NETZ', 'LOKAL']) for (const w of worte) expect(`${art}-${h}: ${teil(`FLUSS-${s}-${z}-${h}`, 'pattern-sanitizers').includes(w) ? w : 'frei'}`).toBe(`${art}-${h}: frei`)
  }
  // Voller Pfad: startswith allein (ohne realpath/abspath/normpath bzw. resolve/normalize/join) zählt nicht.
  const py = regexVon(mitTeil('FLUSS-PY-PFAD-NETZ', 'pattern-sanitizers', 'os.path.$N')[0], '$N')
  for (const [n, s] of [['realpath', true], ['abspath', true], ['normpath', true], ['join', false], ['basename', false]] as [string, boolean][]) expect(`py ${n}: ${py?.test(n)}`).toBe(`py ${n}: ${s}`)
  const js = regexVon(mitTeil('FLUSS-JS-PFAD-NETZ', 'pattern-sanitizers', 'path.$N')[0], '$N')
  for (const [n, s] of [['resolve', true], ['normalize', true], ['join', true], ['basename', false], ['relative', false]] as [string, boolean][]) expect(`js ${n}: ${js?.test(n)}`).toBe(`js ${n}: ${s}`)
  // Gemessen 28.11.2026: Bereiche "if (...) { ... }" liefen auf einem grossen Prüfprogramm (16'781 Zeilen ohne Main) in die Zeitgrenze von
  // Semgrep (Timeout FLUSS-CS-PFAD-*); die Prüfung wirkt darum ab dem Aufruf (by-side-effect) und steht in keinem if-Bereich.
  for (const s of SPRACHEN) {
    for (const h of ['NETZ', 'LOKAL']) {
      const pr = mitTeil(`FLUSS-${s}-PFAD-${h}`, 'pattern-sanitizers', '$P')
      expect(pr.length).toBe(s === 'PY' ? 4 : 2)
      for (const x of pr) expect(`${s}-${h}: ${x['by-side-effect'] === true && !JSON.stringify(x).includes('if ')}`).toBe(`${s}-${h}: true`)
    }
  }
  // encodeURIComponent lässt ' stehen: für SQL kein Schutz. Deserialisieren macht nichts sicher.
  expect(teil('FLUSS-JS-SQL-NETZ', 'pattern-sanitizers')).not.toContain('encodeURIComponent')
  for (const s of SPRACHEN) expect(teil(`FLUSS-${s}-DESER-NETZ`, 'pattern-sanitizers')).toBe('null')
})

test('Semgrep-Regeln: Protokoll nur mit \\r UND \\n bereinigt, ReplaceLineEndings nur mit festem Text (Schlussprüfung Befund 8)', () => {
  const muster = (id: string): string[] => ((regel(id)['pattern-sanitizers'] ?? []) as any[]).map(x => x.pattern).filter((x: unknown) => typeof x === 'string')
  const py = muster('FLUSS-PY-PROTOKOLL-NETZ')
  expect(py).toContain('$X.replace("\\r", ...).replace("\\n", ...)')
  expect(py).toContain('$X.replace("\\n", ...).replace("\\r", ...)')
  expect(py).not.toContain('$X.replace("\\r", ...)')
  expect(py).not.toContain('$X.replace("\\n", ...)')
  const cs = muster('FLUSS-CS-PROTOKOLL-NETZ')
  expect(cs).toContain('$X.Replace("\\r", ...).Replace("\\n", ...)')
  expect(cs).toContain("$X.Replace('\\n', ...).Replace('\\r', ...)")
  for (const einzeln of ['$X.Replace("\\r", ...)', '$X.Replace("\\n", ...)', "$X.Replace('\\r', ...)", "$X.Replace('\\n', ...)", '$X.ReplaceLineEndings(...)']) {
    expect(`${einzeln}: ${cs.includes(einzeln)}`).toBe(`${einzeln}: false`)
  }
  // ReplaceLineEndings() setzt Environment.NewLine ein (Microsoft-Doku): nur "" , " " oder string.Empty bereinigt
  const r = regexVon(mitTeil('FLUSS-CS-PROTOKOLL-NETZ', 'pattern-sanitizers', '$X.ReplaceLineEndings($R)')[0], '$R')
  for (const [arg, soll] of [['""', true], ['" "', true], ['string.Empty', true], ['Environment.NewLine', false], ['"\\n"', false], ['"\\r\\n"', false], ['zeile', false]] as [string, boolean][]) {
    expect(`ReplaceLineEndings(${arg}): ${r?.test(arg)}`).toBe(`ReplaceLineEndings(${arg}): ${soll}`)
  }
})

test('Semgrep-Regeln: Shell als Programm erkannt (cmd, powershell, bash, .bat), andere Programme nicht (Schlussprüfung Befund 2)', () => {
  const py = regexVon(mitTeil('FLUSS-PY-PROGRAMM-NETZ', 'pattern-sinks', 'subprocess.$F([$CMD, ..., $X, ...], ...)')[0], '$CMD')
  for (const [cmd, soll] of [['"cmd"', true], ["'cmd.exe'", true], ['r"C:\\Windows\\System32\\cmd.exe"', true], ['"powershell"', true], ['"pwsh.exe"', true],
    ['"bash"', true], ['"werkzeug.bat"', true], ['"Start.CMD"', true], ['"ping"', false], ['"programm"', false], ['"cmdtool"', false], ['befehl', false]] as [string, boolean][]) {
    expect(`py ${cmd}: ${py?.test(cmd)}`).toBe(`py ${cmd}: ${soll}`)
  }
  expect(mitTeil('FLUSS-PY-PROGRAMM-NETZ', 'pattern-sinks', 'asyncio.create_subprocess_exec($CMD, ..., $X, ...)').length).toBe(1)
  // Text ohne shell=True: eine Liste (auch in einer Variablen aus [...]) ist kein Ziel
  const text = (regel('FLUSS-PY-PROGRAMM-NETZ')['pattern-sinks'] as any[]).filter(z => JSON.stringify(z).includes('"subprocess.$F($X, ...)"'))
  expect(text.length).toBe(1)
  pruefe('py Text', JSON.stringify(text[0]), ['subprocess.$F([...], ...)', '$X = [...]\n...'])
  const js = regexVon(mitTeil('FLUSS-JS-PROGRAMM-NETZ', 'pattern-sinks', 'child_process.$F($CMD, [..., $X, ...], ...)')[0], '$CMD')
  for (const [cmd, soll] of [["'cmd.exe'", true], ['"powershell"', true], ['`bash`', true], ["'C:\\\\Windows\\\\System32\\\\cmd.exe'", true], ["'werkzeug.bat'", true],
    ["'ping'", false], ["'node'", false], ['programm', false]] as [string, boolean][]) {
    expect(`js ${cmd}: ${js?.test(cmd)}`).toBe(`js ${cmd}: ${soll}`)
  }
})

test('Semgrep-Regeln: StreamReader/StreamWriter nur mit Pfad, ein Strom ist kein Ziel (Schlussprüfung Befund 9)', () => {
  const ziel = mitTeil('FLUSS-CS-PFAD-NETZ', 'pattern-sinks', '(StreamReader|StreamWriter)$')
  expect(ziel.length).toBe(1)
  const x = regexVon(ziel[0], '$X')
  for (const [arg, soll] of [['name', true], ['Request.Form["name"]', true], ['streamPfad', true], ['Path.Combine(basis, datei)', true],
    ['ctx.Request.Body', false], ['client.GetStream()', false], ['await http.GetStreamAsync(url)', false], ['await r.Content.ReadAsStreamAsync()', false],
    ['netStream', false], ['strom', false], ['body', false], ['new MemoryStream(daten)', false]] as [string, boolean][]) {
    expect(`StreamReader(${arg}): ${x?.test(arg)}`).toBe(`StreamReader(${arg}): ${soll}`)
  }
  pruefe('Strom', JSON.stringify(ziel[0]), ['new $T((Stream $S), ...)', 'new $T((MemoryStream $S), ...)', 'var $X = await $H.GetStreamAsync(...);\n...', 'var $X = $C.Request.Body;\n...'])
})

test('Semgrep-Meldung: beim Pfad der volle Pfad und "..", nicht mehr "nur den Dateinamen" (Schlussprüfung Befund 4)', () => {
  setLang('de')
  const de = semgrepText('FLUSS-PY-PFAD-NETZ')
  expect(de).toContain('Den vollen Pfad bilden')
  expect(de).toContain('".."')
  expect(de).not.toContain('Nur den Dateinamen nehmen')
  setLang('en')
  expect(semgrepText('FLUSS-CS-PFAD-NETZ')).toContain('Build the full path')
  setLang('de')
})

test('Semgrep-Regeltext: gültiges JSON; für .pyw nur die Python-Regeln, für .mts/.cts nur TypeScript', () => {
  expect(JSON.parse(semgrepRegelText()).rules.length).toBe(33)
  const py = JSON.parse(semgrepRegelText('python')).rules
  expect(py.length).toBe(11)
  for (const r of py) expect(r.languages).toEqual(['python'])
  const ts = JSON.parse(semgrepRegelText('typescript')).rules
  expect(ts.length).toBe(11)
  for (const r of ts) expect(r.languages).toEqual(['typescript'])
})

// ---- Auswertung (semgrepLesen). JSON wie gemessen mit 1.186.0 (gekürzt auf die Felder, die der Leser braucht).
const PY = 'D:\\p\\werkzeug\\app.py'
const CS = 'D:\\p\\App\\Programm.cs'
const fund = (id: string, line: number, severity: string, pfad = 'D:\\p\\werkzeug\\app.py', col = 5) =>
  ({ check_id: id, path: pfad, start: { line, col, offset: 0 }, end: { line, col: col + 3, offset: 0 }, extra: { message: id, severity, lines: 'requires login' } })
const ausgabe = (results: unknown[], gelesen: string[], errors: unknown[] = [], skipped: unknown[] = []) =>
  JSON.stringify({ version: '1.186.0', results, errors, paths: { scanned: gelesen }, skipped_rules: skipped })

test('Semgrep-Leser: ein Fund kommt mit Zeile, Spalte, Regel und Text zur Datei; aus dem Netz rot, lokal ein Hinweis', () => {
  setLang('de')
  const l = semgrepLesen(ausgabe([fund('FLUSS-PY-PROGRAMM-NETZ', 4, 'ERROR'), fund('FLUSS-PY-PFAD-LOKAL', 9, 'WARNING')], [PY]), [PY], new Map())
  const f = l.funde.get(PY) ?? []
  expect(f.length).toBe(2)
  expect(f[0]).toMatchObject({ line: 4, col: 5, code: 'FLUSS-PY-PROGRAMM-NETZ', schwer: true, scanner: 'Semgrep' })
  expect(f[0].text).toContain('Programmstart mit Text aus dem Netz')
  expect(f[1]).toMatchObject({ line: 9, code: 'FLUSS-PY-PFAD-LOKAL', schwer: false })
  expect(f[1].text).toContain('aus Befehlszeile, Konsole oder Datei')
  expect(f[1].text).toContain('eigenen Werkzeug')
  expect(l.luecken.size).toBe(0)
  expect(l.fehler).toBe(undefined)
})

test('Semgrep-Leser: der Pfad der Ausgabe wird der Datei zugeordnet (Schrägstrich, Gross/Klein), fremde Pfade nicht', () => {
  const l = semgrepLesen(ausgabe([fund('FLUSS-PY-SQL-NETZ', 2, 'ERROR', 'd:/P/Werkzeug/APP.py'), fund('FLUSS-PY-SQL-NETZ', 2, 'ERROR', 'D:\\anders\\app.py')], ['d:/p/werkzeug/app.py']), [PY], new Map())
  expect(l.funde.get(PY)?.length).toBe(1)
  expect(l.funde.size).toBe(1)
  expect(l.luecken.size).toBe(0)
})

test('Semgrep-Leser: aus Netz und lokal in derselben Zeile bleibt nur der Fund aus dem Netz, je Zeile und Ziel einer', () => {
  const l = semgrepLesen(ausgabe([fund('FLUSS-CS-PROGRAMM-LOKAL', 7, 'WARNING', CS, 13), fund('FLUSS-CS-PROGRAMM-NETZ', 7, 'ERROR', CS, 13),
    fund('FLUSS-CS-PROGRAMM-NETZ', 7, 'ERROR', CS, 30), fund('FLUSS-CS-PFAD-LOKAL', 7, 'WARNING', CS, 40)], [CS]), [CS], new Map())
  const f = l.funde.get(CS) ?? []
  expect(f.map(x => `${x.code}:${x.col}`)).toEqual(['FLUSS-CS-PROGRAMM-NETZ:13', 'FLUSS-CS-PFAD-LOKAL:40'])
})

test('Semgrep-Leser: "code-waechter:ok SICHERHEIT" in der Zeile nimmt den Fund aus; in Prüfdateien gibt es nur Hinweise', () => {
  const text = 'import os\nos.system(x)  # code-waechter:ok SICHERHEIT\nos.system(y)\n'
  const l = semgrepLesen(ausgabe([fund('FLUSS-PY-PROGRAMM-NETZ', 2, 'ERROR'), fund('FLUSS-PY-PROGRAMM-NETZ', 3, 'ERROR')], [PY]), [PY], new Map([[PY, text]]))
  expect((l.funde.get(PY) ?? []).map(x => x.line)).toEqual([3])
  const pruef = 'D:\\p\\werkzeug\\tests\\test_app.py'
  const p = semgrepLesen(ausgabe([fund('FLUSS-PY-PROGRAMM-NETZ', 3, 'ERROR', pruef)], [pruef]), [pruef], new Map())
  expect(p.funde.get(pruef)?.[0]?.schwer).toBe(false)
})

test('Semgrep-Leser: ein Syntaxfehler ist eine Lücke ohne Text der Datei; ein Fehler ohne Datei lässt den Lauf nicht gelten', () => {
  setLang('de')
  const syntax = { code: 3, level: 'warn', type: 'Syntax error', path: PY, message: `Syntax error at line ${PY}:3:\n \`geheimer Text\` was unexpected`, spans: [{ file: PY, start: { line: 3, col: 1 } }] }
  const l = semgrepLesen(ausgabe([], [PY], [syntax]), [PY], new Map())
  expect(l.luecken.get(PY)?.[0]).toContain('Semgrep kann die Datei in Zeile 3 nicht lesen')
  expect(l.luecken.get(PY)?.[0]).toContain('nicht ausgewertet')
  expect(l.luecken.get(PY)?.[0]).not.toContain('geheimer Text')
  // Gemessen an gültigem C# 12 (Sammlungsausdruck): die Art ist eine Liste, die Meldung zeigt Text der Datei.
  const teilweise = { code: 3, level: 'warn', type: ['PartialParsing', [{ path: CS, start: { line: 211, col: 93 }, end: { line: 211, col: 94 } }]],
    message: `Syntax error at line ${CS}:211:\n \`geheim, Kategorie\` was unexpected`, path: CS, spans: [{ file: CS, start: { line: 211, col: 93 } }] }
  const p = semgrepLesen(ausgabe([], [CS], [teilweise]), [CS], new Map())
  expect(p.luecken.get(CS)?.[0]).toContain('Semgrep kann die Datei in Zeile 211 nicht lesen')
  expect(p.luecken.get(CS)?.[0]).not.toContain('geheim')
  const regelFehler = { code: 7, level: 'error', type: 'SemgrepError', message: 'invalid configuration file found (1 configs were invalid)' }
  const k = semgrepLesen(ausgabe([fund('FLUSS-PY-SQL-NETZ', 2, 'ERROR')], [], [regelFehler]), [PY], new Map())
  expect(k.fehler).toContain('invalid configuration file')
  expect(k.funde.size).toBe(0)
})

test('Semgrep-Leser: eine Datei, die Semgrep nicht gelesen hat, ist eine Lücke; übersprungene Regeln auch; kaputte Ausgabe ist ein Fehler', () => {
  setLang('de')
  const l = semgrepLesen(ausgabe([], [PY]), [PY, CS], new Map())
  expect(l.luecken.has(PY)).toBe(false)
  expect(l.luecken.get(CS)?.[0]).toContain('übersprungen')
  const r = semgrepLesen(ausgabe([], [PY], [], [{ rule_id: 'FLUSS-PY-SQL-NETZ' }]), [PY], new Map())
  expect(r.luecken.get(PY)?.[0]).toContain('Regeln übersprungen')
  expect(semgrepLesen('Traceback (most recent call last)', [PY], new Map()).fehler).toContain('nicht lesbar')
})

// ---- Lauf (semgrepPruefen) mit gespieltem Semgrep: es schreibt sein JSON in die Datei hinter --output (wie gemessen).
const EXE = 'C:\\Users\\x\\.local\\bin\\semgrep.exe'
const ARBEIT = 'C:\\Temp\\code-waechter'
type Antwort = { code: number; json?: string; stderr?: string } | Lauf
function sgUmgebung(antwort: (argv: string[]) => Antwort, exe: string | null = EXE, dateien: Record<string, string> = {}) {
  const aufrufe: { argv: string[]; cwd?: string; timeoutMs?: number }[] = []
  const geschrieben: string[] = []
  const fs = new Map<string, string>(Object.entries(dateien))
  const u: Umgebung = {
    run: async (argv, opts) => {
      if (argv[0] !== EXE) return { ok: false, reason: 'kein Lauf erwartet' }
      aufrufe.push({ argv, cwd: opts.cwd, timeoutMs: opts.timeoutMs })
      const a = antwort(argv)
      if ('ok' in a) return a
      const aus = argv[argv.indexOf('--output') + 1] ?? ''
      if (a.json !== undefined) fs.set(aus, a.json)
      return { ok: true, exitCode: a.code, stdout: '', stderr: a.stderr ?? '', truncated: false }
    },
    python: ['py'],
    exe: async () => undefined,
    workDir: async () => ARBEIT,
    read: async p => fs.get(p),
    write: async (p, text) => {
      geschrieben.push(p)
      fs.set(p, text)
    },
    kennung: 'probe',
    semgrep: async () => exe ?? undefined,
  }
  return { u, aufrufe, geschrieben, fs }
}
const frist = (ms: number) => async () => ms

test('Semgrep-Lauf: Aufruf wie gemessen - ohne Messdaten und Versionsabfrage, eigene Regeln im Arbeitsordner, voller Pfad, kein Konto', async () => {
  const { u, aufrufe, geschrieben } = sgUmgebung(() => ({ code: 0, json: ausgabe([fund('FLUSS-PY-PROGRAMM-NETZ', 4, 'ERROR')], [PY]) }))
  const e = (await semgrepPruefen(u, [PY], new Map(), frist(120000))).get(PY)
  expect(e?.funde.length).toBe(1)
  expect(e?.liefen).toEqual(['Semgrep'])
  expect(e?.luecken).toEqual([])
  expect(aufrufe.length).toBe(1)
  // --jobs=1: mit mehreren Fäden fehlten gemessen ab und zu Funde, ohne Fehlermeldung (Kopf von semgrepArgv).
  expect(aufrufe[0].argv).toEqual([EXE, '--metrics=off', '--disable-version-check', '--quiet', '--json', '--no-rewrite-rule-ids', '--jobs=1',
    '--config', 'C:\\Temp\\code-waechter\\semgrep-regeln.json', '--output', 'C:\\Temp\\code-waechter\\semgrep-probe.json', PY])
  expect(aufrufe[0].cwd).toBe(ARBEIT)
  expect(aufrufe[0].timeoutMs).toBe(120000)
  for (const verboten of ['--pro', '--pro-intrafile', 'login', 'auto', 'p/default']) expect(aufrufe[0].argv).not.toContain(verboten)
  expect(geschrieben).toContain('C:\\Temp\\code-waechter\\semgrep-regeln.json')
})

test('Semgrep-Lauf: geprüft wird eine Kopie im Arbeitsordner (kleine Endung); Funde, Lücken und Markierung gehören zur echten Datei', async () => {
  // Gemessen 28.11.2026: echte Dateien in einem grossen Projektordner (Git) 6,6 s je Datei nur für die Zielsuche, Kopien im Temp-Ordner nicht.
  const echt = 'D:\\p\\werkzeug\\Haupt.PY'
  const kopie = 'C:\\Temp\\code-waechter\\semgrep-probe\\0.py'
  const text = 'import os\nos.system(a)  # code-waechter:ok SICHERHEIT\nos.system(b)\n'
  const { u, aufrufe, fs } = sgUmgebung(() => ({ code: 0, json: ausgabe([fund('FLUSS-PY-PROGRAMM-NETZ', 2, 'ERROR', kopie), fund('FLUSS-PY-PROGRAMM-NETZ', 3, 'ERROR', kopie)], [kopie]) }))
  const e = (await semgrepPruefen(u, [echt], new Map([[echt, text]]), frist(120000))).get(echt)
  expect(aufrufe[0].argv[aufrufe[0].argv.length - 1]).toBe(kopie)
  expect(aufrufe[0].argv).not.toContain(echt)
  expect(fs.get(kopie)).toBe(text)
  expect((e?.funde ?? []).map(f => `${f.code}:${f.line}`)).toEqual(['FLUSS-PY-PROGRAMM-NETZ:3'])
  expect(e?.liefen).toEqual(['Semgrep'])
  const leer = sgUmgebung(() => ({ code: 0, json: ausgabe([], []) }))
  expect((await semgrepPruefen(leer.u, [echt], new Map([[echt, text]]), frist(120000))).get(echt)?.luecken[0]).toContain('übersprungen')
})

test('Semgrep-Lauf: die Regeldatei wird nur neu geschrieben, wenn sie sich geändert hat', async () => {
  const regeln = 'C:\\Temp\\code-waechter\\semgrep-regeln.json'
  const gleich = sgUmgebung(() => ({ code: 0, json: ausgabe([], [PY]) }), EXE, { [regeln]: semgrepRegelText() })
  await semgrepPruefen(gleich.u, [PY], new Map(), frist(120000))
  expect(gleich.geschrieben).not.toContain(regeln)
  const alt = sgUmgebung(() => ({ code: 0, json: ausgabe([], [PY]) }), EXE, { [regeln]: '{"rules": []}' })
  await semgrepPruefen(alt.u, [PY], new Map(), frist(120000))
  expect(alt.geschrieben).toContain(regeln)
})

test('Semgrep-Lauf: fehlendes Programm, Absturz, Zeitgrenze, Code 7, keine Ausgabe sind Lücken, nie "geprüft"', async () => {
  setLang('de')
  const fehlt = sgUmgebung(() => ({ code: 0 }), null)
  const a = (await semgrepPruefen(fehlt.u, [PY], new Map(), frist(120000))).get(PY)
  expect(a?.luecken[0]).toContain('Semgrep fehlt (einmalig: py -3.14 -m pipx install semgrep)')
  expect(a?.liefen).toEqual([])
  expect(fehlt.aufrufe.length).toBe(0)
  const weg = sgUmgebung(() => ({ ok: false, reason: 'abgestürzt' }))
  expect((await semgrepPruefen(weg.u, [PY], new Map(), frist(120000))).get(PY)?.luecken[0]).toContain('Semgrep lief nicht: abgestürzt')
  const zeit = sgUmgebung(() => ({ code: 0, json: ausgabe([], [PY]) }))
  const z = (await semgrepPruefen(zeit.u, [PY], new Map(), frist(500))).get(PY)
  expect(z?.luecken[0]).toContain('Zeitgrenze')
  expect(zeit.aufrufe.length).toBe(0)
  const sieben = sgUmgebung(() => ({ code: 7, json: ausgabe([], []) }))
  const s = (await semgrepPruefen(sieben.u, [PY], new Map(), frist(120000))).get(PY)
  expect(s?.luecken[0]).toContain('Semgrep lief nicht')
  expect(s?.liefen).toEqual([])
  const leer = sgUmgebung(() => ({ code: 2, stderr: 'Invalid scanning root\n' }))
  const n = (await semgrepPruefen(leer.u, [PY], new Map(), frist(120000))).get(PY)
  expect(n?.luecken[0]).toContain('keine Ausgabe geschrieben')
  expect(n?.liefen).toEqual([])
  const ueber = sgUmgebung(() => ({ code: 0, json: ausgabe([], []) }))
  const ue = (await semgrepPruefen(ueber.u, [PY], new Map(), frist(120000))).get(PY)
  expect(ue?.luecken[0]).toContain('übersprungen')
  expect(ue?.liefen).toEqual([])
})

test('Semgrep-Lauf: .pyw und .mts laufen je mit den Regeln ihrer Sprache und --scan-unknown-extensions, die anderen zusammen', async () => {
  const PYW = 'D:\\p\\werkzeug\\fenster.pyw'
  const MTS = 'D:\\p\\web\\worker.mts'
  const TS = 'D:\\p\\web\\index.ts'
  const { u, aufrufe, fs } = sgUmgebung(argv => ({ code: 0, json: ausgabe([], argv.filter(a => /^D:\\p\\/.test(a))) }))
  const erg = await semgrepPruefen(u, [PY, PYW, MTS, TS], new Map(), frist(120000))
  expect(aufrufe.length).toBe(3)
  const mit = (f: string) => aufrufe.find(a => a.argv.includes(f))?.argv ?? []
  expect(mit(PY)).toContain(TS)
  expect(mit(PY)).not.toContain('--scan-unknown-extensions')
  expect(mit(PYW)).toContain('--scan-unknown-extensions')
  expect(mit(PYW)).toContain('C:\\Temp\\code-waechter\\semgrep-regeln-python.json')
  expect(mit(MTS)).toContain('--scan-unknown-extensions')
  expect(mit(MTS)).toContain('C:\\Temp\\code-waechter\\semgrep-regeln-typescript.json')
  expect(JSON.parse(fs.get('C:\\Temp\\code-waechter\\semgrep-regeln-python.json') ?? '{}').rules.every((r: any) => r.languages.join() === 'python')).toBe(true)
  for (const f of [PY, PYW, MTS, TS]) expect(erg.get(f)?.liefen).toEqual(['Semgrep'])
})

test('Semgrep-Lauf: sehr viele Dateien gehen in Stapeln unter 30000 Zeichen, jede Datei genau einmal', async () => {
  const viele = Array.from({ length: 700 }, (_, i) => `D:\\Daten\\Ein langer Ordnername fuer die Probe\\Unterordner\\datei_${i}.py`)
  const st = stapeln(viele)
  expect(st.length).toBeGreaterThan(1)
  for (const s of st) expect(s.reduce((n, f) => n + f.length + 3, 0)).toBeLessThanOrEqual(30000)
  expect(st.flat()).toEqual(viele)
  const { u, aufrufe } = sgUmgebung(argv => ({ code: 0, json: ausgabe([], argv.filter(a => a.endsWith('.py'))) }))
  const erg = await semgrepPruefen(u, viele, new Map(), frist(120000))
  expect(aufrufe.length).toBe(st.length)
  expect([...erg.values()].every(e => e.liefen.includes('Semgrep'))).toBe(true)
})

test('Semgrep-Einbau: scannen prüft .py, .cs, .ts und .js mit Semgrep, eine .txt nicht; ohne Feld semgrep läuft nichts', async () => {
  const { u, aufrufe } = sgUmgebung(argv => ({ code: 0, json: ausgabe([fund('FLUSS-PY-PROGRAMM-NETZ', 1, 'ERROR', argv[argv.length - 1])], [argv[argv.length - 1] ?? '']) }))
  const e = await scannen(u, PY, 'import os\n')
  expect(e.funde.some(f => f.scanner === 'Semgrep' && f.schwer && f.code === 'FLUSS-PY-PROGRAMM-NETZ')).toBe(true)
  expect(e.liefen).toContain('Semgrep')
  for (const f of [CS, 'D:\\p\\web\\index.ts', 'D:\\p\\web\\app.js']) expect((await scannen(u, f, 'x\n')).liefen).toContain('Semgrep')
  await scannen(u, 'D:\\p\\notiz.txt', 'Text\n')
  expect(aufrufe.length).toBe(4)
  const ohne = sgUmgebung(() => ({ code: 0, json: ausgabe([], [PY]) }))
  delete ohne.u.semgrep
  const o = await scannen(ohne.u, PY, 'import os\n')
  expect(o.liefen).not.toContain('Semgrep')
  expect(ohne.aufrufe.length).toBe(0)
})

test('Semgrep-Einbau: scannenOrdner prüft alle Dateien der drei Sprachen in EINEM Aufruf und ordnet die Funde zu', async () => {
  const TS = 'D:\\p\\web\\index.ts'
  const TXT = 'D:\\p\\notiz.txt'
  // Semgrep prüft die Kopien im Spiegel des Ordner-Scans (<Arbeitsordner>\spiegel-<Chat>\<Nummer>\<Name>), nicht die echten Dateien.
  const SP = 'C:\\Temp\\code-waechter\\spiegel-probe'
  const kopien = [`${SP}\\0\\app.py`, `${SP}\\1\\Programm.cs`, `${SP}\\2\\index.ts`]
  const { u, aufrufe } = sgUmgebung(() => ({ code: 0, json: ausgabe([fund('FLUSS-CS-PFAD-NETZ', 2, 'ERROR', kopien[1])], kopien) }), EXE,
    { [PY]: 'import os\n', [CS]: 'class P {\n  void M() {}\n}\n', [TS]: 'export {}\n', [TXT]: 'Text\n' })
  const erg = await scannenOrdner(u, [PY, CS, TS, TXT])
  expect(aufrufe.length).toBe(1)
  expect(aufrufe[0].argv.slice(-3)).toEqual(kopien)
  expect(erg.get(CS)?.funde.some(f => f.scanner === 'Semgrep' && f.line === 2 && f.schwer)).toBe(true)
  expect(erg.get(PY)?.liefen).toContain('Semgrep')
  expect(erg.get(TXT)?.liefen).not.toContain('Semgrep')
  expect(aufrufe[0].argv).toContain('C:\\Temp\\code-waechter\\semgrep-probe-ordner.json')
})

test('Semgrep: Meldung auf Englisch, wenn Englisch eingestellt ist', () => {
  setLang('en')
  expect(semgrepText('FLUSS-JS-SQL-NETZ')).toContain('SQL query contains text from the network')
  expect(semgrepText('FLUSS-PY-PFAD-LOKAL')).toContain('from the command line, console or a file')
  setLang('de')
  expect(semgrepText('FLUSS-JS-SQL-NETZ')).toContain('SQL-Abfrage enthält Text aus dem Netz')
  expect(semgrepText('FLUSS-JS-SQL-NETZ')).toContain('Datenfluss innerhalb einer Funktion')
})
