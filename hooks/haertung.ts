// Härtungs-Hinweise für C# (06.11.2026, aus den Befunden einer Sicherheitsprüfung).
// Gemeldet werden Fehlerarten, die sich am Text erkennen lassen. Es sind Hinweise, nie Fehler: Ob eine Stelle wirklich
// eine Lücke ist, entscheidet der Mensch. Gegenprobe im Test: die alten Lücken schlagen an, ihre berichtigte Form
// bleibt still.
// - Abfangen jedes Fehlers als "leer": catch ohne when, dessen ganzer Inhalt "return null" (oder leer) ist.
// - Schleife über eine Antwort von aussen ohne Grenze: foreach über eine Antwort (await, JSON), die im Rumpf sammelt,
//   ohne Take, break oder Mengenprüfung.
import { t } from './i18n'

export type HardFinding = { file: string; line: number; col: number; code: string; text: string }

export const HARD_CODE = 'HAERTUNG'

// Die Zeilennummer zu einer Stelle im Text.
function lineAt(text: string, index: number): number {
  let n = 1
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) n++
  return n
}

// Kommentare und Zeichenketten durch Leerzeichen ersetzen, Länge und Zeilenumbrüche bleiben: so stimmen die Stellen, und
// "catch" oder "{" in einem Text zählt nicht. Ein Durchgang über den Text. Wortgetreue (@"…") und rohe ("""…""") Zeichenketten
// werden wie normale behandelt, ihr Inhalt zählt also auch nicht.
export function blankCode(text: string): string {
  const out = text.split('')
  const n = text.length
  let i = 0
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to; k++) if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' '
  }
  while (i < n) {
    const c = text[i]
    const d = text[i + 1]
    if (c === '/' && d === '/') {
      const end = text.indexOf('\n', i)
      const stop = end === -1 ? n : end
      blank(i, stop)
      i = stop
    } else if (c === '/' && d === '*') {
      const end = text.indexOf('*/', i + 2)
      const stop = end === -1 ? n : end + 2
      blank(i, stop)
      i = stop
    } else if (c === '"' && text.startsWith('"""', i)) {
      const end = text.indexOf('"""', i + 3)
      const stop = end === -1 ? n : end + 3
      blank(i + 1, stop - 1)
      i = stop
    } else if (c === '"') {
      const verbatim = i > 0 && (text[i - 1] === '@' || (text[i - 1] === '$' && i > 1 && text[i - 2] === '@'))
      let k = i + 1
      while (k < n) {
        if (verbatim && text[k] === '"' && text[k + 1] === '"') k += 2
        else if (!verbatim && text[k] === '\\') k += 2
        else if (text[k] === '"' || (!verbatim && text[k] === '\n')) break
        else k++
      }
      blank(i + 1, Math.min(k, n))
      i = Math.min(k + 1, n)
    } else if (c === "'") {
      let k = i + 1
      while (k < n && k < i + 12 && text[k] !== "'" && text[k] !== '\n') k += text[k] === '\\' ? 2 : 1
      if (k < n && text[k] === "'") {
        blank(i + 1, k)
        i = k + 1
      } else i++
    } else i++
  }
  return out.join('')
}

// Das Ende eines Klammerpaars (Index der schliessenden Klammer) im bereinigten Text, oder -1.
function closing(code: string, open: number): number {
  const o = code[open]
  const c = o === '(' ? ')' : o === '{' ? '}' : ']'
  let depth = 0
  for (let k = open; k < code.length; k++) {
    if (code[k] === o) depth++
    else if (code[k] === c && --depth === 0) return k
  }
  return -1
}

// ---- Abfangen jedes Fehlers als "leer"
// Beispiel: catch (Exception) { return null; } machte aus "Passwort-Tresor gerade nicht lesbar" ein "kein Passwort".
const CATCH_ALL = /\bcatch\b\s*(?:\(\s*(?:System\.)?Exception(?:\s+@?\w+)?\s*\)\s*)?(?=\{)/g
const EMPTY_RETURN =
  /^return\s+(?:null|default(?:\s*\([^()]*\))?|string\.Empty|""|Array\.Empty\s*<[^<>]+>\s*\(\s*\)|Enumerable\.Empty\s*<[^<>]+>\s*\(\s*\)|new\s+(?:List|HashSet|Dictionary)\s*<[^;]*>\s*\(\s*\)|\[\s*\]|new\s*\(\s*\))\s*;$/

// Bewusste Stellen: "code-waechter:ok HAERTUNG" in einem Kommentar der Zeile der Schleife bzw. des catch oder im catch-Rumpf
// (wie bei den Sicherheitsmustern), z. B. wo null ausdrücklich "unlesbar" heisst.
const OK_MARK = /code-waechter:ok\s+HAERTUNG\b/
function marked(text: string, from: number, to: number): boolean {
  const lineStart = text.lastIndexOf('\n', from) + 1
  const lineEnd = text.indexOf('\n', from)
  return OK_MARK.test(text.slice(lineStart, Math.max(to, lineEnd === -1 ? text.length : lineEnd)))
}

function catchAllAsEmpty(text: string, code: string, file: string): HardFinding[] {
  const found: HardFinding[] = []
  for (const m of code.matchAll(CATCH_ALL)) {
    const open = (m.index ?? 0) + m[0].length
    const close = closing(code, open)
    if (close === -1 || marked(text, m.index ?? 0, close)) continue
    // Im bereinigten Text sind Zeichenketten leer: "" bleibt "", also stimmt der Vergleich auch für return "".
    const body = code.slice(open + 1, close).replace(/\s+/g, ' ').trim()
    if (!EMPTY_RETURN.test(body)) continue
    found.push({
      file,
      line: lineAt(text, m.index ?? 0),
      col: 0,
      code: HARD_CODE,
      text: t(
        'Härtung: jeder Fehler wird hier zu "leer" – "gerade nicht lesbar" ist nicht "leer". Nur den eindeutigen Fall als leer werten (catch … when), sonst "unlesbar" weitergeben oder protokollieren.',
        'hardening: every error becomes "empty" here – "cannot be read right now" is not "empty". Treat only the clear case as empty (catch … when), otherwise pass on "unreadable" or log it.',
      ),
    })
  }
  return found
}

// ---- Schleife über eine Antwort von aussen ohne Grenze
// Beispiel: foreach über die Treffer zweier Such-Antworten, jeder kam in eine gespeicherte Liste, ohne Obergrenze.
const FOREACH = /\bforeach\s*\(/g
// Woher eine Antwort von aussen kommt: ein Netzaufruf mit await (Name mit Http, Api, Twitch, Suche, Get…Async usw.).
// Gemessen am 06.11.2026 an einem WPF-Programm mit 117 Dateien: "jedes await" und "jede JSON-Umwandlung" meldeten 15 Stellen
// im berichtigten Code (eigene Dateien, Task.Run, Gerätelisten); mit nur Netzaufrufen bleibt er still, die alte Lücke schlägt an.
const OUTSIDE =
  /\bawait\b(?![^;]*\bTask\s*\.\s*Run\b)[^;]*?\b(?:\w*(?:Http|Api|Helix|Twitch|Tavily|Websuche|Suche|Search|Fetch|Download|Abfrage|Anfrage)\w*|Get\w*Async|Post\w*Async|Send\w*Async|ReadFromJsonAsync|GetFromJsonAsync|ReadAsStringAsync)\b/
const COLLECTS = /\.\s*(?:Add|AddRange|Append|AppendLine|Enqueue|Push|Insert|TryAdd)\s*\(|\+=/
const BOUNDED = /\.\s*Take\s*\(|\bbreak\s*;|\.\s*(?:Count|Length)\b\s*(?:>=|>|<|<=|==)|(?:>=|>|<|<=)\s*\w+\s*\.\s*(?:Count|Length)\b|\bCount\s*\(\s*\)\s*(?:>=|>|<|<=)/

// Die Zuweisung des Namens vor der Schleife (die letzte davor), bis zu ihrem Semikolon.
function assignmentBefore(code: string, name: string, before: number): string | undefined {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`(?<![\\w.])${esc}\\s*(?:\\?\\?)?=(?![=>])`, 'g')
  let last = -1
  for (const m of code.slice(0, before).matchAll(re)) last = (m.index ?? 0) + m[0].length
  if (last === -1) return undefined
  const end = code.indexOf(';', last)
  return code.slice(last, end === -1 ? Math.min(code.length, last + 2000) : end)
}

function unboundedLoops(text: string, code: string, file: string): HardFinding[] {
  const found: HardFinding[] = []
  for (const m of code.matchAll(FOREACH)) {
    const open = (m.index ?? 0) + m[0].length - 1
    const close = closing(code, open)
    if (close === -1 || marked(text, m.index ?? 0, close)) continue
    const head = code.slice(open + 1, close)
    const inAt = /\bin\b/.exec(head)
    if (!inAt) continue
    const source = head.slice(inAt.index + 2)
    if (BOUNDED.test(source)) continue
    // Woher die Folge kommt: der erste Name der Quelle (grunddaten in "(grunddaten?.Treffer ?? …)").
    const root = /^[\s(]*@?([A-Za-z_]\w*)/.exec(source)?.[1]
    const outside = root !== undefined && OUTSIDE.test(assignmentBefore(code, root, m.index ?? 0) ?? '')
    if (!outside) continue
    // Der Rumpf: ein Block oder eine einzelne Anweisung.
    let k = close + 1
    while (k < code.length && /\s/.test(code[k])) k++
    const bodyEnd = code[k] === '{' ? closing(code, k) : code.indexOf(';', k)
    if (bodyEnd === -1) continue
    const body = code.slice(k, bodyEnd + 1)
    if (!COLLECTS.test(body) || BOUNDED.test(body)) continue
    found.push({
      file,
      line: lineAt(text, m.index ?? 0),
      col: 0,
      code: HARD_CODE,
      text: t(
        'Härtung: Schleife über eine Antwort von aussen sammelt ohne Grenze – Anzahl begrenzen (Take, Obergrenze mit break), sonst bläht eine aufgeblähte Antwort Listen und Dateien auf.',
        'hardening: loop over an outside answer collects without a limit – limit the count (Take, upper bound with break), otherwise a bloated answer inflates lists and files.',
      ),
    })
  }
  return found
}

export function csHardeningHints(text: string, file: string): HardFinding[] {
  const code = blankCode(text)
  return [...catchAllAsEmpty(text, code, file), ...unboundedLoops(text, code, file), ...csThreats(text, code, file).filter(f => !f.schwer)].sort((a, b) => a.line - b.line)
}

// ---- Bedrohungen, die beim Schreiben erkennbar sind (21.11.2026, aus den 54 Funden eines Härtetests: 12 davon folgen
// einem Muster, das in jedem C#-Projekt gefährlich ist). Schwere Fälle (schwer) sind
// Fehler, die übrigen Hinweise. Gesucht wird je Methode (vom Kopf eines Mitglieds bis zum nächsten). Bewusste Stellen: wie oben
// "code-waechter:ok HAERTUNG" in der Zeile.
export type ThreatFinding = HardFinding & { regel: string; schwer: boolean }

// Kopf eines Typs oder Namensraums vor einer "{" (class Name, record Name(...), namespace A.B); "where T : class" ist keiner.
const TYPE_HEAD = /\b(?:class|struct|interface|enum|record|namespace)\s+@?[A-Za-z_][\w.]*[^;{}]*$/

// Die Mitglieder der Datei als Abschnitte [von, bis) im bereinigten Text, nach Klammertiefe: ein Abschnitt endet, wo ein
// Mitglied im Rumpf eines Typs mit "}" oder ";" endet. Am 21.11.2026 gemessen: die Erkennung über Zugriffswörter am Zeilenanfang
// trennte Methoden an "new X(" und "async (" und legte Methoden ohne Zugriffswort mit der vorigen zusammen.
function memberSegments(code: string): [number, number][] {
  const cuts = [0]
  const typ: boolean[] = [] // je offene "{": Rumpf eines Typs oder Namensraums?
  let last = 0
  for (let i = 0; i < code.length; i++) {
    const c = code[i]
    if (c === '{') {
      const isType = (typ.length === 0 || typ[typ.length - 1]) && TYPE_HEAD.test(code.slice(last, i))
      typ.push(isType)
      if (isType) cuts.push((last = i + 1))
    } else if (c === '}') {
      const war = typ.pop()
      if (war || typ[typ.length - 1]) cuts.push((last = i + 1))
    } else if (c === ';' && typ[typ.length - 1]) cuts.push((last = i + 1))
  }
  cuts.push(code.length)
  const out: [number, number][] = []
  for (let k = 0; k + 1 < cuts.length; k++) if (/\S/.test(code.slice(cuts[k], cuts[k + 1]))) out.push([cuts[k], cuts[k + 1]])
  return out
}

// Eine Bedrohung melden: Zeile im Originaltext; bewusst markierte Zeilen fallen weg.
function threat(text: string, file: string, at: number, regel: string, schwer: boolean, de: string, en: string): ThreatFinding | undefined {
  if (marked(text, at, at)) return undefined
  return { file, line: lineAt(text, at), col: 0, code: HARD_CODE, regel, schwer, text: t(`${schwer ? 'Sicherheit' : 'Härtung'} (${regel}): ${de}`, `${schwer ? 'security' : 'hardening'} (${regel}): ${en}`) }
}

// Die Argumente eines Aufrufs (bereinigter Text) ab der öffnenden Klammer.
function argsAt(code: string, open: number): string {
  const close = closing(code, open)
  return close === -1 ? code.slice(open + 1, open + 400) : code.slice(open + 1, close)
}

const SECRET_NAME = /\b\w*(?:token|passwor[dt]|kennwort|secret|codewort|api_?key)\w*\b/gi
const SECRET_HARMLESS = /(?:count|length|anzahl|gueltig|valid|expired|abgelaufen|ablauf|expiry|expires|hash|name|feld|field|art|kind|type|typ|source)$/i
const FRAMEWORK_CHECK = /\b(?:Uri|char|Char|string|String|Regex|Path|File|Directory|Enum|Type|Guid|DateTime|Math|IPAddress|Encoding|int|long|double|decimal|Int32|Int64|Double|Nullable|Environment|Debugger|object|Object)\s*\.\s*$/
const CHECK_CALL = /\b((?:Ist|Is|Enthaelt|Pruef|Check|Validate)\w*)\s*\(\s*([A-Za-z_]\w*)\s*[,)]/g

// Fest eingebaute Bytes: Literal-Bytes, "..."u8, Encoding.X.GetBytes("Literal"), stackalloc mit Werten, { 1, 2 } und [0x4B, ...].
// Eine Zeichenkette mit Einsetzungen ($"{benutzer}:{kennwort}") ist nicht fest.
const FIXED_BYTES = /GetBytes\s*\(\s*(?:@?"|\$@?"[^"{]*")|new\s+byte\s*\[\s*\d*\s*\]\s*\{|"[^"]*"u8|\bstackalloc\s+byte\s*\[\s*\d*\s*\]\s*\{|^\s*(?:new\s*\[\s*\]\s*)?[{[]\s*(?:0x[\da-f]|\d)/i

// Prüfdateien und Prüfprojekte (Tests, X.Tests, UnitTests, X.Probe): dort sind feste Werte gewollt
// (21.11.2026: ein Probe-Projekt prüft PBKDF2 mit einem festen Probe-Salz gegen .NET).
const TEST_PATH = /\.test\.|[\\/](?:[^\\/]*[._-])?(?:(?:Unit|Integration)?Tests?|Probe)[\\/]/i

// Ein Zufallsname in derselben Anweisung macht einen Temp-Pfad unvorhersagbar.
const RANDOM_NAME = /\bCreateTempSubdirectory\b|\bGetRandomFileName\b|\bGetTempFileName\b|\bGuid\s*\.\s*NewGuid\b/

// Startet der Abschnitt nur das eigene Programm, einen festen Programmnamen oder eine Adresse (Neustart als Admin, Link öffnen)?
// Dann kommt nichts aus Temp. Geprüft werden das erste Argument von Process.Start/ProcessStartInfo und FileName = ....
function ownStartOnly(text: string, code: string, from: number, seg: string): boolean {
  const ziele: string[] = []
  for (const m of seg.matchAll(/\b(?:Process\s*\.\s*Start|new\s+ProcessStartInfo)\s*\(/g)) {
    const open = from + (m.index ?? 0) + m[0].length - 1
    const a = splitArgs(text.slice(open + 1, open + 1 + argsAt(code, open).length))[0]?.trim() ?? ''
    // Process.Start(new ProcessStartInfo(...)) und Process.Start(psi): das Ziel steht im ProcessStartInfo bzw. bei FileName.
    if (a !== '' && !/^new\b/.test(a) && !/^@?[A-Za-z_]\w*$/.test(a)) ziele.push(a)
  }
  for (const m of seg.matchAll(/\bFileName\s*=\s*/g)) {
    const at = from + (m.index ?? 0) + m[0].length
    const end = code.slice(at).search(/[,;}\n]/)
    ziele.push(text.slice(at, end === -1 ? at + 200 : at + end).trim())
  }
  const eigen = (z: string): boolean =>
    /\b(?:Environment\s*\.\s*ProcessPath|Application\s*\.\s*ExecutablePath|GetCurrentProcess\s*\(\s*\)\s*\.\s*MainModule|AppContext\s*\.\s*BaseDirectory)\b/.test(z) ||
    /^@?"[^"{]*"$/.test(z)
  return ziele.length > 0 && ziele.every(eigen)
}

const DELETES = /\bFile\s*\.\s*Delete\s*\(|\bDirectory\s*\.\s*Delete\s*\(|\bDeleteSubKey(?:Tree)?\s*\(|\w*Loeschen\s*\(|\bDelete(?:\w*[A-Z]\w*)?\s*\(/

// Steht ein Löschen im Zweig eines Startschalters "--x"? Der Schalter muss im Code stehen (nicht im Kommentar).
function switchDeletes(code: string, from: number, raw: string): boolean {
  for (const m of raw.matchAll(/"--?[A-Za-z][\w-]*"/g)) {
    const at = from + (m.index ?? 0)
    if (code[at] !== '"') continue
    // case "--x": bis zum nächsten break/return
    const vor = code.slice(Math.max(0, at - 40), at)
    if (/\bcase\s*$/.test(vor)) {
      const ende = code.slice(at).search(/\bbreak\s*;|\breturn\b|\bcase\b|\bdefault\s*:/)
      if (DELETES.test(code.slice(at, ende === -1 ? at + 2000 : at + ende))) return true
      continue
    }
    // if (... "--x" ...): die Klammer der Bedingung, dann ein Block oder eine Anweisung
    const ifAt = code.slice(Math.max(0, at - 400), at).search(/\bif\s*\([^;{}]*$/)
    if (ifAt === -1) continue
    const open = code.indexOf('(', Math.max(0, at - 400) + ifAt)
    const close = closing(code, open)
    if (close === -1 || close < at) continue
    let k = close + 1
    while (k < code.length && /\s/.test(code[k])) k++
    const bodyEnd = code[k] === '{' ? closing(code, k) : code.indexOf(';', k)
    if (bodyEnd !== -1 && DELETES.test(code.slice(k, bodyEnd + 1))) return true
  }
  return false
}

// Der Wert eines Namens beim Aufruf: die letzte Zuweisung davor im Abschnitt (byte[] salt = ...), sonst ein Feld der Datei.
function valueAt(text: string, code: string, name: string, segFrom: number, before: number): string | undefined {
  const n = name.replace(/\s*\.\s*(?:ToArray|AsSpan|Span)\s*\(\s*\)\s*$/, '').trim()
  if (!/^@?[A-Za-z_]\w*$/.test(n)) return undefined
  const re = new RegExp(`(?<![\\w.])${n.replace('@', '')}\\s*=(?![=>])\\s*`, 'g')
  let last = -1
  for (const m of code.slice(segFrom, before).matchAll(re)) last = segFrom + (m.index ?? 0) + m[0].length
  if (last !== -1) {
    const end = code.indexOf(';', last)
    return text.slice(last, end === -1 ? last + 300 : end)
  }
  return fieldValue(text, code, n.replace('@', ''))
}

// Die Argumente eines Aufrufs an den Kommas der obersten Ebene.
function splitArgs(a: string): string[] {
  const out: string[] = []
  let tiefe = 0
  let start = 0
  for (let i = 0; i < a.length; i++) {
    const c = a[i]
    if (c === '(' || c === '[' || c === '{' || c === '<') tiefe++
    else if (c === ')' || c === ']' || c === '}' || c === '>') tiefe--
    else if (c === ',' && tiefe === 0) {
      out.push(a.slice(start, i))
      start = i + 1
    }
  }
  out.push(a.slice(start))
  return out
}

// Der Wert eines Felds oder einer Konstanten der Datei (const/readonly NAME = Wert;), sonst undefined. Nur einfache Namen.
function fieldValue(text: string, code: string, name: string): string | undefined {
  if (!/^[A-Za-z_]\w*$/.test(name)) return undefined
  const m = new RegExp(`\\b(?:const|readonly|static)\\b[^;={}()]*\\b${name}\\s*=\\s*`).exec(code)
  if (!m) return undefined
  const start = m.index + m[0].length
  const end = code.indexOf(';', start)
  return text.slice(start, end === -1 ? start + 300 : end)
}

function csThreats(text: string, code: string, file: string): ThreatFinding[] {
  if (TEST_PATH.test(file)) return []
  const out: (ThreatFinding | undefined)[] = []
  // Ein fester Ordner unter Temp in der Datei (Path.Combine(Path.GetTempPath(), "Name") oder %TEMP%): eine Anweisung im Code
  // (nicht im Kommentar), in der kein Zufallsname mitgebaut wird (Guid, GetRandomFileName ... in derselben Anweisung).
  const fixedTemp = [...code.matchAll(/\bPath\s*\.\s*Combine\s*\(\s*Path\s*\.\s*GetTempPath\s*\(\s*\)\s*,\s*\$?@?"|\bGetEnvironmentVariable\s*\(\s*"/g)].some(m => {
    const at = m.index ?? 0
    if (/GetEnvironmentVariable/.test(m[0]) && !/^GetEnvironmentVariable\s*\(\s*"(?:TEMP|TMP)"/.test(text.slice(at, at + 40))) return false
    const start = Math.max(code.lastIndexOf(';', at), code.lastIndexOf('{', at), code.lastIndexOf('}', at)) + 1
    const end = code.indexOf(';', at)
    return !RANDOM_NAME.test(code.slice(start, end === -1 ? code.length : end))
  })
  for (const [from, to] of memberSegments(code)) {
    const seg = code.slice(from, to)
    const raw = text.slice(from, to)
    const at = (re: RegExp): number => {
      const m = re.exec(seg)
      return m ? from + m.index : from
    }

    // R1: Programm aus einem festen Ordner unter Temp starten (dort kann ein anderes Programm eine DLL unterschieben; mit
    // Adminrechten läuft sie dann mit). Herunterladen und Starten liegen oft in verschiedenen Methoden (Update-Dienst),
    // darum gilt der Ordner für die ganze Datei; gemeldet wird der Start mit der Shell (UseShellExecute oder runas).
    if (fixedTemp && /\bProcess\s*\.\s*Start\b|\bProcessStartInfo\b/.test(seg) && /\bUseShellExecute\s*=\s*true\b|\bVerb\s*=\s*"runas"/i.test(raw) && !ownStartOnly(text, code, from, seg)) {
      const admin = /\bVerb\s*=\s*"runas"/i.test(raw)
      out.push(threat(text, file, at(/\bProcess\s*\.\s*Start\b|\bProcessStartInfo\b/), 'R1', admin,
        `ein Programm wird aus einem festen Ordner unter Temp gestartet${admin ? ' (mit Adminrechten)' : ''} – dort kann ein anderes Programm eine DLL unterschieben, die beim Start mitläuft. In einen frisch angelegten, zufällig benannten Ordner laden (Directory.CreateTempSubdirectory) und direkt vor dem Start prüfen, dass nur die eigene Datei darin liegt.`,
        `a program is started from a fixed folder under Temp${admin ? ' (with admin rights)' : ''} – another program can plant a DLL there that runs along. Download into a freshly created, randomly named folder (Directory.CreateTempSubdirectory) and check right before the start that only your own file is in it.`))
    }

    // R2: Schlüssel aus einem Kennwort mit festem Salz (Fehler) oder zu wenigen Runden (Hinweis). Salz und Runden stehen oft in
    // einem Feld oder einer Konstanten der Klasse; deren Wert wird nachgeschlagen.
    for (const m of seg.matchAll(/\bRfc2898DeriveBytes\s*(?:\.\s*Pbkdf2\s*)?\(/g)) {
      const open = from + (m.index ?? 0) + m[0].length - 1
      const argText = text.slice(open + 1, open + 1 + argsAt(code, open).length)
      const teile = splitArgs(argText)
      const werte = teile.map(x => fieldValue(text, code, x.trim()) ?? x)
      // Das Salz: das zweite Argument oder "salt:" (nicht das Kennwort davor).
      const salzArg = teile.find(x => /^\s*salt\s*:/.test(x))?.replace(/^\s*salt\s*:/, '') ?? teile[1] ?? ''
      const salz = valueAt(text, code, salzArg.trim(), from, open) ?? salzArg
      if (FIXED_BYTES.test(salz.trim())) {
        out.push(threat(text, file, open, 'R2', true,
          'Schlüssel wird mit einem festen Salz abgeleitet – gleiches Kennwort gibt überall denselben Schlüssel (vorberechenbar). Salz mit RandomNumberGenerator.GetBytes(16) erzeugen und mit dem Ergebnis speichern.',
          'key is derived with a fixed salt – the same password gives the same key everywhere (precomputable). Create the salt with RandomNumberGenerator.GetBytes(16) and store it with the result.'))
      }
      const runden = werte.map(w => /^\s*(\d[\d_']*)\s*$/.exec(w)?.[1]).filter((x): x is string => x !== undefined).map(x => Number(x.replace(/[_']/g, ''))).find(n => n >= 1000)
      if (runden !== undefined && runden < 600000) {
        out.push(threat(text, file, open, 'R2', false,
          `Schlüsselableitung mit nur ${runden} Runden – mindestens 600000 (PBKDF2 mit SHA-256), sonst lässt sich ein Kennwort schnell durchprobieren.`,
          `key derivation with only ${runden} iterations – use at least 600000 (PBKDF2 with SHA-256), otherwise a password can be brute-forced quickly.`))
      }
    }

    // R3: Bild aus dem Netz ohne Grössengrenze entpacken.
    if (/\b(?:BitmapImage|BitmapDecoder|BitmapFrame)\b/.test(seg) && /\b(?:GetByteArrayAsync|GetStreamAsync|ReadAsByteArrayAsync|ReadAsStreamAsync)\b/.test(seg) &&
      !/\bDecodePixel(?:Width|Height)\b|\bPixel(?:Width|Height)\b/.test(seg)) {
      out.push(threat(text, file, at(/\b(?:BitmapImage|BitmapDecoder|BitmapFrame)\b/), 'R3', false,
        'Bild aus dem Netz wird ohne Grössengrenze entpackt – ein kleines Bild kann riesig entpacken (Speicher voll). Bytes begrenzen und DecodePixelWidth/-Height setzen oder PixelWidth/-Height prüfen.',
        'image from the network is decoded without a size limit – a small file can decode huge (memory full). Limit the bytes and set DecodePixelWidth/-Height or check PixelWidth/-Height.'))
    }

    // R4: Entschlüsselung gibt bei fehlender Kennung den Eingabetext unverändert zurück (Fälschung als Klartext möglich).
    if (/\bAesGcm\b|\.\s*Decrypt\s*\(|\bUnprotect\s*\(|\bCreateDecryptor\s*\(/.test(seg)) {
      const m = /\bif\s*\(\s*!\s*(?:\(\s*)?([A-Za-z_]\w*)\s*(?:\?\s*)?\.\s*StartsWith\s*\([^)]*\)\s*\)*\s*\)\s*\{?\s*return\s+\1\s*;/.exec(seg)
      if (m) {
        out.push(threat(text, file, from + m.index, 'R4', false,
          'Entschlüsselung gibt Text ohne Kennung unverändert zurück – wer den Speicher beschreiben kann, legt so beliebigen Inhalt als "echt" ab. Nach der Umstellung Text ohne Kennung als unlesbar behandeln.',
          'decryption returns text without the marker unchanged – whoever can write the storage can plant any content as "genuine". After the migration treat unmarked text as unreadable.'))
      }
    }

    // R5: Ein Startargument löst eine zerstörende Aktion aus (ohne Rückfrage kann jedes andere Programm sie auslösen).
    // Gemeldet wird nur, wenn das Löschen im Zweig des Schalters steht (if (... "--x" ...) { ... } oder case "--x": ...).
    if (/\bGetCommandLineArgs\b|\b(?:e\s*\.\s*)?Args\b|\bargs\b/.test(seg) && switchDeletes(code, from, raw)) {
      out.push(threat(text, file, at(/\bGetCommandLineArgs\b|\b(?:e\s*\.\s*)?Args\b|\bargs\b/), 'R5', false,
        'ein Startargument löscht oder überschreibt etwas – jedes andere Programm kann es so auslösen. Nur mit einer Bestätigung oder einem Wert, den nur der Deinstallierer kennt; nie, wenn das Programm schon läuft.',
        'a start argument deletes or overwrites something – any other program can trigger it. Only with a confirmation or a value only the uninstaller knows; never while the program is already running.'))
    }

    // R6: Alle Eigenschaften per Reflection von einem anderen Objekt übernehmen (eine eingelesene Datei setzt so jede Einstellung,
    // auch Adressen und Schalter). Muster: Schleife über GetProperties mit SetValue(ziel, eigenschaft.GetValue(quelle)).
    if (/\.\s*GetProperties\s*\(/.test(seg) && /\.\s*SetValue\s*\(\s*[\w.]+\s*,\s*\w+\s*\.\s*GetValue\s*\(\s*[\w.]+\s*\)/.test(seg)) {
      out.push(threat(text, file, at(/\.\s*GetProperties\s*\(/), 'R6', false,
        'alle Eigenschaften werden per Reflection von einem anderen Objekt übernommen – kommt es aus einer Datei, setzt sie so auch Server-Adressen, Schlüssel und Sicherheitsschalter. Nur eine feste Liste erlaubter Eigenschaften übernehmen, wichtige erst nach Rückfrage.',
        'all properties are copied by reflection from another object – if it comes from a file, it sets server addresses, keys and security switches too. Copy only a fixed list of allowed properties, important ones only after confirmation.'))
    }

    // R7: Erst prüfen, dann kürzen (das Kürzen kann aus einem harmlosen Wort ein gesperrtes machen oder einen Link bilden). Gekürzt
    // wird oft eine abgeleitete Variable (geprüft wird text, gekürzt sauber = f(text)).
    for (const m of seg.matchAll(CHECK_CALL)) {
      const name = m[2] ?? ''
      if (/^(?:IsNullOrEmpty|IsNullOrWhiteSpace|IsDigit|IsLetter|IsWhiteSpace|IsLetterOrDigit|IsUpper|IsLower|IsHighSurrogate|IsLowSurrogate|IsSurrogate|IsControl)$/.test(m[1] ?? '')) continue
      // Prüfungen des Frameworks (Uri.IsWellFormedUriString, Path.IsPathRooted, Regex.IsMatch ...) sind kein eigener Filter.
      if (FRAMEWORK_CHECK.test(seg.slice(Math.max(0, (m.index ?? 0) - 40), m.index ?? 0))) continue
      const later = seg.slice((m.index ?? 0) + m[0].length)
      const namen = [name, ...[...later.matchAll(new RegExp(`\\b([A-Za-z_]\\w*)\\s*=\\s*[^;=]*(?<![\\w.])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g'))].map(x => x[1] ?? '')]
      const cut = namen
        .map(n => new RegExp(`(?<![\\w.])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*(?:\\.\\s*(?:Substring\\s*\\(\\s*0\\s*,|Remove\\s*\\()|\\[\\s*\\.\\.)`).exec(later))
        .find((x): x is RegExpExecArray => x !== null)
      // Nur ein Kürzen für die Anzeige (mit … oder ...): am 21.11.2026 waren die zwei Treffer ohne Auslassungszeichen in einem
      // anderen Programm (Fingerabdruck, Pfadteile) keine Lücken.
      // Satzende im bereinigten Text: ein ';' in einer Zeichenkette oder einem Zeichen (TrimEnd(';')) ist keins.
      const cutAt = from + (m.index ?? 0) + m[0].length + (cut?.index ?? 0)
      const satzEnde = code.indexOf(';', cutAt)
      const satz = cut ? text.slice(cutAt, satzEnde === -1 ? cutAt + 400 : satzEnde) : ''
      if (cut && /…|\.\.\."|"\.\.\./.test(satz)) {
        out.push(threat(text, file, from + (m.index ?? 0) + m[0].length + cut.index, 'R7', false,
          `«${name}» wird erst geprüft (${m[1]}) und danach gekürzt – das Kürzen kann aus einem harmlosen Wort ein gesperrtes machen oder einen Link bilden. Erst kürzen, dann den fertigen Text prüfen.`,
          `«${name}» is checked first (${m[1]}) and cut afterwards – cutting can turn a harmless word into a blocked one or form a link. Cut first, then check the final text.`))
        break
      }
    }

    // R8: Liste aus einer Datei ohne Obergrenze übernehmen.
    // Gesucht wird der Aufruf und davor in derselben Anweisung der Name (var ids = ...). Am 21.11.2026 gemessen: ein Muster
    // "Typ Name = [^;]* Deserialize" brauchte für eine Datei mit 40000 Zeilen 4 Minuten.
    for (const m of seg.matchAll(/\b(?:JsonSerializer\s*\.\s*Deserialize|JsonConvert\s*\.\s*DeserializeObject)\s*<\s*(?:List|IList|IEnumerable|HashSet|Dictionary|[\w.]+\s*\[\s*\])/g)) {
      const at = m.index ?? 0
      const vor = seg.slice(Math.max(seg.lastIndexOf(';', at), seg.lastIndexOf('{', at), seg.lastIndexOf('}', at)) + 1, at)
      const name = /([A-Za-z_]\w*)\s*(?:\?\?)?=(?![=>])/.exec(vor)?.[1] ?? ''
      if (name === '') continue
      const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const used = new RegExp(`(?:AddRange|UnionWith)\\s*\\(\\s*${esc}\\b|foreach\\s*\\([^)]*\\bin\\s+${esc}\\b`).test(seg)
      const bounded = new RegExp(`\\b${esc}\\s*(?:\\?\\s*)?\\.\\s*(?:Count|Length|Take)\\b`).test(seg)
      if (used && !bounded) {
        out.push(threat(text, file, from + at - vor.length, 'R8', false,
          `«${name}» kommt aus einer Datei und wird ohne Obergrenze übernommen – eine aufgeblähte Datei füllt Speicher und Sicherungen. Anzahl begrenzen (Take oder Prüfung von Count) und jeden Eintrag wie eine Eingabe prüfen.`,
          `«${name}» comes from a file and is taken over without a limit – a bloated file fills memory and backups. Limit the count (Take or a Count check) and check every entry like input.`))
        break
      }
    }

    // R9: Ein Befehl aus dem Chat wird nur am normalen Leerzeichen getrennt (geschütztes Leerzeichen oder Tab umgehen so z. B.
    // "!stopp"). Nur wo die Methode einen Befehl mit "!" auswertet: am 21.11.2026 meldete die Regel ohne diese Grenze 42 Stellen
    // in einem Chat-Programm, fast alle eigene, feste Texte.
    {
      const m = /\.\s*(?:Split|IndexOf|LastIndexOf)\s*\(\s*(?:' '|" ")\s*[,)]/.exec(raw)
      if (m && code.slice(from + m.index, from + m.index + 2).trim() !== '' && /"!|'!'|StartsWith\s*\(\s*'!'/.test(raw)) {
        out.push(threat(text, file, from + m.index, 'R9', false,
          'ein Befehl wird nur am normalen Leerzeichen getrennt – ein geschütztes Leerzeichen oder ein Tab umgeht so den Befehl. char.IsWhiteSpace verwenden oder Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).',
          'a command is split only at the normal space – a no-break space or a tab bypasses the command. Use char.IsWhiteSpace or Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).'))
      }
    }

    // R10: Name eines Geheimnisses in einem Protokoll oder einer Meldung.
    for (const m of seg.matchAll(/\b(?:Log(?!in|on|out|ged)\w*|(?:[Ll]og|_?[Ll]ogger|_log)\s*\.\s*(?:Information|Info|Debug|Warn\w*|Error|Fatal|Trace|Verbose|Critical|Log\w*|Write\w*)|Protokoll\w*|Console\s*\.\s*Write\w*|Debug\s*\.\s*Write\w*|Trace\s*\.\s*Write\w*|MessageBox\s*\.\s*Show|File\s*\.\s*AppendAllText\w*)\s*\(/g)) {
      const open = from + (m.index ?? 0) + m[0].length - 1
      const len = argsAt(code, open).length
      const argsCode = code.slice(open + 1, open + 1 + len)
      const argsRaw = text.slice(open + 1, open + 1 + len)
      const holes = [...argsRaw.matchAll(/(?:\$+@?|@\$+)("(?:"")?)[\s\S]*?\1/g)].flatMap(s => [...(s[0] ?? '').matchAll(/\{([^{}:]+)[^{}]*\}/g)].map(h => h[1] ?? ''))
      // Nur "gesetzt oder nicht" (Länge, Anzahl, null-Vergleich) verrät den Wert nicht.
      const ohneLaenge = [argsCode, ...holes]
        .join(' ')
        .replace(/\bnameof\s*\([^)]*\)|[\w.]+\s*\??\.\s*(?:Length|Count)\b[^,;)]*|\bstring\s*\.\s*IsNullOr\w+\s*\([^)]*\)|[\w.]+\s*(?:is\s+(?:not\s+)?null|[!=]=\s*null)/g, ' ')
      const names = [...ohneLaenge.matchAll(SECRET_NAME)].map(x => x[0]).filter(n => !SECRET_HARMLESS.test(n) && !/^(?:cancellation|stopping)/i.test(n))
      if (names.length > 0) {
        out.push(threat(text, file, open, 'R10', false,
          `«${names[0]}» steht in einem Protokoll oder einer Meldung – ein Geheimnis landet so im Klartext in Dateien oder Bildschirmfotos. Nie den Wert ausgeben, höchstens "gesetzt/nicht gesetzt".`,
          `«${names[0]}» is written to a log or message – a secret ends up in plain text in files or screenshots. Never output the value, at most "set/not set".`))
        break
      }
    }
  }
  return out.filter((x): x is ThreatFinding => x !== undefined)
}

// Die schweren Bedrohungen (Fehler) für die Prüfung beim Schreiben und im Scan; alle Bedrohungen für das Härtungsprotokoll.
export function csThreatFindings(text: string, file: string): ThreatFinding[] {
  return csThreats(text, blankCode(text), file).sort((a, b) => a.line - b.line)
}

// ---- KI-Fehlerarten: häufige Fehler in KI-geschriebenem Code (eingebaute Geheimnisse, Debug-Reste und Merkposten, stille
// Fehler). Für jede Code-Datei, geprüft wird nur der neu geschriebene Text (Edit: der neue Teil, Write: alles).
// Ungenutzter Code gehört NICHT hierher: Wer erst ein Feld anlegt und im nächsten Schritt den
// Aufruf, hätte sonst jeden Zwischenstand rot - das prüft der Bau am Schluss (Prüfwerkzeug des Projekts).
// Bewusste Stellen: "code-waechter:ok KI" in derselben Zeile.

// Längere Texte werden nur bis hier geprüft; kiNote sagt das dann offen (ein stiller Teil-Lauf wäre ein "OK" für Ungeprüftes).
export const KI_MAX_ZEICHEN = 200000

export type KiBefund = { art: 'geheimnis' | 'debug' | 'merkposten' | 'leerer_fang' | 'async_void' | 'test_aus' | 'sicherheit'; name: string }

// Sicherheitslücken in C#, die der Prüfbau nicht meldet (gemessen 18.11.2026, .NET 10 mit allen Sicherheitsregeln: abgeschaltete
// Zertifikatsprüfung bei HttpClientHandler, XmlUrlResolver und DtdProcessing.Parse meldet keine CA-Regel). Python prüft ruff (S),
// JavaScript die SEC-Regeln.
const KI_SICHER_CS: [string, RegExp][] = [
  ['Zertifikatsprüfung abgeschaltet', /DangerousAcceptAnyServerCertificateValidator|(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|RemoteCertificateValidationCallback)\s*\+?=\s*(?:\([^)]*\)|\w+)\s*=>\s*true\b/],
  ['unsichere Deserialisierung', /\bnew\s+(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\b|TypeNameHandling\s*=\s*TypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)\b/],
  ['XML lädt fremde Dateien (XXE)', /DtdProcessing\s*=\s*DtdProcessing\s*\.\s*Parse\b|\bnew\s+XmlUrlResolver\b/],
]

// Prüfdateien enthalten absichtlich schlechte Beispiele - dort zählt nur ein abgeschalteter Prüfsatz.
const KI_PRUEFDATEI = /\.test\.[cm]?[jt]sx?$/i
// Abgeschaltete oder allein gestellte Prüfsätze (Fachleute 2026: KI-Agenten schalten Tests ab, die sie nicht bestehen).
//
const KI_TEST_AUS = /\[Ignore\b|\[(?:Fact|Theory|Test)\s*\([^)]*\bSkip\s*=|\b(?:it|test|describe)\s*\.\s*(?:skip|only|todo)\s*\(|\bx(?:it|describe|test)\s*\(|@unittest\s*\.\s*skip|@pytest\s*\.\s*mark\s*\.\s*(?:skip|xfail)/ // code-waechter:ok KI
const KI_ASYNC_VOID = /\basync\s+void\s+\w+\s*\((?!\s*object\b)/

// "async void" ausserhalb eines Ereignisses (object sender, ...) und ohne try im Rumpf: ein Fehler darin beendet das Programm
// oder geht verloren.
function kiAsyncVoidOhneTry(zeilen: string[]): boolean {
  for (let i = 0; i < zeilen.length; i++) {
    const z = zeilen[i]
    const m = KI_ASYNC_VOID.exec(z)
    if (!m || /\boverride\b/.test(z)) continue
    const davor = z.slice(0, m.index)
    if (davor.includes('//') || (davor.split('"').length - 1) % 2 === 1) continue
    if (z.includes('=>')) { if (!/\btry\b/.test(z)) return true; continue }
    let tiefe = 0
    let angefangen = false
    let geschuetzt = false
    for (let j = i; j < Math.min(zeilen.length, i + 400); j++) {
      if (angefangen && /\btry\b/.test(zeilen[j])) { geschuetzt = true; break }
      tiefe += (zeilen[j].match(/\{/g)?.length ?? 0) - (zeilen[j].match(/\}/g)?.length ?? 0)
      angefangen = angefangen || zeilen[j].includes('{')
      if (angefangen && tiefe <= 0) break
    }
    if (!geschuetzt) return true
  }
  return false
}

const KI_OK = /code-waechter:ok\s+KI\b/

const KI_CODE_DATEI = /\.(?:cs|vb|fs|py|pyw|js|mjs|cjs|ts|tsx|jsx|ps1|psm1|cpp|cc|cxx|c|h|hpp|java|kt|go|rs|php|lua|swift|dart)$/i

// Nur Muster mit eindeutigem Anbieter-Vorsatz - der Fund selbst wird nie ausgegeben.
const KI_GEHEIMNISSE: [string, RegExp][] = [
  ['Anthropic-Schlüssel', /sk-ant-[A-Za-z0-9_-]{30,}/],
  ['OpenAI-Schlüssel', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
  ['GitHub-Zugang', /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}/],
  ['Google-Schlüssel', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Slack-Zugang', /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
  ['Tavily-Schlüssel', /\btvly-[A-Za-z0-9]{16,}/],
  ['AWS-Zugang', /\bAKIA[0-9A-Z]{16}\b/],
  ['Twitch-Token', /\boauth:[a-z0-9]{25,}/],
  ['Privater Schlüssel', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
]

function kiDebugMuster(file: string): RegExp | undefined {
  if (/\.(?:cs|vb|fs)$/i.test(file)) return /\b(?:Debug|Trace)\s*\.\s*(?:Write|WriteLine|Print)\s*\(|\bDebugger\s*\.\s*(?:Break|Launch)\s*\(/
  if (/\.(?:js|mjs|cjs|ts|tsx|jsx)$/i.test(file)) return /^\s*debugger\s*;?\s*$|\bconsole\s*\.\s*(?:log|debug)\s*\(/m
  if (/\.pyw?$/i.test(file)) return /\bbreakpoint\s*\(\s*\)|\bpdb\s*\.\s*set_trace\s*\(|^\s*import\s+pdb\b/m
  return undefined
}

// Merkposten nur im Kommentar und nur als Merkposten: am Anfang des Kommentars oder mit Doppelpunkt. Eine Variable "TODO" (Pfad
// zur TO-DO-Datei) oder ein Suchmuster ist keiner.
const KI_MERKPOSTEN = /^\s*(?:TODO|FIXME|HACK)\b|\b(?:TODO|FIXME|HACK|XXX)\s*:/ // code-waechter:ok KI

function kiKommentar(file: string, zeile: string): string | undefined {
  const raute = /\.(?:py|pyw|ps1|psm1)$/i.test(file)
  let i = raute ? zeile.indexOf('#') : zeile.indexOf('//')
  if (!raute && i < 0) i = zeile.indexOf('/*')
  return i < 0 ? undefined : zeile.slice(i + (raute ? 1 : 2))
}

function kiLeererFang(file: string): RegExp | undefined {
  // Ein Kommentar an "except" oder "pass" ist die Begründung - dann ist der Fang nicht leer.
  if (/\.pyw?$/i.test(file)) return /^\s*except\b[^\n:#]*:[ \t]*\n\s*pass[ \t]*$/m
  if (/\.(?:ps1|psm1)$/i.test(file)) return /\bcatch\s*(?:\[[^\]]*\]\s*)?\{\s*\}/i
  // Auch ein Fang mit Bedingung (when) und leerem Rumpf ist leer (Lücke bis 18.11.2026). Ein Kommentar gleich hinter dem leeren
  // Rumpf ist die Begründung.
  return /\bcatch\s*(?:\([^)]*\))?\s*(?:when\s*\([^{}]*\)\s*)?\{\s*\}(?![ \t]*\/\/)/ // code-waechter:ok KI
}

// Ob die KI-Fehlerarten für diese Datei gelten (Code-Datei nach Endung).
export function kiPruefbar(file: string): boolean {
  return KI_CODE_DATEI.test(file)
}

export function kiBefunde(written: string, file: string): KiBefund[] {
  if (!kiPruefbar(file)) return []
  // Bewusst markierte Zeilen fallen weg, bevor gesucht wird.
  const text = (written.length > KI_MAX_ZEICHEN ? written.slice(0, KI_MAX_ZEICHEN) : written)
    .split('\n').filter(z => !KI_OK.test(z)).join('\n')
  const befunde: KiBefund[] = []
  if (text.split('\n').some(z => KI_TEST_AUS.test(z))) befunde.push({ art: 'test_aus', name: 'Prüfsatz abgeschaltet' })
  if (KI_PRUEFDATEI.test(file)) return befunde
  if (/\.cs$/i.test(file) && kiAsyncVoidOhneTry(text.split('\n'))) {
    befunde.push({ art: 'async_void', name: 'async void ohne try (ein Fehler beendet das Programm)' })
  }
  if (/\.cs$/i.test(file)) {
    // Nur der Code vor einem Kommentar: ein Kommentar, der eine Lücke nennt, ist keine.
    const code = text.split('\n').map(z => { const k = kiKommentar(file, z); return k === undefined ? z : z.slice(0, z.length - k.length) })
    for (const [name, re] of KI_SICHER_CS) if (code.some(z => re.test(z))) befunde.push({ art: 'sicherheit', name })
  }
  for (const [name, re] of KI_GEHEIMNISSE) if (re.test(text)) befunde.push({ art: 'geheimnis', name })
  const debug = kiDebugMuster(file)
  if (debug && debug.test(text)) befunde.push({ art: 'debug', name: 'Debug-Ausgabe' })
  if (text.split('\n').some(z => { const k = kiKommentar(file, z); return k !== undefined && KI_MERKPOSTEN.test(k) })) {
    befunde.push({ art: 'merkposten', name: 'Merkposten (TODO/FIXME)' }) // code-waechter:ok KI
  }
  const fang = kiLeererFang(file)
  if (fang && fang.test(text)) befunde.push({ art: 'leerer_fang', name: 'leerer Fang (Fehler wird verschluckt)' })
  return befunde
}

export const hardeningChecks = { csHardeningHints, csThreatFindings, kiBefunde, kiPruefbar, kiMaxZeichen: KI_MAX_ZEICHEN }
