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
  return [...catchAllAsEmpty(text, code, file), ...unboundedLoops(text, code, file)].sort((a, b) => a.line - b.line)
}

export const hardeningChecks = { csHardeningHints }
