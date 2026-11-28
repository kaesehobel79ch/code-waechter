// Testbetrug (27.11.2026, Bauplan des Code-Wächters, freigegeben "Alle drei Stufen"): meldet, wenn ein Prüfsatz schwächer
// gemacht wird, statt den Fehler im Code zu beheben, und wenn Programmcode Vergleiche fest auf "gleich" stellt oder nach der
// Testumgebung fragt. Schützt die Vorgabe "Prüfprogramme sind unantastbar, eine Erwartung ändert sich nur mit der Vorgabe und
// nur mit Freigabe" (KI-Fehlerart: Prüfsätze an den Fehler anpassen). Die Regel meldet, sie verbietet nichts.
//
// Beleg: ImpossibleBench (Zhong, Raghunathan, Carlini; arXiv 2510.20270, gelesen 27.11.2026). Abschnitt 4.1 nennt vier Arten zu
// schummeln: Prüfsätze ändern, Vergleichsoperatoren überladen, Zusatzzustand merken, Sonderfälle einbauen. Abschnitt 4.2 (Abb. 5,
// Conflicting-SWEbench): "Claude models and Qwen3-Coder, however, cheat primarily (>79%) through modifying test cases."
//
//   testBetrug(alt, neu, file)  nur Prüfdateien: vergleicht den Stand vor und nach dem Schreiben (alles Hinweise)
//     TEST-WENIGER    weniger Prüfungen als vorher (expect(...).to…, assert, self.assert…, Assert.…, .Should())
//     TEST-ERWARTUNG  der erwartete Wert einer Prüfung ist anders, der geprüfte Ausdruck blieb gleich
//     TEST-GELOESCHT  ein ganzer Prüfsatz ist weg (gelöscht oder auskommentiert)
//     TEST-AUS        ein Prüfsatz ist neu ausgeschaltet (skip-Varianten, Ignore-Attribut, Skip-Wert im Fact-Attribut,
//                     Skip-Dekoratoren von unittest und pytest, return bzw. skipTest als erste Anweisung)
//   immerWahr(text, file)       Programmcode (keine Prüfdatei)
//     VERGLEICH-IMMER-WAHR  Fehler: Equals/==/__eq__/equals fest true (!=/__ne__ fest false), CompareTo/Compare/GetHashCode,
//                           compareTo/hashCode, __hash__ und __lt__/__le__/__gt__/__ge__ fest
//     TEST-UMGEBUNG         Hinweis: der Code fragt, ob er unter einem Prüfsatz läuft (CI/TEST-Variable, pytest in sys.modules,
//                           NODE_ENV gleich 'test', Debugger.IsAttached als Verzweigung)
//
// Text in Zeichenketten und Kommentaren zählt nie als Code (csBereinigt, jsBereinigt, pyBereinigt aus sicherheit.ts). Bewusste
// Stellen: "code-waechter:ok SICHERHEIT" in der Zeile.

import { t } from './i18n'
import { OK_SICHER, PRUEF_PFAD, cArgumente, csBereinigt, daten, jsBereinigt, pyBereinigt } from './sicherheit'
import type { SFund } from './sicherheit'

type Sprache = 'js' | 'py' | 'cs'
type Bereich = { von: number; bis: number }
type Code = { roh: string; bare: string; zeilen: string[]; zeile: (at: number) => number; spalte: (at: number) => number }
// Ein Prüfsatz: Name, Kopf (Stelle für die Meldung), Bereich, wie er ausgeschaltet ist, Wörter des Rumpfs (für "umbenannt").
type Satz = { name: string; schluessel: string; kopf: number; von: number; bis: number; aus?: string; woerter: Set<string> }
// Eine Prüfung: schluessel = Art und geprüfter Ausdruck, wert = Erwartung; ohne schluessel wird sie nur gezählt.
type Pruefung = { at: number; satz: number; schluessel?: string; wert?: string; zeigen?: string; wertZeigen?: string; nicht?: boolean }
type Stand = { code: Code; saetze: Satz[]; pruefungen: Pruefung[] }

const SCANNER = (): string => t('Testbetrug', 'test tampering')

function spracheVon(file: string): Sprache | undefined {
  return /\.[cm]?[jt]sx?$/i.test(file) ? 'js' : /\.pyw?$/i.test(file) ? 'py' : /\.cs$/i.test(file) ? 'cs' : undefined
}

// Prüfdateien: Namen nach den Regeln der Prüfprogramme (Jest/Vitest *.test.* und *.spec.*, pytest test_*.py und *_test.py, .NET
// *Tests.cs und *Test.cs - gross geschrieben, sonst wäre "Latest.cs" eine), jede Datei in __tests__ und in einem Prüfordner nach
// PRUEF_PFAD (Tests, test, X.Tests, Probe, Pruefung).
const PRUEF_NAME = /\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|[\\/])test_[^\\/]*\.pyw?$|_test\.pyw?$|[\\/]__tests__[\\/]/i
const PRUEF_CS = /(?:^|[\\/])[^\\/]*Tests?\.cs$/

export function istPruefdatei(file: string): boolean {
  return spracheVon(file) !== undefined && (PRUEF_NAME.test(file) || PRUEF_CS.test(file) || PRUEF_PFAD.test(file))
}

function codeVon(text: string, sprache: Sprache): Code {
  const bare = sprache === 'js' ? jsBereinigt(text).bare : sprache === 'py' ? pyBereinigt(text) : csBereinigt(text)
  const start: number[] = [0]
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) start.push(i + 1)
  // Zeilennummer über eine Suche in den Zeilenanfängen: eine Prüfdatei hat tausende Prüfungen (register.test.ts: 294 KB).
  const zeile = (at: number): number => {
    let lo = 0
    let hi = start.length - 1
    while (lo < hi) {
      const mitte = (lo + hi + 1) >> 1
      if ((start[mitte] ?? 0) <= at) lo = mitte
      else hi = mitte - 1
    }
    return lo + 1
  }
  return { roh: text, bare, zeilen: text.split('\n').map(z => z.replace(/\r$/, '')), zeile, spalte: at => at - (start[zeile(at) - 1] ?? 0) + 1 }
}

// Stelle der schliessenden Klammer zur öffnenden bei offen ((, [ und { zählen zusammen); -1, wenn sie fehlt.
function zuVon(bare: string, offen: number): number {
  let tiefe = 0
  for (let k = offen; k < bare.length; k++) {
    const c = bare[k]
    if (c === '(' || c === '[' || c === '{') tiefe++
    else if ((c === ')' || c === ']' || c === '}') && --tiefe === 0) return k
  }
  return -1
}

// Bereiche der Argumente eines Aufrufs (cArgumente teilt an den Kommas der obersten Ebene; die Stücke liegen lückenlos hintereinander).
function argumente(bare: string, offen: number): Bereich[] {
  let pos = offen + 1
  const out = cArgumente(bare, offen).map(s => {
    const b = { von: pos, bis: pos + s.length }
    pos += s.length + 1
    return b
  })
  return out.length === 1 && bare.slice(out[0]?.von ?? 0, out[0]?.bis ?? 0).trim() === '' ? [] : out
}

// Vergleichbare Form: ohne Leerraum, " wie ', ohne Komma vor einer schliessenden Klammer.
const glatt = (s: string): string => s.replace(/\s+/g, '').replace(/"/g, "'").replace(/,(?=[)\]}]|$)/g, '')
const woerter = (s: string): Set<string> => new Set(s.match(/[A-Za-z_$À-ɏ][\w$À-ɏ]*|\d+(?:\.\d+)?/g) ?? [])
const roh = (c: Code, b: Bereich): string => c.roh.slice(b.von, b.bis).trim()

// Fester Wert (Zahl, Text, true/false/None/null oder Liste daraus): bei symmetrischen Prüfungen ist das die Erwartung.
const ZAHL_ODER_WORT = /^[-+]?(?:0x[\da-f_]+|\d[\d_]*(?:\.\d*)?(?:e[-+]?\d+)?|\.\d+)[a-z]*$|^(?:true|false|none|null|undefined)$/i
const TEXT_LITERAL = /^[@$rRbBuUfF]{0,3}("""|'''|"|'|`)\s*\1$/
function istLiteral(c: Code, b: Bereich): boolean {
  const r = roh(c, b)
  const k = c.bare.slice(b.von, b.bis).trim()
  if (ZAHL_ODER_WORT.test(r) || TEXT_LITERAL.test(k)) return true
  return /^[[({]/.test(k) && /^[\s\d.,:+\-eE"'`[\](){}]*$/.test(k.replace(/\b(?:true|false|True|False|None|null)\b/g, ''))
}

// Inhalt eines einzelnen Textes (Name eines Prüfsatzes); undefined, wenn das Argument kein fester Text ist.
function textInhalt(c: Code, b: Bereich): string | undefined {
  const s = c.bare.slice(b.von, b.bis)
  const m = /^\s*[@$rRbBuUfF]{0,3}("""|'''|"|'|`)\s*\1\s*$/.exec(s)
  if (!m || !m[1]) return undefined
  return c.roh.slice(b.von + s.indexOf(m[1]) + m[1].length, b.von + s.lastIndexOf(m[1]))
}

// Meldungstexte (nur ein Text und msg=...) hinter der Erwartung zählen nicht: eine neue Meldung ist keine neue Erwartung.
const nurMeldung = (c: Code, b: Bereich): boolean => TEXT_LITERAL.test(c.bare.slice(b.von, b.bis).trim()) || /^\s*msg\s*=/.test(c.bare.slice(b.von, b.bis))

function erwartung(c: Code, art: string, ausdruck: Bereich, erwartet: Bereich[], nicht: boolean, vor = ''): Partial<Pruefung> {
  const [erstes, ...rest] = erwartet
  const teile = [...(erstes ? [erstes] : []), ...rest.filter(b => !nurMeldung(c, b))]
  const zeigen = roh(c, ausdruck)
  return {
    schluessel: `${art}|${glatt(zeigen)}`,
    wert: `${nicht ? '!' : ''}${vor}${teile.map(b => glatt(roh(c, b))).join(',')}`,
    zeigen,
    wertZeigen: `${vor}${teile.map(b => roh(c, b)).join(', ')}`,
    nicht,
  }
}

// Zwei Argumente: ausdruck und erwartet nach der Regel des Prüfprogramms; bei symmetrischen Prüfungen (gleich, dasselbe) ist der
// feste Wert die Erwartung, auch wenn er an der anderen Stelle steht.
function zweiArgs(c: Code, art: string, ausdruck: Bereich, erwartet: Bereich, rest: Bereich[], nicht: boolean, symmetrisch: boolean): Partial<Pruefung> {
  const tausch = symmetrisch && istLiteral(c, ausdruck) && !istLiteral(c, erwartet)
  return erwartung(c, art, tausch ? erwartet : ausdruck, [tausch ? ausdruck : erwartet, ...rest], nicht)
}

// Gegensatzpaare ohne Argument (wahr/falsch, null/nicht null): der Wechsel ist eine geänderte Erwartung.
function fest(c: Code, art: string, ausdruck: Bereich, wert: string, name: string): Partial<Pruefung> {
  const zeigen = roh(c, ausdruck)
  return { schluessel: `${art}|${glatt(zeigen)}`, wert, zeigen, wertZeigen: name }
}

// ---- JavaScript/TypeScript (Jest, Vitest, claude-code/testing, node:assert)
const JS_SATZ = /(?<![\w$.])(?<!\bfunction\s+)(xit|xtest|it|test)\s*(?:\.\s*(skip|only|todo|concurrent|failing)\s*)?\(/g
const JS_GRUPPE_AUS = /(?<![\w$.])(?:xdescribe\s*\(|describe\s*\.\s*skip\s*\()/g
const JS_EXPECT = /(?<![\w$.])expect\s*\(/g
const JS_MATCHER = /^\s*((?:\.\s*(?:not|resolves|rejects)\s*)*)\.\s*(to[A-Z]\w*)\s*\(/
const JS_ASSERT = /(?<![\w$.])assert\s*(?:\.\s*(\w+)\s*)?\(/g
const JS_ASSERT_ZWEI = new Set(['equal', 'strictEqual', 'deepEqual', 'deepStrictEqual', 'notEqual', 'notStrictEqual', 'notDeepEqual', 'notDeepStrictEqual'])
const JS_PAAR: Record<string, [string, string]> = { toBeTruthy: ['wahr', 'ja'], toBeFalsy: ['wahr', 'nein'], toBeDefined: ['definiert', 'ja'], toBeUndefined: ['definiert', 'nein'] }
// Erste Anweisung "return" ohne Wert (auch return am Zeilenende: dort setzt JavaScript ein Semikolon).
const JS_RETURN_ANFANG = /^\s*return[ \t]*(?:;|\r?\n|\}|$)/

function jsStand(c: Code): Stand {
  const { bare } = c
  const gruppenAus: Bereich[] = []
  for (const m of bare.matchAll(JS_GRUPPE_AUS)) {
    const offen = (m.index ?? 0) + m[0].length - 1
    const zu = zuVon(bare, offen)
    if (zu > 0) gruppenAus.push({ von: offen, bis: zu })
  }
  const saetze: Satz[] = []
  for (const m of bare.matchAll(JS_SATZ)) {
    const kopf = m.index ?? 0
    const offen = kopf + m[0].length - 1
    const zu = zuVon(bare, offen)
    const args = argumente(bare, offen)
    const erstes = args[0]
    if (zu < 0 || !erstes) continue
    const art = m[1] ?? ''
    let aus: string | undefined
    if (art.startsWith('x')) aus = art
    else if (m[2] === 'skip' || m[2] === 'todo') aus = `${art}.${m[2]}`
    else if (gruppenAus.some(g => g.von < kopf && kopf < g.bis)) aus = 'describe'
    else {
      // Rumpf der Prüffunktion: () => { ... } oder function () { ... }
      for (const b of args.slice(1)) {
        const k = /(?:=>|\bfunction\b[^{]*)\s*\{/.exec(bare.slice(b.von, b.bis))
        if (!k) continue
        if (JS_RETURN_ANFANG.test(bare.slice(b.von + k.index + k[0].length, zu))) aus = 'return'
        break
      }
    }
    saetze.push({ name: textInhalt(c, erstes) ?? roh(c, erstes), schluessel: '', kopf, von: offen, bis: zu, aus, woerter: woerter(c.roh.slice(erstes.bis, zu)) })
  }
  const pruefungen: Pruefung[] = []
  for (const m of bare.matchAll(JS_EXPECT)) {
    const at = m.index ?? 0
    const offen = at + m[0].length - 1
    const zu = zuVon(bare, offen)
    const k = zu < 0 ? null : JS_MATCHER.exec(bare.slice(zu + 1, zu + 400))
    // expect(x) ohne Matcher prüft nichts
    if (!k) continue
    const kette = (k[1] ?? '').replace(/\s+/g, '')
    const nicht = /\.not\b/.test(kette)
    const art = `expect${kette.replace(/\.not\b/g, '')}.`
    const matcher = k[2] ?? ''
    const ausdruck = { von: offen + 1, bis: zu }
    const paar = JS_PAAR[matcher]
    pruefungen.push({ at, satz: -1, ...(paar ? fest(c, art + paar[0], ausdruck, (nicht ? '!' : '') + paar[1], `${nicht ? 'not.' : ''}${matcher}`) : erwartung(c, art + matcher, ausdruck, argumente(bare, zu + k[0].length), nicht)) })
  }
  for (const m of bare.matchAll(JS_ASSERT)) {
    const at = m.index ?? 0
    const args = argumente(bare, at + m[0].length - 1)
    const meth = m[1] ?? ''
    const a0 = args[0]
    const a1 = args[1]
    if (JS_ASSERT_ZWEI.has(meth) && a0 && a1) {
      const basis = meth.replace(/^not/, '').replace(/^./, x => x.toLowerCase())
      pruefungen.push({ at, satz: -1, ...zweiArgs(c, `assert.${basis}`, a0, a1, args.slice(2), meth.startsWith('not'), true) })
    } else pruefungen.push({ at, satz: -1 })
  }
  return { code: c, saetze, pruefungen }
}

// ---- Python (unittest, pytest)
type PyZeile = Bereich & { einzug: number; text: string }

// Logische Zeilen: eine Anweisung über mehrere Zeilen (offene Klammer, \ am Ende) gehört zusammen.
function pyZeilen(bare: string): PyZeile[] {
  const out: PyZeile[] = []
  let start = 0
  let tiefe = 0
  for (let k = 0; k <= bare.length; k++) {
    const c = bare[k]
    if (c === '(' || c === '[' || c === '{') tiefe++
    else if (c === ')' || c === ']' || c === '}') tiefe = Math.max(0, tiefe - 1)
    const weiter = bare[k - 1] === '\\' || (bare[k - 1] === '\r' && bare[k - 2] === '\\')
    if (k === bare.length || (c === '\n' && tiefe === 0 && !weiter)) {
      const text = bare.slice(start, k)
      if (text.trim() !== '') out.push({ von: start, bis: k, einzug: (/^[ \t]*/.exec(text)?.[0] ?? '').replace(/\t/g, '    ').length, text })
      start = k + 1
    }
  }
  return out
}

// Eine Zeile nur aus einem (geleerten) Text: Docstring, keine Anweisung. pyBereinigt lässt die Anführungszeichen stehen und leert
// den Inhalt ("""Doc.""" wird zu """    """); Anfang und Ende eines mehrzeiligen Docstrings sind je eine Zeile mit """.
const PY_NUR_TEXT = /^[rRbBuUfF]{0,2}(?:"""|'''|"|')(?:\s*(?:"""|'''|"|'))?$/
const PY_SKIP = /^@\s*(?:unittest\s*\.\s*)?skip(?:If|Unless)?\b|^@\s*pytest\s*\.\s*mark\s*\.\s*skip(?:if)?\b/
const PY_DEF_TEST = /^\s*(?:async\s+)?def\s+(test\w*)\s*\(/
const PY_KLASSE = /^\s*class\s+(\w+)/
const PY_SKIP_ANFANG = /^\s*(?:return\s*(?:None\s*)?$|(?:self\s*\.\s*skipTest|pytest\s*\.\s*skip)\s*\()/
const PY_PAAR: Record<string, [string, string]> = { assertTrue: ['wahr', 'ja'], assertFalse: ['wahr', 'nein'], assertIsNone: ['none', 'ja'], assertIsNotNone: ['none', 'nein'] }
const PY_SYM = ['assertEqual', 'assertEquals', 'assertAlmostEqual', 'assertAlmostEquals', 'assertIs', 'assertCountEqual', 'assertListEqual', 'assertDictEqual', 'assertSetEqual', 'assertTupleEqual', 'assertSequenceEqual', 'assertMultiLineEqual']
const PY_ZWEI_SYM = new Set(PY_SYM)
const PY_ZWEI = new Set([...PY_SYM, 'assertIn', 'assertGreater', 'assertGreaterEqual', 'assertLess', 'assertLessEqual', 'assertRegex', 'assertIsInstance'])
const PY_VERGLEICH = /^(?:==|!=|<=|>=|<(?![<=])|>(?![>=])|\s+is\s+not\s+|\s+is\s+|\s+not\s+in\s+|\s+in\s+)/

// Erster Vergleich auf der obersten Ebene eines assert-Ausdrucks.
function pyVergleich(bare: string, von: number, bis: number): { links: Bereich; op: string; rechts: Bereich } | undefined {
  let tiefe = 0
  for (let k = von; k < bis; k++) {
    const c = bare[k] ?? ''
    if (c === '(' || c === '[' || c === '{') tiefe++
    else if (c === ')' || c === ']' || c === '}') tiefe--
    else if (tiefe === 0 && !(c === '<' && bare[k - 1] === '<') && !(c === '>' && (bare[k - 1] === '>' || bare[k - 1] === '-'))) {
      const m = PY_VERGLEICH.exec(bare.slice(k, Math.min(bis, k + 14)))
      if (m) return { links: { von, bis: k }, op: m[0].trim().replace(/\s+/g, ' '), rechts: { von: k + m[0].length, bis } }
    }
  }
  return undefined
}

function pyAssert(c: Code, von: number, ende: number): Partial<Pruefung> {
  // Die Meldung hinter dem ersten Komma der obersten Ebene gehört nicht zur Prüfung.
  let bis = ende
  let tiefe = 0
  for (let k = von; k < ende; k++) {
    const ch = c.bare[k]
    if (ch === '(' || ch === '[' || ch === '{') tiefe++
    else if (ch === ')' || ch === ']' || ch === '}') tiefe--
    else if (ch === ',' && tiefe === 0) {
      bis = k
      break
    }
  }
  const v = pyVergleich(c.bare, von, bis)
  if (!v) return {}
  const sym = v.op === '==' || v.op === '!=' || v.op === 'is' || v.op === 'is not'
  const tausch = sym && istLiteral(c, v.links) && !istLiteral(c, v.rechts)
  return erwartung(c, 'assert', tausch ? v.rechts : v.links, [tausch ? v.links : v.rechts], false, `${v.op} `)
}

function pyMethode(c: Code, meth: string, args: Bereich[]): Partial<Pruefung> {
  const paar = PY_PAAR[meth]
  const a0 = args[0]
  const a1 = args[1]
  if (paar && a0) return fest(c, `self.${paar[0]}`, a0, paar[1], meth)
  const basis = meth.replace(/Not(?=[A-Z]|$)/, '')
  if (!PY_ZWEI.has(basis) || !a0 || !a1) return {}
  return zweiArgs(c, `self.${basis}`, a0, a1, args.slice(2), basis !== meth, PY_ZWEI_SYM.has(basis))
}

function pyStand(c: Code): Stand {
  const zeilen = pyZeilen(c.bare)
  const saetze: Satz[] = []
  const klassen: { einzug: number; name: string; aus?: string }[] = []
  let deko: PyZeile[] = []
  for (let i = 0; i < zeilen.length; i++) {
    const z = zeilen[i]
    if (!z) continue
    while (klassen.length > 0 && z.einzug <= (klassen[klassen.length - 1]?.einzug ?? -1)) klassen.pop()
    if (/^\s*@/.test(z.text)) {
      deko.push(z)
      continue
    }
    const dekoAus = deko.find(d => PY_SKIP.test(d.text.trim()))
    deko = []
    const kl = PY_KLASSE.exec(z.text)
    if (kl) {
      klassen.push({ einzug: z.einzug, name: kl[1] ?? '', aus: dekoAus ? roh(c, dekoAus) : klassen[klassen.length - 1]?.aus })
      continue
    }
    const def = PY_DEF_TEST.exec(z.text)
    if (!def) continue
    // Rumpf: bis zur nächsten Zeile, die nicht tiefer eingerückt ist.
    let j = i + 1
    while (j < zeilen.length && (zeilen[j]?.einzug ?? 0) > z.einzug) j++
    const bis = zeilen[j - 1]?.bis ?? c.bare.length
    // Erste Anweisung: hinter dem Doppelpunkt der Kopfzeile oder die erste Zeile des Rumpfs, die kein Docstring ist.
    const inline = /\)\s*(?:->[^:]*)?:[ \t]*(\S[\s\S]*)$/.exec(z.text)?.[1]
    const erste = inline ?? zeilen.slice(i + 1, j).find(x => !PY_NUR_TEXT.test(x.text.trim()))?.text
    let aus = dekoAus ? roh(c, dekoAus) : undefined
    if (!aus && erste !== undefined && PY_SKIP_ANFANG.test(erste)) aus = erste.trim().split(/\s|\(/)[0]
    if (!aus) aus = klassen[klassen.length - 1]?.aus
    const name = [...klassen.map(k => k.name), def[1] ?? ''].join('.')
    saetze.push({ name, schluessel: '', kopf: z.von + z.text.length - z.text.trimStart().length, von: z.von, bis, aus, woerter: woerter(c.roh.slice(z.bis, bis)) })
  }
  const pruefungen: Pruefung[] = []
  for (const z of zeilen) {
    const a = /^(\s*)assert\b/.exec(z.text)
    if (a) pruefungen.push({ at: z.von + (a[1]?.length ?? 0), satz: -1, ...pyAssert(c, z.von + a[0].length, z.bis) })
    for (const m of z.text.matchAll(/\bself\s*\.\s*(assert\w*)\s*\(/g)) {
      const at = z.von + (m.index ?? 0)
      pruefungen.push({ at, satz: -1, ...pyMethode(c, m[1] ?? '', argumente(c.bare, at + m[0].length - 1)) })
    }
    for (const m of z.text.matchAll(/\bpytest\s*\.\s*raises\s*\(/g)) pruefungen.push({ at: z.von + (m.index ?? 0), satz: -1 })
  }
  return { code: c, saetze, pruefungen }
}

// ---- C# (xUnit, NUnit, MSTest, FluentAssertions)
const CS_METHODE = /((?:\[[^[\]]*\]\s*)+)(?:(?:public|private|internal|protected|static|async|virtual|override|sealed|unsafe|new|extern)\s+)*[\w<>[\],.?]+\s+(\w+)\s*(?:<[^<>()]*>)?\s*\(/g
const CS_TEST_ATTR = /\b(?:Fact|Theory|Test|TestMethod|DataTestMethod|TestCase|TestCaseSource)\b(?!\s*=)/
const CS_AUS_ATTR = /\bIgnore\b|\bSkip\s*=/
const CS_KLASSE = /((?:\[[^[\]]*\]\s*)+)(?:(?:public|private|internal|protected|static|sealed|abstract|partial)\s+)*(?:class|record|struct)\s+\w+[^{;]*\{/g
const CS_ASSERT = /\b(\w*Assert)\s*\.\s*(\w+)\s*(?:<[^<>()]*>)?\s*\(/g
const CS_SHOULD = /\.\s*Should\s*\(\s*\)\s*\.\s*(\w+)\s*(?:<[^<>()]*>)?\s*\(/g
// Name -> [Art, verneint, symmetrisch]; die Erwartung steht bei Assert und CollectionAssert vorne (expected, actual).
const CS_ZWEI: Record<string, [string, boolean, boolean]> = {
  AreEqual: ['Equal', false, true], AreNotEqual: ['Equal', true, true], Equal: ['Equal', false, true], NotEqual: ['Equal', true, true],
  AreSame: ['Same', false, true], AreNotSame: ['Same', true, true], Same: ['Same', false, true], NotSame: ['Same', true, true],
  StrictEqual: ['StrictEqual', false, true], NotStrictEqual: ['StrictEqual', true, true],
  Contains: ['Contains', false, false], DoesNotContain: ['Contains', true, false], StartsWith: ['StartsWith', false, false], EndsWith: ['EndsWith', false, false],
}
const CS_PAAR: Record<string, [string, string]> = {
  IsTrue: ['wahr', 'ja'], True: ['wahr', 'ja'], IsFalse: ['wahr', 'nein'], False: ['wahr', 'nein'],
  IsNull: ['null', 'ja'], Null: ['null', 'ja'], IsNotNull: ['null', 'nein'], NotNull: ['null', 'nein'],
}
const FA_PAAR: Record<string, [string, string]> = { BeTrue: ['wahr', 'ja'], BeFalse: ['wahr', 'nein'], BeNull: ['null', 'ja'], NotBeNull: ['null', 'nein'] }

// Ausdruck vor ".Should()": rückwärts bis zum Anfang der Anweisung (; { } = , oder eine offene Klammer).
function davor(bare: string, at: number): Bereich {
  let tiefe = 0
  let k = at - 1
  for (; k >= 0; k--) {
    const ch = bare[k] ?? ''
    if (ch === ')' || ch === ']' || ch === '}') {
      if (tiefe === 0 && ch === '}') break
      tiefe++
    } else if (ch === '(' || ch === '[' || ch === '{') {
      if (tiefe === 0) break
      tiefe--
    } else if (tiefe === 0 && !/[\w.?!@$"'\s]/.test(ch)) break
  }
  return { von: k + 1, bis: at }
}

function csStand(c: Code): Stand {
  const { bare } = c
  const klassenAus: Bereich[] = []
  for (const m of bare.matchAll(CS_KLASSE)) {
    if (!CS_AUS_ATTR.test(m[1] ?? '')) continue
    const offen = (m.index ?? 0) + m[0].length - 1
    const zu = zuVon(bare, offen)
    if (zu > 0) klassenAus.push({ von: offen, bis: zu })
  }
  const saetze: Satz[] = []
  for (const m of bare.matchAll(CS_METHODE)) {
    const attr = m[1] ?? ''
    if (!CS_TEST_ATTR.test(attr)) continue
    const kopf = m.index ?? 0
    const offen = kopf + m[0].length - 1
    const zu = zuVon(bare, offen)
    if (zu < 0) continue
    const nach = /^\s*(\{|=>)/.exec(bare.slice(zu + 1, zu + 200))
    let bis = zu
    let aus = CS_AUS_ATTR.test(attr) ? c.roh.slice(kopf, kopf + attr.length).trim() : undefined
    if (nach?.[1] === '{') {
      const a = zu + nach[0].length
      const e = zuVon(bare, a)
      bis = e < 0 ? bare.length : e
      if (!aus && /^\s*return\s*;/.test(bare.slice(a + 1, bis))) aus = 'return'
    } else if (nach) {
      const e = bare.indexOf(';', zu)
      bis = e < 0 ? bare.length : e
    }
    if (!aus && klassenAus.some(k => k.von < kopf && kopf < k.bis)) aus = t('Ignore der Klasse', 'class Ignore')
    saetze.push({ name: m[2] ?? '', schluessel: '', kopf, von: kopf, bis, aus, woerter: woerter(c.roh.slice(zu + 1, bis)) })
  }
  const pruefungen: Pruefung[] = []
  for (const m of bare.matchAll(CS_ASSERT)) {
    const at = m.index ?? 0
    const klasse = m[1] ?? ''
    const meth = m[2] ?? ''
    const args = argumente(bare, at + m[0].length - 1)
    const a0 = args[0]
    const a1 = args[1]
    const zwei = klasse === 'Assert' || klasse === 'CollectionAssert' ? CS_ZWEI[meth] : undefined
    const paar = klasse === 'Assert' ? CS_PAAR[meth] : undefined
    if (zwei && a0 && a1) pruefungen.push({ at, satz: -1, ...zweiArgs(c, `${klasse}.${zwei[0]}`, a1, a0, args.slice(2), zwei[1], zwei[2]) })
    else if (paar && a0) pruefungen.push({ at, satz: -1, ...fest(c, `Assert.${paar[0]}`, a0, paar[1], meth) })
    else if (klasse === 'Assert' && meth === 'That' && a0 && a1) pruefungen.push({ at, satz: -1, ...erwartung(c, 'Assert.That', a0, [a1, ...args.slice(2)], false) })
    else pruefungen.push({ at, satz: -1 })
  }
  for (const m of bare.matchAll(CS_SHOULD)) {
    const at = m.index ?? 0
    const ausdruck = davor(bare, at)
    const meth = m[1] ?? ''
    const paar = FA_PAAR[meth]
    const basis = meth.replace(/^Not(?=[A-Z])/, '')
    pruefungen.push({ at: ausdruck.von, satz: -1, ...(paar ? fest(c, `Should.${paar[0]}`, ausdruck, paar[1], meth) : erwartung(c, `Should.${basis}`, ausdruck, argumente(bare, at + m[0].length - 1), basis !== meth)) })
  }
  return { code: c, saetze, pruefungen }
}

function stand(text: string, sprache: Sprache): Stand {
  const c = codeVon(text, sprache)
  const s = sprache === 'js' ? jsStand(c) : sprache === 'py' ? pyStand(c) : csStand(c)
  // Gleiche Namen (z. B. in verschiedenen describe-Gruppen) werden der Reihe nach unterschieden.
  const zaehler = new Map<string, number>()
  for (const x of s.saetze) {
    const n = zaehler.get(x.name) ?? 0
    zaehler.set(x.name, n + 1)
    x.schluessel = `${x.name}#${n}`
  }
  // Jede Prüfung gehört zum Prüfsatz, in dessen Bereich sie steht (Prüfsätze liegen nebeneinander, nie ineinander).
  const sortiert = s.saetze.map((x, i) => ({ x, i })).sort((a, b) => a.x.von - b.x.von)
  for (const p of s.pruefungen) {
    let lo = 0
    let hi = sortiert.length - 1
    let treffer = -1
    while (lo <= hi) {
      const mitte = (lo + hi) >> 1
      if ((sortiert[mitte]?.x.von ?? 0) <= p.at) {
        treffer = mitte
        lo = mitte + 1
      } else hi = mitte - 1
    }
    const kandidat = sortiert[treffer]
    if (kandidat && p.at < kandidat.x.bis) p.satz = kandidat.i
  }
  return s
}

// Ähnlichkeit zweier Rümpfe (Dice über die Wörter): ab SCHWELLE gilt ein Prüfsatz mit neuem Namen als umbenannt, nicht gelöscht.
const SCHWELLE = 0.6
const MAX_PAARE = 250000
function aehnlich(a: Set<string>, b: Set<string>): number {
  if (a.size + b.size === 0) return 1
  let gleich = 0
  for (const w of a) if (b.has(w)) gleich++
  return (2 * gleich) / (a.size + b.size)
}

// Lange Erwartungen, die vorne gleich sind, ab kurz vor dem ersten Unterschied zeigen: sonst stünden zwei gleich aussehende,
// gekürzte Texte da (gemessen 27.11.2026 im Verlauf von sicherheit.test.ts: scannerFuer(...) bekam das Feld muster dazu).
function abUnterschied(a: string, b: string): [string, string] {
  let p = 0
  while (p < a.length && p < b.length && a[p] === b[p]) p++
  return p > 20 ? [`…${a.slice(p - 12)}`, `…${b.slice(p - 12)}`] : [a, b]
}

function zuordnenSaetze(A: Stand, N: Stand): Map<number, number> {
  const zuNeu = new Map<number, number>()
  const vergeben = new Set<number>()
  const nachName = new Map<string, number>()
  N.saetze.forEach((s, j) => nachName.set(s.schluessel, j))
  A.saetze.forEach((s, i) => {
    const j = nachName.get(s.schluessel)
    if (j !== undefined) {
      zuNeu.set(i, j)
      vergeben.add(j)
    }
  })
  const offenAlt = A.saetze.map((_, i) => i).filter(i => !zuNeu.has(i))
  const offenNeu = N.saetze.map((_, j) => j).filter(j => !vergeben.has(j))
  if (offenAlt.length === 0 || offenNeu.length === 0) return zuNeu
  const paare: { i: number; j: number; w: number }[] = []
  if (offenAlt.length * offenNeu.length <= MAX_PAARE) {
    for (const i of offenAlt) {
      for (const j of offenNeu) {
        const w = aehnlich(A.saetze[i]?.woerter ?? new Set(), N.saetze[j]?.woerter ?? new Set())
        if (w >= SCHWELLE) paare.push({ i, j, w })
      }
    }
    paare.sort((a, b) => b.w - a.w || a.i - b.i)
  } else {
    // Sehr viele umbenannte Prüfsätze auf einmal: der Reihe nach (sonst würde die Ähnlichkeit zu teuer).
    offenAlt.forEach((i, k) => {
      const j = offenNeu[k]
      if (j !== undefined) paare.push({ i, j, w: 1 })
    })
  }
  for (const p of paare) {
    if (zuNeu.has(p.i) || vergeben.has(p.j)) continue
    zuNeu.set(p.i, p.j)
    vergeben.add(p.j)
  }
  return zuNeu
}

export function testBetrug(alt: string | undefined, neu: string, file: string): SFund[] {
  const sprache = spracheVon(file)
  if (alt === undefined || alt === neu || !sprache || !istPruefdatei(file)) return []
  const A = stand(alt, sprache)
  const N = stand(neu, sprache)
  const c = N.code
  const zuNeu = zuordnenSaetze(A, N)
  const funde: SFund[] = []
  const bewusst = (at: number): boolean => OK_SICHER.test(c.zeilen[c.zeile(at) - 1] ?? '')
  const fund = (at: number, code: string, de: string, en: string, zeile?: number) =>
    funde.push({ line: zeile ?? c.zeile(at), col: zeile === undefined ? c.spalte(at) : 1, code, schwer: false, scanner: SCANNER(), text: t(de, en) })

  // Wo ein verschwundener Prüfsatz im neuen Stand stand: beim nächsten erhaltenen danach, sonst beim letzten davor.
  const ortNeu = (i: number): number => {
    for (let k = i + 1; k < A.saetze.length; k++) {
      const j = zuNeu.get(k)
      if (j !== undefined) return c.zeile(N.saetze[j]?.kopf ?? 0)
    }
    for (let k = i - 1; k >= 0; k--) {
      const j = zuNeu.get(k)
      if (j !== undefined) return c.zeile(N.saetze[j]?.bis ?? 0)
    }
    return 1
  }

  // Die Texte bleiben unter 200 Zeichen: so lang zeigt der Wächter eine eigene Meldung (clip in register.tsx, what).
  // TEST-GELOESCHT
  A.saetze.forEach((s, i) => {
    if (zuNeu.has(i)) return
    const name = daten(s.name, 60)
    fund(0, 'TEST-GELOESCHT',
      `Prüfsatz ${name} (vorher Zeile ${A.code.zeile(s.kopf)}) ist weg - löschen oder auskommentieren nur mit geänderter Vorgabe und Freigabe`,
      `test ${name} (before line ${A.code.zeile(s.kopf)}) is gone - deleting or commenting it out needs a changed requirement and the user's approval`,
      ortNeu(i))
  })

  // TEST-AUS: nur, was im alten Stand noch lief
  for (const [i, j] of zuNeu) {
    const s = N.saetze[j]
    if (!s?.aus || A.saetze[i]?.aus || bewusst(s.kopf)) continue
    fund(s.kopf, 'TEST-AUS',
      `Prüfsatz ${daten(s.name, 50)} ist jetzt ausgeschaltet (${daten(s.aus, 25)}) - den Code beheben, nicht den Prüfsatz; nur mit Freigabe`,
      `test ${daten(s.name, 50)} is now switched off (${daten(s.aus, 25)}) - fix the code, not the test; only with the user's approval`)
  }

  // TEST-ERWARTUNG: je Prüfsatz (bzw. ausserhalb) und gleichem geprüftem Ausdruck die Erwartungen vorher und nachher
  const gruppen = new Map<string, { alt: Pruefung[]; neu: Pruefung[] }>()
  const gruppe = (g: string, p: Pruefung) => {
    const k = `${g}\u0000${p.schluessel}`
    const e = gruppen.get(k) ?? { alt: [], neu: [] }
    gruppen.set(k, e)
    return e
  }
  for (const p of A.pruefungen) {
    if (p.schluessel === undefined) continue
    const j = p.satz < 0 ? -1 : zuNeu.get(p.satz)
    if (j === undefined) continue
    gruppe(String(j), p).alt.push(p)
  }
  for (const p of N.pruefungen) if (p.schluessel !== undefined) gruppe(String(p.satz), p).neu.push(p)
  for (const { alt: va, neu: vn } of gruppen.values()) {
    if (va.length === 0 || vn.length === 0) continue
    const frei = [...vn]
    const weg: Pruefung[] = []
    for (const p of va) {
      const k = frei.findIndex(q => q.wert === p.wert)
      if (k >= 0) frei.splice(k, 1)
      else weg.push(p)
    }
    for (let k = 0; k < Math.min(weg.length, frei.length); k++) {
      const vorher = weg[k]
      const jetzt = frei[k]
      if (!vorher || !jetzt || bewusst(jetzt.at)) continue
      const [wa, wn] = abUnterschied(vorher.wertZeigen ?? '', jetzt.wertZeigen ?? '')
      const w = (p: Pruefung, s: string) => `${p.nicht ? t('nicht ', 'not ') : ''}${daten(s, 40)}`
      fund(jetzt.at, 'TEST-ERWARTUNG',
        `Erwartung geändert (${w(vorher, wa)} -> ${w(jetzt, wn)}) bei gleichem Ausdruck ${daten(jetzt.zeigen ?? '', 40)} - nur mit geänderter Vorgabe erlaubt`,
        `expectation changed (${w(vorher, wa)} -> ${w(jetzt, wn)}) with the same expression ${daten(jetzt.zeigen ?? '', 40)} - only allowed with a changed requirement`)
    }
  }

  // TEST-WENIGER: Zahl aller Prüfungen; gemeldet beim ersten Prüfsatz, der weniger hat, sonst beim ersten verschwundenen.
  const vorher = A.pruefungen.length
  const jetzt = N.pruefungen.length
  if (jetzt < vorher) {
    const zahl = (s: Stand) => {
      const n = new Map<number, number>()
      for (const p of s.pruefungen) n.set(p.satz, (n.get(p.satz) ?? 0) + 1)
      return n
    }
    const za = zahl(A)
    const zn = zahl(N)
    const weniger = [...zuNeu].filter(([i, j]) => (zn.get(j) ?? 0) < (za.get(i) ?? 0)).map(([, j]) => N.saetze[j]?.kopf ?? 0).sort((a, b) => a - b)[0]
    const geloescht = A.saetze.findIndex((_, i) => !zuNeu.has(i))
    fund(weniger ?? 0, 'TEST-WENIGER',
      `weniger Prüfungen als vorher (vorher ${vorher}, jetzt ${jetzt}) - nur mit geänderter Vorgabe und Freigabe; schlägt eine fehl, liegt der Fehler im Code`,
      `fewer checks than before (before ${vorher}, now ${jetzt}) - only with a changed requirement and the user's approval; if one fails, the bug is in the code`,
      weniger !== undefined ? undefined : geloescht >= 0 ? ortNeu(geloescht) : 1)
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}

// ---- immerWahr: Programmcode, der Vergleiche fest beantwortet oder nach der Testumgebung fragt
const CS_GLEICH = /\b(?:bool|Boolean)\s+(?:[\w<>,.\s]*?\.\s*)?(Equals|operator\s*==|operator\s*!=)\s*\(([^()]*)\)\s*(?:=>\s*(true|false)\s*;|\{\s*return\s+(true|false)\s*;\s*\})/g
const CS_ORDNUNG = /\b(?:int|Int32)\s+(?:[\w<>,.\s]*?\.\s*)?(CompareTo|Compare|GetHashCode)\s*\(([^()]*)\)\s*(?:=>\s*([-+]?\d+)\s*;|\{\s*return\s+([-+]?\d+)\s*;\s*\})/g
const JS_METHODE_FEST = /(?<![\w$.])(equals|compareTo|hashCode)\s*\(([^()]*)\)\s*(?::\s*[\w<>[\]|. ]+)?\{\s*return\s+(true|[-+]?\d+)\s*;?\s*\}/g
const JS_PFEIL_FEST = /(?<![\w$.])(equals|compareTo|hashCode)\s*[:=]\s*(?:async\s*)?(?:\(([^()]*)\)|[\w$]+)\s*(?::\s*[\w<>[\]|. ]+)?=>\s*(true|[-+]?\d+)\s*(?=[;,}\r\n]|$)/g
const PY_DUNDER = /^\s*(?:async\s+)?def\s+(__eq__|__ne__|__hash__|__lt__|__le__|__gt__|__ge__)\s*\(/
const PY_LAMBDA = /^\s*(__eq__|__ne__|__hash__|__lt__|__le__|__gt__|__ge__)\s*=\s*lambda\b[^:]*:\s*(True|False|[-+]?\d+)\s*$/
const PY_RETURN_FEST = /^\s*return\s+(True|False|[-+]?\d+)\s*$/
const ZAHL = /^[-+]?\d+$/
// Welcher feste Wert bei welchem Namen der Betrug ist: Gleichheit fest wahr, Ungleichheit fest falsch, Ordnung und Hash fest.
const FEST_ART: Record<string, { art: 'gleich' | 'ordnung' | 'hash'; wert: (w: string) => boolean }> = {
  Equals: { art: 'gleich', wert: w => w === 'true' }, '==': { art: 'gleich', wert: w => w === 'true' }, '!=': { art: 'gleich', wert: w => w === 'false' },
  equals: { art: 'gleich', wert: w => w === 'true' }, __eq__: { art: 'gleich', wert: w => w === 'True' }, __ne__: { art: 'gleich', wert: w => w === 'False' },
  CompareTo: { art: 'ordnung', wert: w => ZAHL.test(w) }, Compare: { art: 'ordnung', wert: w => ZAHL.test(w) }, compareTo: { art: 'ordnung', wert: w => ZAHL.test(w) },
  __lt__: { art: 'ordnung', wert: w => w === 'True' || w === 'False' }, __le__: { art: 'ordnung', wert: w => w === 'True' || w === 'False' },
  __gt__: { art: 'ordnung', wert: w => w === 'True' || w === 'False' }, __ge__: { art: 'ordnung', wert: w => w === 'True' || w === 'False' },
  GetHashCode: { art: 'hash', wert: w => ZAHL.test(w) }, hashCode: { art: 'hash', wert: w => ZAHL.test(w) }, __hash__: { art: 'hash', wert: w => ZAHL.test(w) },
}

// Namen von Umgebungsvariablen, die nur sagen, ob ein Prüfsatz oder eine Prüfkette läuft.
const TEST_VAR = /^(?:CI|TESTS?|TESTING|IS_?TEST(?:ING)?|UNIT_?TESTS?|RUNNING_?TESTS|PYTEST_CURRENT_TEST|JEST_WORKER_ID|VITEST\w*|VSTEST_\w+)$/i
// Fragen nach der Testumgebung; die Gruppe a ist das erste Wort des Codes (es muss im bereinigten Text stehen, sonst ist es Text
// oder Kommentar), v der Name der Variable.
const UMGEBUNG: Record<Sprache, RegExp[]> = {
  cs: [/\b(?<a>Environment)\s*\.\s*GetEnvironmentVariable\s*\(\s*@?"(?<v>[^"]*)"/dg],
  py: [
    /["'](?:pytest|_pytest|unittest)["']\s+in\s+(?<a>sys)\s*\.\s*modules\b/dg,
    /\b(?<a>os)\s*\.\s*(?:environ\s*\.\s*get|getenv)\s*\(\s*["'](?<v>[^"']*)["']/dg,
    /\b(?<a>os)\s*\.\s*environ\s*\[\s*["'](?<v>[^"']*)["']\s*\]/dg,
    /["'](?<v>[^"']*)["']\s+(?:not\s+)?in\s+(?<a>os)\s*\.\s*environ\b/dg,
  ],
  js: [/\b(?<a>process)\s*\.\s*env\s*(?:\.\s*(?<v>\w+)|\[\s*["'`](?<w>\w+)["'`]\s*\])/dg],
}
// Debugger.IsAttached als Verzweigung: in if/while/when, mit && oder || oder als Bedingung vor ?.
const CS_DEBUGGER = /\b(?<a>Debugger)\s*\.\s*IsAttached\b/dg
const VERZWEIGUNG = /\b(?:if|while|when)\s*\(|&&|\|\||\?(?![.?[])/

export function immerWahr(text: string, file: string): SFund[] {
  const sprache = spracheVon(file)
  if (!sprache || istPruefdatei(file)) return []
  const c = codeVon(text, sprache)
  const funde: SFund[] = []
  const melden = (at: number, code: string, schwer: boolean, de: string, en: string) => {
    const nr = c.zeile(at)
    if (OK_SICHER.test(c.zeilen[nr - 1] ?? '') || funde.some(f => f.line === nr && f.code === code)) return
    funde.push({ line: nr, col: c.spalte(at), code, schwer, scanner: SCANNER(), text: t(de, en) })
  }
  const fest = (at: number, name: string, wert: string) => {
    const f = FEST_ART[name]
    if (!f || !f.wert(wert)) return
    const was = daten(name, 40)
    const w = daten(wert, 20)
    if (f.art === 'gleich') {
      melden(at, 'VERGLEICH-IMMER-WAHR', true,
        `${was} liefert fest ${w}: alles gilt als gleich, ein Prüfsatz besteht auch mit falschem Ergebnis - die Felder echt vergleichen`,
        `${was} always returns ${w}: everything counts as equal, a test passes even with a wrong result - compare the fields for real`)
    } else if (f.art === 'ordnung') {
      melden(at, 'VERGLEICH-IMMER-WAHR', true,
        `${was} liefert fest ${w}: die Reihenfolge ist erfunden, Sortieren und Prüfsätze sehen keinen Unterschied - die Felder echt vergleichen`,
        `${was} always returns ${w}: the order is made up, sorting and tests see no difference - compare the fields for real`)
    } else {
      melden(at, 'VERGLEICH-IMMER-WAHR', true,
        `${was} liefert fest ${w}: alle Objekte bekommen denselben Hash - den Hash aus denselben Feldern bilden wie den Vergleich`,
        `${was} always returns ${w}: every object gets the same hash - build the hash from the same fields as the comparison`)
    }
  }
  if (sprache === 'cs') {
    for (const m of c.bare.matchAll(CS_GLEICH)) fest(m.index ?? 0, (m[1] ?? '').replace(/^operator\s*/, ''), m[3] ?? m[4] ?? '')
    for (const m of c.bare.matchAll(CS_ORDNUNG)) fest(m.index ?? 0, m[1] ?? '', m[3] ?? m[4] ?? '')
  } else if (sprache === 'js') {
    for (const re of [JS_METHODE_FEST, JS_PFEIL_FEST]) for (const m of c.bare.matchAll(re)) fest(m.index ?? 0, m[1] ?? '', m[3] ?? '')
  } else {
    const zeilen = pyZeilen(c.bare)
    zeilen.forEach((z, i) => {
      const l = PY_LAMBDA.exec(z.text)
      if (l) return fest(z.von + z.text.length - z.text.trimStart().length, l[1] ?? '', l[2] ?? '')
      const d = PY_DUNDER.exec(z.text)
      if (!d) return
      // Der Rumpf besteht nur aus "return <fester Wert>" (ein Docstring davor zählt nicht).
      const inline = /\)\s*(?:->[^:]*)?:[ \t]*(\S[\s\S]*)$/.exec(z.text)?.[1]
      let rumpf: string[]
      if (inline !== undefined) rumpf = [inline]
      else {
        rumpf = []
        for (let j = i + 1; j < zeilen.length && (zeilen[j]?.einzug ?? 0) > z.einzug; j++) {
          const x = zeilen[j]?.text ?? ''
          if (!PY_NUR_TEXT.test(x.trim())) rumpf.push(x)
        }
      }
      const r = rumpf.length === 1 ? PY_RETURN_FEST.exec(rumpf[0] ?? '') : null
      if (r) fest(z.von + z.text.length - z.text.trimStart().length, d[1] ?? '', r[1] ?? '')
    })
  }
  // TEST-UMGEBUNG
  const imCode = (i: number): boolean => c.bare[i] === text[i] && /[A-Za-z_$]/.test(text[i] ?? '')
  const umgebung = (at: number, stelle: string) =>
    melden(at, 'TEST-UMGEBUNG', false,
      `Programmcode fragt nach der Testumgebung (${daten(stelle, 30)}) - so prüft der Prüfsatz etwas anderes, als der Benutzer bekommt; bewusst: "code-waechter:ok SICHERHEIT"`,
      `program code asks for the test environment (${daten(stelle, 30)}) - so the test checks something else than the user gets; deliberate: "code-waechter:ok SICHERHEIT"`)
  for (const re of UMGEBUNG[sprache]) {
    for (const m of text.matchAll(re)) {
      const a = m.indices?.groups?.a?.[0]
      if (a === undefined || !imCode(a)) continue
      const v = m.groups?.v ?? m.groups?.w
      const at = m.index ?? 0
      if (v === undefined) umgebung(at, m[0])
      else if (TEST_VAR.test(v)) umgebung(at, m[0])
      else if (v === 'NODE_ENV') {
        // NODE_ENV zählt nur im Vergleich mit 'test'
        const ende = at + m[0].length
        if (/^\s*[!=]==?\s*["'`]test["'`]/.test(text.slice(ende, ende + 20)) || /["'`]test["'`]\s*[!=]==?\s*$/.test(text.slice(Math.max(0, at - 20), at))) umgebung(at, m[0])
      }
    }
  }
  if (sprache === 'cs') {
    let bareZeilen: string[] | undefined
    for (const m of text.matchAll(CS_DEBUGGER)) {
      const at = m.index ?? 0
      if (!imCode(at)) continue
      bareZeilen ??= c.bare.split('\n')
      if (VERZWEIGUNG.test(bareZeilen[c.zeile(at) - 1] ?? '')) umgebung(at, m[0])
    }
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}
