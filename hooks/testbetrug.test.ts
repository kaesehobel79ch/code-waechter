import { expect, test } from 'claude-code/testing'
import { setLang } from './i18n'
import { immerWahr, istPruefdatei, testBetrug } from './testbetrug'

// Erwartungen aus dem Auftrag "Testbetrug" (27.11.2026, Bauplan des Code-Wächters), nicht aus dem Code. Die Ausschalt-Wörter
// sind zusammengesetzt: wörtlich in dieser Datei meldeten die KI-Fehlerarten sonst "Prüfsatz abgeschaltet" (wie haertung.test.ts).
const SK = 'sk' + 'ip'
const IGN = 'Ign' + 'ore'

const TS = 'D:\\p\\rechner.test.ts'
const PY = 'D:\\p\\test_rechner.py'
const CS = 'D:\\p\\Rechner.Tests\\RechnerTests.cs'

const funde = (alt: string | undefined, neu: string, file: string) => {
  setLang('de')
  return testBetrug(alt, neu, file)
}
const codes = (alt: string | undefined, neu: string, file: string) => funde(alt, neu, file).map(f => f.code)
// Ersetzt genau eine Stelle; fehlt sie, wäre der Prüfsatz wertlos.
const ersetzt = (text: string, alt: string, neu: string): string => {
  if (text.split(alt).length !== 2) throw new Error(`Stelle nicht genau einmal da: ${alt}`)
  return text.replace(alt, neu)
}

const JS_ALT = [
  "import { expect, test } from 'claude-code/testing'",
  "test('addiert', () => {",
  '  expect(plus(1, 2)).toBe(3)',
  '  expect(plus(2, 2)).toBe(4)',
  '})',
  "test('teilt', () => {",
  '  expect(teil(6, 3)).toBe(2)',
  '})',
  '',
].join('\n')

const PY_ALT = [
  'import unittest',
  'from rechner import plus',
  '',
  '',
  'class Rechner(unittest.TestCase):',
  '    def test_plus(self):',
  '        self.assertEqual(plus(1, 2), 3)',
  '        assert plus(2, 2) == 4',
  '',
  '    def test_null(self):',
  '        """Null bleibt null."""',
  '        self.assertTrue(plus(0, 0) == 0)',
  '',
].join('\n')

const CS_ALT = [
  'using Xunit;',
  'public class RechnerTests',
  '{',
  '    [Fact]',
  '    public void Plus()',
  '    {',
  '        Assert.Equal(3, Rechner.Plus(1, 2));',
  '        Assert.Equal(4, Rechner.Plus(2, 2));',
  '    }',
  '',
  '    [Fact]',
  '    public void Teil() => Assert.Equal(2, Rechner.Teil(6, 3));',
  '}',
  '',
].join('\n')

test('Prüfdateien: Namen und Ordner der Prüfprogramme zählen, andere Dateien nicht', () => {
  for (const f of ['D:\\p\\a.test.ts', 'D:\\p\\a.spec.js', 'D:\\p\\a.test.tsx', 'D:\\p\\test_a.py', 'D:\\p\\a_test.py', 'D:\\p\\RechnerTests.cs', 'D:\\p\\RechnerTest.cs',
    'D:\\p\\Tests\\Hilfe.cs', 'D:\\p\\test\\hilfe.py', 'D:\\p\\tests\\hilfe.py', 'D:\\p\\__tests__\\hilfe.js', 'D:\\p\\Rechner.Tests\\Hilfe.cs']) {
    expect([f, istPruefdatei(f)]).toEqual([f, true])
  }
  for (const f of ['D:\\p\\Latest.cs', 'D:\\p\\rechner.ts', 'D:\\p\\contest\\a.py', 'D:\\p\\testament.py', 'D:\\p\\a.test.json']) {
    expect([f, istPruefdatei(f)]).toEqual([f, false])
  }
})

test('Neue Datei (kein alter Inhalt) und unveränderter Inhalt: nichts', () => {
  expect(codes(undefined, JS_ALT, TS)).toEqual([])
  expect(codes(JS_ALT, JS_ALT, TS)).toEqual([])
  expect(codes(undefined, PY_ALT, PY)).toEqual([])
})

test('TEST-WENIGER (JavaScript): eine Prüfung weniger ist ein Hinweis, der Text nennt vorher und nachher', () => {
  const f = funde(JS_ALT, ersetzt(JS_ALT, '  expect(plus(2, 2)).toBe(4)\n', ''), TS)
  expect(f.map(x => [x.code, x.line, x.schwer])).toEqual([['TEST-WENIGER', 2, false]])
  expect(f[0]?.text).toContain('vorher 3')
  expect(f[0]?.text).toContain('jetzt 2')
})

test('TEST-WENIGER (Python): ein assert weniger', () => {
  const f = funde(PY_ALT, ersetzt(PY_ALT, '        assert plus(2, 2) == 4\n', ''), PY)
  expect(f.map(x => [x.code, x.line, x.schwer])).toEqual([['TEST-WENIGER', 6, false]])
  expect(f[0]?.text).toContain('vorher 3')
})

test('TEST-WENIGER (C#): ein Assert weniger', () => {
  expect(codes(CS_ALT, ersetzt(CS_ALT, '        Assert.Equal(4, Rechner.Plus(2, 2));\n', ''), CS)).toEqual(['TEST-WENIGER'])
})

test('TEST-ERWARTUNG (JavaScript): toBe(3) -> toBe(4) bei gleichem Ausdruck', () => {
  const f = funde(JS_ALT, ersetzt(JS_ALT, 'toBe(3)', 'toBe(4)'), TS)
  expect(f.map(x => [x.code, x.line, x.schwer])).toEqual([['TEST-ERWARTUNG', 3, false]])
  expect(f[0]?.text).toContain('Erwartung geändert')
  expect(f[0]?.text).toContain('nur mit geänderter Vorgabe erlaubt')
  // auch die Umkehr (toBe -> not.toBe) und der Wechsel toBeTruthy -> toBeFalsy sind eine andere Erwartung
  expect(codes(JS_ALT, ersetzt(JS_ALT, 'toBe(3)', 'not.toBe(3)'), TS)).toEqual(['TEST-ERWARTUNG'])
  const wahr = JS_ALT.replace('toBe(2)', 'toBeTruthy()')
  expect(codes(wahr, ersetzt(wahr, 'toBeTruthy()', 'toBeFalsy()'), TS)).toEqual(['TEST-ERWARTUNG'])
})

test('TEST-ERWARTUNG (C#, Python): Assert.AreEqual(5, x) -> (6, x), assert x == 1 -> == 2, self.assertEqual(x, 1) -> (x, 2)', () => {
  const cs = ['[TestClass]', 'public class FuenfTests', '{', '    [TestMethod]', '    public void Fuenf()', '    {', '        var x = Rechner.Plus(2, 3);', '        Assert.AreEqual(5, x);', '    }', '}'].join('\n')
  expect(funde(cs, ersetzt(cs, 'AreEqual(5, x)', 'AreEqual(6, x)'), CS).map(x => [x.code, x.line])).toEqual([['TEST-ERWARTUNG', 8]])
  const py = ['def test_eins():', '    x = eins()', '    assert x == 1', '', 'class Eins(unittest.TestCase):', '    def test_auch(self):', '        x = eins()', '        self.assertEqual(x, 1)', ''].join('\n')
  expect(funde(py, ersetzt(py, 'x == 1', 'x == 2'), PY).map(x => [x.code, x.line])).toEqual([['TEST-ERWARTUNG', 3]])
  expect(funde(py, ersetzt(py, 'assertEqual(x, 1)', 'assertEqual(x, 2)'), PY).map(x => [x.code, x.line])).toEqual([['TEST-ERWARTUNG', 8]])
})

test('TEST-ERWARTUNG: bei langer, vorne gleicher Erwartung zeigt der Text die Stelle des Unterschieds', () => {
  // Gemessen 27.11.2026 im Verlauf von sicherheit.test.ts: zwei gekürzte, gleich aussehende Werte sagten nichts.
  const lang = JS_ALT.replace('toBe(2)', 'toEqual({ devskim: true, cppcheck: true, bandit: false, gitleaks: true })')
  const f = funde(lang, ersetzt(lang, 'gitleaks: true })', 'gitleaks: true, muster: true })'), TS)
  expect(f.map(x => x.code)).toEqual(['TEST-ERWARTUNG'])
  expect(f[0]?.text).toContain('muster: true')
})

test('Kein TEST-ERWARTUNG, wenn Erwartung UND Ausdruck geändert wurden', () => {
  expect(codes(JS_ALT, ersetzt(JS_ALT, 'expect(plus(1, 2)).toBe(3)', 'expect(plus(1, 3)).toBe(4)'), TS)).toEqual([])
  expect(codes(PY_ALT, ersetzt(PY_ALT, 'assert plus(2, 2) == 4', 'assert plus(2, 3) == 5'), PY)).toEqual([])
  expect(codes(CS_ALT, ersetzt(CS_ALT, 'Assert.Equal(3, Rechner.Plus(1, 2))', 'Assert.Equal(4, Rechner.Plus(1, 3))'), CS)).toEqual([])
})

test('TEST-GELOESCHT: ein ganzer Prüfsatz ist weg - gelöscht oder auskommentiert (test, def test_, [Fact])', () => {
  const ohne = ersetzt(JS_ALT, "test('teilt', () => {\n  expect(teil(6, 3)).toBe(2)\n})\n", '')
  const f = funde(JS_ALT, ohne, TS)
  expect(f.map(x => x.code).sort()).toEqual(['TEST-GELOESCHT', 'TEST-WENIGER'])
  expect(f.find(x => x.code === 'TEST-GELOESCHT')?.text).toContain('teilt')
  expect(f.every(x => !x.schwer)).toBe(true)
  const auskommentiert = ersetzt(JS_ALT, "test('teilt', () => {\n  expect(teil(6, 3)).toBe(2)\n})", "// test('teilt', () => {\n//   expect(teil(6, 3)).toBe(2)\n// })")
  expect(codes(JS_ALT, auskommentiert, TS)).toContain('TEST-GELOESCHT')
  expect(codes(PY_ALT, ersetzt(PY_ALT, '    def test_null(self):\n        """Null bleibt null."""\n        self.assertTrue(plus(0, 0) == 0)\n', ''), PY)).toContain('TEST-GELOESCHT')
  expect(codes(CS_ALT, ersetzt(CS_ALT, '    [Fact]\n    public void Teil() => Assert.Equal(2, Rechner.Teil(6, 3));\n', ''), CS)).toContain('TEST-GELOESCHT')
})

test('TEST-AUS (JavaScript): skip, x-Vorsilbe, ausgeschaltete Gruppe, return am Anfang', () => {
  const f = funde(JS_ALT, ersetzt(JS_ALT, "test('teilt'", `test.${SK}('teilt'`), TS)
  expect(f.map(x => [x.code, x.line, x.schwer])).toEqual([['TEST-AUS', 6, false]])
  expect(f[0]?.text).toContain('teilt')
  const mitIt = JS_ALT.replace(/\btest\(/g, 'it(')
  expect(codes(mitIt, ersetzt(mitIt, "it('teilt'", `x${'it'}('teilt'`), TS)).toEqual(['TEST-AUS'])
  const gruppe = `describe('Rechner', () => {\n${JS_ALT}})\n`
  expect(codes(gruppe, ersetzt(gruppe, "describe('Rechner'", `describe.${SK}('Rechner'`), TS)).toEqual(['TEST-AUS', 'TEST-AUS'])
  expect(codes(JS_ALT, ersetzt(JS_ALT, "test('teilt', () => {\n", "test('teilt', () => {\n  return\n"), TS)).toEqual(['TEST-AUS'])
})

test('TEST-AUS (C#): Skip im Fact-Attribut, Ignore-Attribut, return am Anfang', () => {
  expect(codes(CS_ALT, ersetzt(CS_ALT, '    [Fact]\n    public void Teil()', `    [Fact(S${'kip'} = "später")]\n    public void Teil()`), CS)).toEqual(['TEST-AUS'])
  const nunit = CS_ALT.replace(/\[Fact\]/g, '[Test]')
  expect(codes(nunit, ersetzt(nunit, '    [Test]\n    public void Plus()', `    [Test]\n    [${IGN}("rot")]\n    public void Plus()`), CS)).toEqual(['TEST-AUS'])
  expect(codes(CS_ALT, ersetzt(CS_ALT, '    {\n        Assert.Equal(3', '    {\n        return;\n        Assert.Equal(3'), CS)).toEqual(['TEST-AUS'])
})

test('TEST-AUS (Python): unittest- und pytest-Dekorator, return am Anfang', () => {
  expect(codes(PY_ALT, ersetzt(PY_ALT, '    def test_plus', `    @unittest.${SK}("rot")\n    def test_plus`), PY)).toEqual(['TEST-AUS'])
  const pyt = 'import pytest\n\n\ndef test_plus():\n    assert plus(1, 2) == 3\n'
  expect(codes(pyt, ersetzt(pyt, 'def test_plus', `@pytest.mark.${SK}\ndef test_plus`), PY)).toEqual(['TEST-AUS'])
  expect(codes(PY_ALT, ersetzt(PY_ALT, '        """Null bleibt null."""\n', '        """Null bleibt null."""\n        return\n'), PY)).toEqual(['TEST-AUS'])
})

test('TEST-AUS nur, wenn der Prüfsatz im alten Stand noch lief', () => {
  const schon = ersetzt(JS_ALT, "test('teilt'", `test.${SK}('teilt'`)
  expect(codes(schon, ersetzt(schon, '  expect(teil(6, 3)).toBe(2)\n', '  expect(teil(6, 3)).toBe(2)\n  expect(teil(8, 4)).toBe(2)\n'), TS)).toEqual([])
})

test('Kein Treffer: Prüfsatz umbenannt, Reihenfolge geändert, neue Prüfungen dazu', () => {
  expect(codes(JS_ALT, ersetzt(JS_ALT, "test('teilt'", "test('dividiert'"), TS)).toEqual([])
  const teile = JS_ALT.split("test('teilt'")
  const getauscht = `${teile[0]?.split("test('addiert'")[0]}test('teilt'${teile[1]?.replace(/\n$/, '')}\ntest('addiert'${teile[0]?.split("test('addiert'")[1]}`
  expect(getauscht.includes("test('teilt'") && getauscht.indexOf("'teilt'") < getauscht.indexOf("'addiert'")).toBe(true)
  expect(codes(JS_ALT, getauscht, TS)).toEqual([])
  expect(codes(JS_ALT, ersetzt(JS_ALT, '  expect(teil(6, 3)).toBe(2)\n', '  expect(teil(6, 3)).toBe(2)\n  expect(teil(9, 3)).toBe(3)\n'), TS)).toEqual([])
  expect(codes(PY_ALT, ersetzt(PY_ALT, 'def test_null', 'def test_nullsumme'), PY)).toEqual([])
  expect(codes(CS_ALT, ersetzt(CS_ALT, 'public void Teil()', 'public void Dividiert()'), CS)).toEqual([])
})

test('Text in Kommentaren und Zeichenketten zählt nicht als Prüfung', () => {
  const mit = ersetzt(JS_ALT, '  expect(teil(6, 3)).toBe(2)\n', "  expect(teil(6, 3)).toBe(2)\n  // expect(teil(6, 2)).toBe(3)\n  const s = 'expect(a).toBe(1)'\n")
  expect(codes(mit, ersetzt(mit, '  // expect(teil(6, 2)).toBe(3)\n', ''), TS)).toEqual([])
  expect(codes(mit, ersetzt(mit, "'expect(a).toBe(1)'", "'expect(a).toBe(2)'"), TS)).toEqual([])
  const py = ersetzt(PY_ALT, '        assert plus(2, 2) == 4\n', '        assert plus(2, 2) == 4\n        # assert plus(3, 3) == 6\n')
  expect(codes(py, ersetzt(py, '        # assert plus(3, 3) == 6\n', ''), PY)).toEqual([])
})

test('Bewusste Stelle: "code-waechter:ok SICHERHEIT" in der Zeile wird nicht gemeldet', () => {
  expect(codes(JS_ALT, ersetzt(JS_ALT, 'toBe(3)', 'toBe(4) // code-waechter:ok SICHERHEIT Vorgabe 27.11.'), TS)).toEqual([])
})

test('Keine Prüfdatei: testBetrug meldet nichts', () => {
  expect(codes(JS_ALT, ersetzt(JS_ALT, '  expect(plus(2, 2)).toBe(4)\n', ''), 'D:\\p\\rechner.ts')).toEqual([])
})

const CS_PUNKT = [
  'public sealed class Punkt : IEquatable<Punkt>, IComparable<Punkt>',
  '{',
  '    public override bool Equals(object? obj) => true;',
  '    public bool Equals(Punkt? other) { return true; }',
  '    public static bool operator ==(Punkt? a, Punkt? b) => true;',
  '    public static bool operator !=(Punkt? a, Punkt? b) => false;',
  '    public override int GetHashCode() => 0;',
  '    public int CompareTo(Punkt? other)',
  '    {',
  '        return 0;',
  '    }',
  '}',
].join('\n')

test('VERGLEICH-IMMER-WAHR (C#, rot): Equals, operator ==/!=, GetHashCode und CompareTo fest', () => {
  setLang('de')
  const f = immerWahr(CS_PUNKT, 'D:\\p\\Punkt.cs')
  expect(f.map(x => [x.code, x.line, x.schwer])).toEqual([3, 4, 5, 6, 7, 8].map(n => ['VERGLEICH-IMMER-WAHR', n, true]))
  expect(f[0]?.text).toContain('Equals')
})

test('VERGLEICH-IMMER-WAHR (Python, JavaScript): __eq__ fest True, __hash__ fest, equals/hashCode fest', () => {
  const py = ['class Punkt:', '    def __eq__(self, other):', '        """Immer gleich."""', '        return True', '', '    def __hash__(self):', '        return 0', '', '    __ne__ = lambda self, o: False', ''].join('\n')
  expect(immerWahr(py, 'D:\\p\\punkt.py').map(x => [x.code, x.line, x.schwer])).toEqual([['VERGLEICH-IMMER-WAHR', 2, true], ['VERGLEICH-IMMER-WAHR', 6, true], ['VERGLEICH-IMMER-WAHR', 9, true]])
  const js = ['class Punkt {', '  equals(o: Punkt): boolean { return true }', '  hashCode = () => 0', '}', ''].join('\n')
  expect(immerWahr(js, 'D:\\p\\punkt.ts').map(x => [x.code, x.line, x.schwer])).toEqual([['VERGLEICH-IMMER-WAHR', 2, true], ['VERGLEICH-IMMER-WAHR', 3, true]])
})

test('Kein VERGLEICH-IMMER-WAHR: echter Vergleich, Aufruf, Text, Kommentar, Prüfdatei', () => {
  const echt = [
    'public sealed class Punkt',
    '{',
    '    public override bool Equals(object? obj) => obj is Punkt p && p.X == X;',
    '    public override int GetHashCode() => HashCode.Combine(X, Y);',
    '    public bool Gleich(Punkt p) { return p.Equals(this); }',
    '    // public override bool Equals(object? obj) => true;',
    '    const string S = "public override bool Equals(object obj) => true;";',
    '}',
  ].join('\n')
  expect(immerWahr(echt, 'D:\\p\\Punkt.cs')).toEqual([])
  expect(immerWahr(CS_PUNKT, 'D:\\p\\PunktTests.cs')).toEqual([])
  expect(immerWahr('class P:\n    def __eq__(self, o):\n        return self.x == o.x\n', 'D:\\p\\p.py')).toEqual([])
})

test('TEST-UMGEBUNG (Hinweis): Programmcode fragt nach der Testumgebung', () => {
  setLang('de')
  const cs = ['if (Environment.GetEnvironmentVariable("CI") != null) return 42;', 'if (Debugger.IsAttached) Starte();'].join('\n')
  expect(immerWahr(cs, 'D:\\p\\Start.cs').map(x => [x.code, x.line, x.schwer])).toEqual([['TEST-UMGEBUNG', 1, false], ['TEST-UMGEBUNG', 2, false]])
  const py = ['import os, sys', 'if "pytest" in sys.modules:', '    pass', 'probe = os.environ.get("PYTEST_CURRENT_TEST")', ''].join('\n')
  expect(immerWahr(py, 'D:\\p\\start.py').map(x => [x.code, x.line])).toEqual([['TEST-UMGEBUNG', 2], ['TEST-UMGEBUNG', 4]])
  expect(immerWahr("if (process.env.NODE_ENV === 'test') return 1\n", 'D:\\p\\start.ts').map(x => [x.code, x.line])).toEqual([['TEST-UMGEBUNG', 1]])
})

test('Kein TEST-UMGEBUNG: andere Variable, Debugger ohne Verzweigung, Text, NODE_ENV ohne test', () => {
  const cs = ['var p = Environment.GetEnvironmentVariable("PATH");', 'var d = Debugger.IsAttached;', 'var s = "if (Environment.GetEnvironmentVariable(\\"CI\\") != null)";'].join('\n')
  expect(immerWahr(cs, 'D:\\p\\Start.cs')).toEqual([])
  expect(immerWahr("const s = 'process.env.NODE_ENV === \"test\"'\nif (process.env.NODE_ENV === 'production') go()\n", 'D:\\p\\start.ts')).toEqual([])
})
