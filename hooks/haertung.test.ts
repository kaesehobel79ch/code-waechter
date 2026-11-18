import { expect, test } from 'claude-code/testing'
import { blankCode, csHardeningHints, kiBefunde } from './haertung'

// KI-Fehlerarten: jede Art schlägt an, die saubere Form und die bewusste Stelle bleiben still.
test('KI-Fehlerarten: Geheimnis, Debug-Rest, Merkposten und leerer Fang schlagen an, sauberer Code nicht', () => {
  const arten = (text: string, datei: string) => kiBefunde(text, datei).map(b => b.art).sort()
  const schluessel = 'sk-' + 'a'.repeat(40)
  expect(arten(`var k = "${schluessel}";`, 'D:\\p\\A.cs')).toEqual(['geheimnis'])
  expect(arten(`var k = "${schluessel}"; // code-waechter:ok KI`, 'D:\\p\\A.cs')).toEqual([])
  expect(arten('Debug.WriteLine("x");', 'D:\\p\\A.cs')).toEqual(['debug'])
  expect(arten('try { Lies(); } catch (IOException) { }', 'D:\\p\\A.cs')).toEqual(['leerer_fang'])
  expect(arten('try { Lies(); } catch (IOException ex) { App.Protokolliere(ex, "Lesen"); }', 'D:\\p\\A.cs')).toEqual([])
  expect(arten('# TO' + 'DO: spaeter', 'D:\\p\\a.py')).toEqual(['merkposten'])
  expect(arten('try:\n    lies()\nexcept OSError:\n    pass\n', 'D:\\p\\a.py')).toEqual(['leerer_fang'])
  expect(arten('try:\n    lies()\nexcept OSError as e:\n    melde(e)\n', 'D:\\p\\a.py')).toEqual([])
  expect(arten('try:\n    lies()\nexcept OSError:\n    pass   # die Lampe darf nie aufhalten\n', 'D:\\p\\a.py')).toEqual([])
  expect(arten('TO' + 'DO = os.path.join(d, "TO-DO.txt")', 'D:\\p\\a.py')).toEqual([])
  expect(arten('x = 1  // TO' + 'DO: aufraeumen', 'D:\\p\\A.cs')).toEqual(['merkposten'])
  expect(arten('breakpoint()', 'D:\\p\\a.py')).toEqual(['debug'])
  expect(arten('console.log(x)', 'D:\\p\\a.ts')).toEqual(['debug'])
  expect(arten('-----BEGIN ' + 'PRIVATE KEY-----', 'D:\\p\\a.ts')).toEqual(['geheimnis'])
  expect(arten('Debug.WriteLine("x");', 'D:\\p\\notiz.txt')).toEqual([])
  expect(arten('public int Summe(int a, int b) => a + b;', 'D:\\p\\A.cs')).toEqual([])
})

// Härtungs-Hinweise (haertung.ts). Gegenprobe gegen zwei echte, inzwischen berichtigte Lücken eines WPF-Programms
// (Sicherheitsprüfung 06.11.2026): die alte Form schlägt an, die berichtigte bleibt still.

const F = 'D:\\p\\App\\Services\\X.cs'

// Lücke 1, alt: SicherungsPasswortTresor.Lesen machte aus jedem Fehler "kein Passwort".
const LUECKE1_ALT = `internal static class SicherungsPasswortTresor
{
    internal static string? Lesen()
    {
        try
        {
            PasswordCredential eintrag = new PasswordVault().Retrieve(Bereich, Benutzer);
            eintrag.RetrievePassword();
            return string.IsNullOrEmpty(eintrag.Password) ? null : eintrag.Password;
        }
        catch (Exception)
        {
            // Kein Eintrag: Windows meldet das als Ausnahme (Element nicht gefunden).
            return null;
        }
    }
}
`

// Lücke 1, berichtigt: nur "nicht gefunden" heisst leer, jeder andere Fehler heisst unlesbar.
const LUECKE1_NEU = `internal static class SicherungsPasswortTresor
{
    private const int NichtGefunden = unchecked((int)0x80070490);
    internal static string? Lesen(out bool unlesbar)
    {
        unlesbar = false;
        try
        {
            PasswordCredential eintrag = new PasswordVault().Retrieve(Bereich, Benutzer);
            return eintrag.Password;
        }
        catch (Exception ex) when (ex.HResult == NichtGefunden)
        {
            return null;
        }
        catch (Exception ex)
        {
            unlesbar = true;
            Log(ex, "Sicherungspasswort lesen");
            return null;
        }
    }
}
`

// Lücke 2, alt: alle Treffer zweier Such-Antworten kamen ohne Obergrenze in Quellen.
const LUECKE2_ALT = `class S
{
    async Task SammleAsync()
    {
        TavilySucheErgebnis? grunddaten = grunddatenNoetig
            ? stand.Grunddaten ??= await Suchdienste.SpielinfoSucheAsync(einstellungen, "frage", maxTreffer: 5, suchZeichen)
            : null;
        TavilySucheErgebnis? fragenQuelle = stand.FragenQuelle ??= await Suchdienste.SpielinfoSucheAsync(einstellungen, "x", maxTreffer: 5, suchZeichen);
        foreach (TavilyTreffer treffer in (grunddaten?.Treffer ?? new List<TavilyTreffer>())
                     .Concat(fragenQuelle?.Treffer ?? new List<TavilyTreffer>()))
        {
            if (treffer.Url.Length is > 0 and <= MaxAdresse && !info.Quellen.Contains(treffer.Url))
            {
                info.Quellen.Add(treffer.Url);
            }
        }
    }
}
`

// Lücke 2, berichtigt: je Suche höchstens MaxGespeicherteTreffer.
const LUECKE2_NEU = LUECKE2_ALT.replace(
  `foreach (TavilyTreffer treffer in (grunddaten?.Treffer ?? new List<TavilyTreffer>())
                     .Concat(fragenQuelle?.Treffer ?? new List<TavilyTreffer>()))`,
  `foreach (TavilyTreffer treffer in (grunddaten?.Treffer ?? new List<TavilyTreffer>()).Take(MaxGespeicherteTreffer)
                     .Concat((fragenQuelle?.Treffer ?? new List<TavilyTreffer>()).Take(MaxGespeicherteTreffer)))`,
)

test('Gegenprobe Lücke 1: altes "jeder Fehler ist leer" schlägt an, die berichtigte Form nicht', async () => {
  const alt = csHardeningHints(LUECKE1_ALT, F)
  expect(alt.length).toBe(1)
  expect(alt[0].line).toBe(11)
  expect(alt[0].code).toBe('HAERTUNG')
  expect(alt[0].text).toContain('gerade nicht lesbar')
  expect(csHardeningHints(LUECKE1_NEU, F).length).toBe(0)
})

test('Gegenprobe Lücke 2: alte Schleife ohne Grenze schlägt an, die berichtigte mit Take nicht', async () => {
  expect(LUECKE2_NEU).not.toBe(LUECKE2_ALT)
  const alt = csHardeningHints(LUECKE2_ALT, F)
  expect(alt.length).toBe(1)
  expect(alt[0].line).toBe(9)
  expect(alt[0].text).toContain('ohne Grenze')
  expect(csHardeningHints(LUECKE2_NEU, F).length).toBe(0)
})

test('Schleife: break oder Mengenprüfung im Rumpf gilt als Grenze, eigene Daten und Task.Run zählen nicht als Antwort von aussen', async () => {
  const mit = (rumpf: string, quelle = 'await _http.GetFromJsonAsync<List<string>>(url)') =>
    csHardeningHints(`class A { async Task F() { var antwort = ${quelle}; foreach (string s in antwort) { ${rumpf} } } }`, F).length
  expect(mit('liste.Add(s);')).toBe(1)
  expect(mit('if (liste.Count >= Max) break; liste.Add(s);')).toBe(0)
  expect(mit('if (liste.Count >= Max) return; liste.Add(s);')).toBe(0)
  expect(mit('Console.WriteLine(s);')).toBe(0)
  expect(mit('liste.Add(s);', 'await Task.Run(() => Grundwissen.Suchen(frage), ct)')).toBe(0)
  expect(mit('liste.Add(s);', 'await File.ReadAllLinesAsync(pfad)')).toBe(0)
  expect(mit('liste.Add(s);', 'Lies()')).toBe(0)
})

test('catch: mit when, mit Protokoll, leer oder mit Markierung kein Hinweis; catch ohne Typ und leere Liste schon', async () => {
  const mit = (c: string) => csHardeningHints(`class A { string? F() { try { return G(); } ${c} } }`, F).length
  expect(mit('catch { return null; }')).toBe(1)
  expect(mit('catch (Exception) { return new List<string>(); }')).toBe(1)
  expect(mit('catch (System.Exception e) { return string.Empty; }')).toBe(1)
  expect(mit('catch (Exception) { return ""; }')).toBe(1)
  expect(mit('catch (Exception) { return default; }')).toBe(1)
  expect(mit('catch (Exception ex) when (ex is IOException) { return null; }')).toBe(0)
  expect(mit('catch (IOException) { return null; }')).toBe(0)
  expect(mit('catch (Exception ex) { Log(ex, "x"); return null; }')).toBe(0)
  expect(mit('catch (Exception) { return false; }')).toBe(0)
  expect(mit('catch (Exception) { }')).toBe(0)
  expect(mit('catch (Exception) // code-waechter:ok HAERTUNG null heisst hier unlesbar\n { return null; }')).toBe(0)
  expect(mit('catch (Exception) { // code-waechter:ok HAERTUNG\n return null; }')).toBe(0)
})

test('Text in Kommentaren und Zeichenketten zählt nicht, die Zeilen bleiben gleich', async () => {
  const text = 'class A {\n  // catch (Exception) { return null; }\n  string s = "catch { return null; }";\n  string v = @"a ""b"" catch { return null; }";\n}\n'
  expect(csHardeningHints(text, F).length).toBe(0)
  const blank = blankCode(text)
  expect(blank.length).toBe(text.length)
  expect(blank.split('\n').length).toBe(text.split('\n').length)
})
