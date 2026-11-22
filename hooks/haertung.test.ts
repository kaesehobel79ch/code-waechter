import { expect, test } from 'claude-code/testing'
import { blankCode, csHardeningHints, csThreatFindings, kiBefunde } from './haertung'

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

test('KI-Fehlerarten: catch-when leer, async void ohne try und abgeschaltete Prüfsätze schlagen an', () => {
  const arten = (text: string, datei: string) => kiBefunde(text, datei).map(b => b.art).sort()
  expect(arten('try { S(); } catch (Exception ex) when (ex is IOException || ex is X) { }', 'D:\\p\\A.cs')).toEqual(['leerer_fang'])
  expect(arten('try\n{\n    S();\n}\ncatch (Win32Exception f)\n    when (f.NativeErrorCode == 1223)\n{\n}\n', 'D:\\p\\A.cs')).toEqual(['leerer_fang'])
  expect(arten('try { S(); } catch (Exception ex) when (ex is IOException) { Melde(ex); }', 'D:\\p\\A.cs')).toEqual([])
  expect(arten('try { S(); } catch (IOException) { }   // naechster Start versucht es wieder', 'D:\\p\\A.cs')).toEqual([])
  expect(arten('async void Laden()\n{\n    await Hole();\n}\n', 'D:\\p\\A.cs')).toEqual(['async_void'])
  expect(arten('async void Laden()\n{\n    try { await Hole(); } catch (IOException ex) { Melde(ex); }\n}\n', 'D:\\p\\A.cs')).toEqual([])
  expect(arten('private async void Knopf_Click(object sender, RoutedEventArgs e)\n{\n    await Hole();\n}\n', 'D:\\p\\A.cs')).toEqual([])
  expect(arten('P("kein async void Laden() mehr", ok);', 'D:\\p\\A.cs')).toEqual([])
  expect(arten("it.sk" + "ip('rechnet', () => {})", 'D:\\p\\a.test.ts')).toEqual(['test_aus'])
  expect(arten('console.log(x) // in Prüfdateien erlaubt', 'D:\\p\\a.test.ts')).toEqual([])
  expect(arten('@pytest.mark.sk' + 'ip\ndef test_a():\n    assert 1\n', 'D:\\p\\test_a.py')).toEqual(['test_aus'])
  expect(arten('[Fact(Sk' + 'ip = "spaeter")]', 'D:\\p\\A.cs')).toEqual(['test_aus'])
})

test('KI-Fehlerarten: Sicherheitslücken in C#, die der Prüfbau nicht meldet, schlagen an', () => {
  const arten = (text: string) => kiBefunde(text, 'D:\\p\\A.cs').map(b => b.art)
  expect(arten('var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = (a, b, c, d) => true };')).toEqual(['sicherheit'])
  expect(arten('h.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAny' + 'ServerCertificateValidator;')).toEqual(['sicherheit'])
  expect(arten('h.ServerCertificateCustomValidationCallback = (a, b, c, f) => f == SslPolicyErrors.None;')).toEqual([])
  expect(arten('var f = new Binary' + 'Formatter();')).toEqual(['sicherheit'])
  expect(arten('s.TypeNameHandling = TypeNameHandling.' + 'Auto;')).toEqual(['sicherheit'])
  expect(arten('s.TypeNameHandling = TypeNameHandling.None;')).toEqual([])
  expect(arten('r.DtdProcessing = DtdProcessing.' + 'Parse;')).toEqual(['sicherheit'])
  expect(arten('// nie DtdProcessing = DtdProcessing.' + 'Parse setzen')).toEqual([])
  expect(kiBefunde('requests.get(u, verify=' + 'False)', 'D:\\p\\a.py')).toEqual([]) // Python prüft ruff (S501)
})

// Bedrohungen beim Schreiben (21.11.2026, aus einem Härtetest): je Regel schlägt die Lücke an, die berichtigte Form
// bleibt still (Gegenprobe). Die Beispiele sind den echten Stellen nachgebaut (am 21.11.2026 über 1139 Dateien gemessen).
const regeln = (cs: string): string[] => csThreatFindings(cs, 'D:\\p\\A.cs').map(f => `${f.regel}${f.schwer ? '!' : ''}`)

test('Bedrohung R1: Start aus festem Temp-Ordner (auch in einer anderen Methode geladen) meldet, zufälliger Ordner nicht; runas ist ein Fehler', () => {
  const laden = 'class U {\n  string Laden() { string o = Path.Combine(Path.GetTempPath(), "App_Update"); return o; }\n'
  const starten = '  void Start(string p) { Process.Start(new ProcessStartInfo(p) { UseShellExecute = true }); }\n}\n'
  expect(regeln(laden + starten)).toEqual(['R1'])
  expect(regeln(laden + starten.replace('UseShellExecute = true', 'UseShellExecute = true, Verb = "runas"'))).toEqual(['R1!'])
  expect(regeln(laden.replace('Path.Combine(Path.GetTempPath(), "App_Update")', 'Directory.CreateTempSubdirectory("App_").FullName') + starten)).toEqual([])
  // Ohne Shell-Start (z. B. ein eigenes Werkzeug mit UseShellExecute = false) nicht.
  expect(regeln(laden + starten.replace('true', 'false'))).toEqual([])
})

test('Bedrohung R2: festes Salz (auch als Feld "…"u8) ist ein Fehler, zu wenige Runden ein Hinweis; zufälliges Salz und 600000 Runden still', () => {
  const kopf = 'class S {\n  private static readonly byte[] Salt = "App Zweck 1"u8.ToArray();\n  private const int Runden = 100_000;\n'
  const ab = '  byte[] K(string p) => Rfc2898DeriveBytes.Pbkdf2(p, Salt, Runden, HashAlgorithmName.SHA256, 32);\n}\n'
  expect(regeln(kopf + ab).sort()).toEqual(['R2', 'R2!'])
  const gut = 'class S {\n  private const int Runden = 600_000;\n  byte[] K(string p, byte[] salt) => Rfc2898DeriveBytes.Pbkdf2(p, salt, Runden, HashAlgorithmName.SHA256, 32);\n}\n'
  expect(regeln(gut)).toEqual([])
  expect(regeln('class S { byte[] K(string p) => Rfc2898DeriveBytes.Pbkdf2(p, Encoding.UTF8.GetBytes("fest"), 600000, HashAlgorithmName.SHA256, 32); }')).toEqual(['R2!'])
})

test('Bedrohung R3: Bild aus dem Netz ohne Grössengrenze meldet, mit DecodePixelWidth nicht', () => {
  const cs = 'class B {\n  async Task<BitmapImage> L(HttpClient h, string u) {\n    var b = await h.GetByteArrayAsync(u);\n    var bild = new BitmapImage();\n    bild.BeginInit(); bild.StreamSource = new MemoryStream(b); bild.EndInit();\n    return bild;\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R3'])
  expect(regeln(cs.replace('bild.BeginInit();', 'bild.BeginInit(); bild.DecodePixelWidth = 112;'))).toEqual([])
})

test('Bedrohung R4: Entschlüsseln gibt Text ohne Kennung unverändert zurück (auch mit Klammern) - meldet; null zurück nicht', () => {
  const cs = 'class G {\n  public static string? Auspacken(string g, string c)\n  {\n    if (!g.StartsWith(Kennung, StringComparison.Ordinal))\n    {\n      return g;\n    }\n    using var aes = new AesGcm(K(c), 16);\n    aes.Decrypt(n, t, tag, r);\n    return "";\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R4'])
  expect(regeln(cs.replace('return g;', 'return null;'))).toEqual([])
})

test('Bedrohung R5: Startargument löscht etwas - meldet; ein Argument ohne Löschen nicht', () => {
  const cs = 'class App {\n  protected override void OnStartup(StartupEventArgs e)\n  {\n    if (e.Args.Contains("--daten-loeschen")) { Speicher.AlleDatenLoeschen(); }\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R5'])
  expect(regeln(cs.replace('Speicher.AlleDatenLoeschen();', 'ZeigeHilfe();'))).toEqual([])
})

test('Bedrohung R6: alle Eigenschaften per Reflection von einem anderen Objekt übernehmen - meldet; eine feste Liste nicht', () => {
  const cs = 'class E {\n  public void Uebernehmen(E sicherung)\n  {\n    foreach (var p in typeof(E).GetProperties())\n    {\n      p.SetValue(this, p.GetValue(sicherung));\n    }\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R6'])
  expect(regeln('class E {\n  public void Uebernehmen(E s)\n  {\n    Name = s.Name;\n    Farbe = s.Farbe;\n  }\n}\n')).toEqual([])
})

test('Bedrohung R7: erst prüfen, dann für die Anzeige kürzen (auch über eine abgeleitete Variable) - meldet; erst kürzen, dann prüfen nicht', () => {
  const cs = 'class K {\n  static string Kuerzen(string text)\n  {\n    if (Filter.IstGesperrt(text)) return "";\n    string sauber = Filter.Entschaerfen(text);\n    return sauber.Length <= 100 ? sauber : sauber[..99] + "\u2026";\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R7'])
  const gut = 'class K {\n  static string Kuerzen(string text)\n  {\n    string kurz = text.Length <= 100 ? text : text[..99] + "\u2026";\n    return Filter.IstGesperrt(kurz) ? "" : kurz;\n  }\n}\n'
  expect(regeln(gut)).toEqual([])
  // Kein Kürzen für die Anzeige (ohne Auslassungszeichen): still (Fehlalarm in einem anderen Programm, 21.11.2026).
  expect(regeln('class F { string Z(string s) => Signatur.IstFrage(s) ? s.Substring(0, 24) : ""; }')).toEqual([])
})

test('Bedrohung R8: Liste aus einer Datei ohne Obergrenze übernehmen - meldet; mit Take nicht', () => {
  const cs = 'class W {\n  void Laden(string json)\n  {\n    var ids = JsonSerializer.Deserialize<List<string>>(json) ?? new();\n    _liste.AddRange(ids);\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R8'])
  expect(regeln(cs.replace('_liste.AddRange(ids);', '_liste.AddRange(ids.Take(5000));'))).toEqual([])
})

test('Bedrohung R9: Chat-Befehl nur am Leerzeichen getrennt - meldet; ohne Befehl oder mit Split(null) nicht', () => {
  const cs = 'class C {\n  bool IstStopp(string t)\n  {\n    var w = t.Split(\' \');\n    return w[0] == "!stopp";\n  }\n}\n'
  expect(regeln(cs)).toEqual(['R9'])
  expect(regeln(cs.replace("t.Split(' ')", 't.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)'))).toEqual([])
  expect(regeln('class C { string[] Teile(string t) => t.Split(\' \'); }')).toEqual([])
})

test('Bedrohung R10: Geheimnis in Protokoll oder Meldung - meldet; "gesetzt" und Tokenzahl nicht', () => {
  expect(regeln('class L { void A(string apiKey) { Log($"Schlüssel: {apiKey}"); } }')).toEqual(['R10'])
  expect(regeln('class L { void A(string apiKey) { Log($"Schlüssel gesetzt: {apiKey.Length > 0}"); } }')).toEqual([])
  expect(regeln('class L { void A(int tokenCount) { Log($"Tokens: {tokenCount}"); } }')).toEqual([])
  expect(regeln('class L { void A(string apiKey) { Log("Schlüssel ist gesetzt"); } }')).toEqual([])
})

test('Bedrohungen: bewusste Stelle (code-waechter:ok HAERTUNG) und Prüfdateien bleiben still', () => {
  const cs = 'class C {\n  bool IstStopp(string t)\n  {\n    var w = t.Split(\' \'); // code-waechter:ok HAERTUNG eigenes festes Format\n    return w[0] == "!stopp";\n  }\n}\n'
  expect(regeln(cs)).toEqual([])
  expect(csThreatFindings(cs.replace(' // code-waechter:ok HAERTUNG eigenes festes Format', ''), 'D:\\p\\Tests\\A.cs')).toEqual([])
})

// Unabhängige Prüfung 21.11.2026: übliche harmlose Stellen dürfen nicht anschlagen, verpasste Fälle müssen es (gemessen mit
// Gegenproben\regelproben.py: vorher 16 von 18 falsch, eine Datei mit 40000 Zeilen brauchte 4 Minuten).
test('Bedrohungen: harmlose Stellen (Admin-Neustart, Link, Anmeldung, CancellationToken, nameof, X.Tests) bleiben still', () => {
  const temp = '  static readonly string Log = Path.Combine(Path.GetTempPath(), "Tool.log");\n'
  expect(regeln(`class A {\n${temp}  void Admin() => Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });\n}\n`)).toEqual([])
  expect(regeln(`class A {\n${temp}  void Web() => Process.Start(new ProcessStartInfo("https://x.ch") { UseShellExecute = true });\n}\n`)).toEqual([])
  expect(regeln('class A {\n  byte[] K(string b, string k, byte[] salz) => Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes($"{b}:{k}"), salz, 600000, HashAlgorithmName.SHA256, 32);\n}\n')).toEqual([])
  // R2 meint das Salz: ein festes Kennwort-Argument mit zufälligem Salz ist kein festes Salz.
  expect(regeln('class A {\n  byte[] K(byte[] salz) => Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("Probe"), salz, 600000, HashAlgorithmName.SHA256, 32);\n}\n')).toEqual([])
  expect(regeln('class A {\n  async Task Go(string b, string passwort) { await _auth.LoginAsync(b, passwort); }\n}\n')).toEqual([])
  expect(regeln('class A {\n  async Task Go(string p, string z, CancellationToken cancellationToken) { await File.AppendAllTextAsync(p, z, cancellationToken); }\n}\n')).toEqual([])
  expect(regeln('class A {\n  void Go() { Log($"fehlt: {nameof(ApiKey)}"); }\n}\n')).toEqual([])
  expect(regeln('class A {\n  public bool IstBefehl(string t) => t.StartsWith(\'!\');\n  string[] Woerter(string t) => t.Split(\' \');\n}\n')).toEqual([])
  expect(regeln('class A {\n  static void Main(string[] args) {\n    if (args.Contains("--help")) Hilfe();\n    db.DeleteAlte();\n  }\n}\n')).toEqual([])
  expect(regeln('class A {\n  void Z(string url) {\n    if (Uri.IsWellFormedUriString(url, UriKind.Absolute)) label.Text = url.Length > 50 ? url.Substring(0, 50) + "\u2026" : url;\n  }\n}\n')).toEqual([])
  expect(csThreatFindings('class T {\n  static readonly byte[] Salt = "App 1"u8.ToArray();\n  byte[] K(string p) => Rfc2898DeriveBytes.Pbkdf2(p, Salt, 600000, HashAlgorithmName.SHA256, 32);\n}\n', 'D:\\p\\App.Tests\\KryptoTests.cs')).toEqual([])
  expect(csThreatFindings('class T {\n  static readonly byte[] Salt = "App 1"u8.ToArray();\n  byte[] K(string p) => Rfc2898DeriveBytes.Pbkdf2(p, Salt, 600000, HashAlgorithmName.SHA256, 32);\n}\n', 'D:\\p\\App.Probe\\Program.cs')).toEqual([])
})

test('Bedrohungen: verpasste Fälle schlagen an (Guid woanders, lokales/Sammel-Salz, Serilog, new-Zeile in der Methode) und eine grosse Datei bleibt schnell', () => {
  expect(regeln('class A {\n  static readonly string Ziel = Path.Combine(Path.GetTempPath(), "Setup.exe");\n  string Id = Guid.NewGuid().ToString();\n  void S() => Process.Start(new ProcessStartInfo(Ziel) { UseShellExecute = true });\n}\n')).toEqual(['R1'])
  expect(regeln('class A {\n  byte[] K(string pw) {\n    byte[] salt = Encoding.UTF8.GetBytes("fest");\n    return Rfc2898DeriveBytes.Pbkdf2(pw, salt, 600000, HashAlgorithmName.SHA256, 32);\n  }\n}\n')).toEqual(['R2!'])
  expect(regeln('class A {\n  static readonly byte[] Salz = [0x4B, 0x48];\n  byte[] K(string pw) => Rfc2898DeriveBytes.Pbkdf2(pw, Salz, 600000, HashAlgorithmName.SHA256, 32);\n}\n')).toEqual(['R2!'])
  expect(regeln('class A {\n  static readonly byte[] Salz = { 1, 2, 3 };\n  byte[] K(string pw) => Rfc2898DeriveBytes.Pbkdf2(pw, Salz, 600000, HashAlgorithmName.SHA256, 32);\n}\n')).toEqual(['R2!'])
  expect(regeln('class A {\n  void Go(string token) { Log.Information("{T}", token); }\n}\n')).toEqual(['R10'])
  expect(regeln('class A {\n  public void Laden(string json) {\n    var ids = JsonSerializer.Deserialize<List<string>>(json);\n    new Thread(Arbeit).Start();\n    _liste.AddRange(ids);\n  }\n}\n')).toEqual(['R8'])
  const gross = 'enum E {\n' + Array.from({ length: 40000 }, (_, i) => `  A${i} = ${i},`).join('\n') + '\n}\n'
  const t0 = Date.now()
  csThreatFindings(gross, 'D:\\p\\G.cs')
  expect(Date.now() - t0).toBeLessThan(5000)
})
