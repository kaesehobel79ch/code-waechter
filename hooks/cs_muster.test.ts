import { expect, test } from 'claude-code/testing'
import { csZusatzMuster } from './cs_muster'

// Erwartungen aus dem Auftrag vom 27.11.2026 (Bauplan "Alle drei Stufen", C#-Zusatzregeln), nicht aus dem Code.
const D = 'D:\\p\\Kasse\\Daten.cs'
const art = (text: string, file = D) => csZusatzMuster(text, file).map(f => `${f.code}${f.schwer ? '!' : ''}@${f.line}`)

test('CS-SQL: zusammengesetzter SQL-Text an CommandText, new SqlCommand & Co. und den Raw-Aufrufen von EF Core ist ein Fehler', () => {
  expect(art('cmd.CommandText = "SELECT * FROM Kunden WHERE Name = \'" + name + "\'";')).toEqual(['CS-SQL!@1'])
  expect(art('cmd.CommandText = "SELECT * FROM Kunden " +\n    "WHERE Name = \'" + name + "\'";')).toEqual(['CS-SQL!@1'])
  expect(art('var cmd = new SqlCommand($"DELETE FROM Kunden WHERE Id = {id}", verbindung);')).toEqual(['CS-SQL!@1'])
  expect(art('using var c = new SqliteCommand(string.Format("UPDATE Kunden SET Ort = \'{0}\'", ort), db);')).toEqual(['CS-SQL!@1'])
  expect(art('var c = new System.Data.Odbc.OdbcCommand(string.Concat("SELECT Name FROM Kunden WHERE Ort = \'", ort, "\'"), db);')).toEqual(['CS-SQL!@1'])
  expect(art('db.Database.ExecuteSqlRaw("INSERT INTO Log VALUES (\'" + text + "\')");')).toEqual(['CS-SQL!@1'])
  expect(art('await db.Database.ExecuteSqlRawAsync($"DELETE FROM Log WHERE Tag < {tag}");')).toEqual(['CS-SQL!@1'])
  expect(art('var k = ctx.Kunden.FromSqlRaw("SELECT * FROM Kunden WHERE Ort = \'" + ort + "\'").ToList();')).toEqual(['CS-SQL!@1'])
  expect(art('var n = db.Database.SqlQueryRaw<int>($"SELECT Id FROM Kunden WHERE Name = \'{name}\'");')).toEqual(['CS-SQL!@1'])
  expect(art('var c = new MySqlCommand("select * from kunden where id = " + id, con);')).toEqual(['CS-SQL!@1'])
  expect(art('var c = new NpgsqlCommand { CommandText = $"SELECT * FROM t WHERE id = {id}", Connection = con };')).toEqual(['CS-SQL!@1'])
  expect(art('OleDbCommand c = new($"SELECT * FROM t WHERE a = {a}", con);')).toEqual(['CS-SQL!@1'])
  expect(art('cmd.CommandText = $@"SELECT * FROM T WHERE a = {a}";')).toEqual(['CS-SQL!@1'])
  expect(art('cmd.CommandText = $"""\n    SELECT * FROM T\n    WHERE a = {a}\n    """;')).toEqual(['CS-SQL!@1'])
  expect(art('cmd.CommandText = $$"""SELECT * FROM T WHERE j = \'{x}\' AND a = {{a}}""";')).toEqual(['CS-SQL!@1'])
  expect(art('cmd.CommandText = "SELECT * FROM T WHERE a = " + (gross ? a : b);')).toEqual(['CS-SQL!@1'])
})

test('CS-SQL: SQL-Text in einer Variable derselben Methode, auch mit += angehängt', () => {
  expect(art([
    'void Laden(string name) {',
    '  string sql = "SELECT * FROM Kunden WHERE Name = \'" + name + "\'";',
    '  using var cmd = new OleDbCommand(sql, verbindung);',
    '}',
  ].join('\n'))).toEqual(['CS-SQL!@3'])
  expect(art([
    'void Suchen(string filter) {',
    '  var sql = "SELECT * FROM Kunden WHERE 1 = 1";',
    '  if (filter != null) sql += " AND Name = \'" + filter + "\'";',
    '  cmd.CommandText = sql;',
    '}',
  ].join('\n'))).toEqual(['CS-SQL!@4'])
  expect(art('var basis = "SELECT * FROM Kunden WHERE ";\ndb.Database.ExecuteSqlRaw(basis + "Ort = \'" + ort + "\'");')).toEqual(['CS-SQL!@2'])
  // Die Variable sql in A ist eine andere als der Parameter sql in B; der Parameter selbst ist nicht zusammengesetzt.
  expect(art([
    'void A(string x) {',
    '  var sql = "SELECT * FROM T WHERE a = " + x;',
    '}',
    'void B(string sql) {',
    '  cmd.CommandText = sql;',
    '}',
  ].join('\n'))).toEqual([])
  // Die Variable im inneren Block gilt nach dessen Ende nicht mehr; sql ist dort ein Feld der Klasse.
  expect(art([
    'void C(string x) {',
    '  if (x != null) {',
    '    var sql = "SELECT * FROM T WHERE a = " + x;',
    '  }',
    '  cmd.CommandText = sql;',
    '}',
  ].join('\n'))).toEqual([])
})

test('CS-SQL: Parameter @name, FromSql/ExecuteSql/SqlQuery mit $"...", feste Teile, kein SQL, Text, Kommentar und Markierung bleiben still', () => {
  expect(art('cmd.CommandText = "SELECT * FROM Kunden WHERE Name = @name";')).toEqual([])
  expect(art('var c = new SqlCommand("SELECT * FROM Kunden WHERE Id = @id", con);\nc.Parameters.AddWithValue("@id", id);')).toEqual([])
  expect(art('var k = ctx.Kunden.FromSql($"SELECT * FROM Kunden WHERE Ort = {ort}").ToList();')).toEqual([])
  expect(art('db.Database.ExecuteSql($"DELETE FROM Log WHERE Tag < {tag}");')).toEqual([])
  expect(art('await db.Database.ExecuteSqlAsync($"DELETE FROM Log WHERE Tag < {tag}");')).toEqual([])
  expect(art('var n = db.Database.SqlQuery<int>($"SELECT Id FROM Kunden WHERE Name = {name}");')).toEqual([])
  expect(art('var k = ctx.Kunden.FromSqlInterpolated($"SELECT * FROM Kunden WHERE Ort = {ort}");')).toEqual([])
  expect(art('db.Database.ExecuteSqlRaw("DELETE FROM Log WHERE Tag < @tag", new SqlParameter("@tag", tag));')).toEqual([])
  // nur feste Teile: Konstante, nameof, Variable mit festem Text, {{ als Zeichen
  expect(art('const string Tabelle = "Kunden";\ncmd.CommandText = "SELECT * FROM " + Tabelle + " WHERE Id = @id";')).toEqual([])
  expect(art('const string Tabelle = "Kunden";\ncmd.CommandText = $"SELECT {nameof(Kunde.Name)} FROM {Tabelle} WHERE Id = @id";')).toEqual([])
  expect(art('var sql = "SELECT * FROM Kunden";\nsql += " WHERE Id = @id";\ncmd.CommandText = sql;')).toEqual([])
  expect(art('cmd.CommandText = $"SELECT * FROM T WHERE j = \'{{}}\'";')).toEqual([])
  expect(art('cmd.CommandText = "SELECT * FROM T" + (nurAktive ? " WHERE Aktiv = 1" : "");')).toEqual([])
  // kein SQL, nicht zusammengesetzt, kein Code
  expect(art('cmd.CommandText = "Hallo " + name;')).toEqual([])
  expect(art('void Ausfuehren(string abfrage) {\n  cmd.CommandText = abfrage;\n}')).toEqual([])
  expect(art('// cmd.CommandText = "SELECT * FROM T WHERE a = " + a;')).toEqual([])
  expect(art('/* new SqlCommand("SELECT * FROM T WHERE a = " + a) */')).toEqual([])
  expect(art('var hilfe = "cmd.CommandText = \\"SELECT * FROM T WHERE a = \\" + a;";')).toEqual([])
  expect(art('if (cmd.CommandText == "SELECT * FROM T" + x) { }')).toEqual([])
  expect(art('cmd.CommandText = "SELECT * FROM T WHERE a = " + a; // code-waechter:ok SICHERHEIT a ist eine Zahl')).toEqual([])
})

test('CS-RECHTE: Schreib- oder Vollzugriff für Jeder, Benutzer oder Authentifizierte Benutzer mit Allow ist ein Fehler', () => {
  expect(art('var r = new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, AccessControlType.Allow);')).toEqual(['CS-RECHTE!@1'])
  expect(art('ds.AddAccessRule(new FileSystemAccessRule("Jeder", FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));')).toEqual(['CS-RECHTE!@1'])
  expect(art('var r = new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Write, AccessControlType.Allow);')).toEqual(['CS-RECHTE!@1'])
  expect(art('var r = new FileSystemAccessRule(@"VORDEFINIERT\\Benutzer", FileSystemRights.Modify, AccessControlType.Allow);')).toEqual(['CS-RECHTE!@1'])
  expect(art('var r = new System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\\\\Authenticated Users", FileSystemRights.FullControl | FileSystemRights.Synchronize, AccessControlType.Allow);')).toEqual(['CS-RECHTE!@1'])
  expect(art('var jeder = new SecurityIdentifier(WellKnownSidType.WorldSid, null);\nfs.AddAccessRule(new FileSystemAccessRule(jeder, FileSystemRights.FullControl, AccessControlType.Allow));')).toEqual(['CS-RECHTE!@2'])
  expect(art('var regel = ds.AccessRuleFactory(new NTAccount("Jeder"), (int)FileSystemRights.FullControl, false, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);')).toEqual(['CS-RECHTE!@1'])
})

test('CS-RECHTE: Deny, nur Lesen, eigenes Konto, Administratoren, ähnliche Namen, Text, Kommentar und Markierung bleiben still', () => {
  expect(art('new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, AccessControlType.Deny);')).toEqual([])
  expect(art('new FileSystemAccessRule("Everyone", FileSystemRights.ReadAndExecute, AccessControlType.Allow);')).toEqual([])
  expect(art('new FileSystemAccessRule("Jeder", FileSystemRights.Read, AccessControlType.Allow);')).toEqual([])
  expect(art('new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow);')).toEqual([])
  expect(art('new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow);')).toEqual([])
  expect(art('new FileSystemAccessRule("Benutzer1", FileSystemRights.FullControl, AccessControlType.Allow);')).toEqual([])
  expect(art('// new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, AccessControlType.Allow);')).toEqual([])
  expect(art('var s = "new FileSystemAccessRule(\\"Everyone\\", FileSystemRights.FullControl, AccessControlType.Allow)";')).toEqual([])
  expect(art('new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, AccessControlType.Allow); // code-waechter:ok SICHERHEIT Austauschordner')).toEqual([])
})

test('CS-WEBVIEW: ExecuteScriptAsync mit zusammengesetztem Text ist ein Fehler, DevTools und Host-Objekte sind Hinweise', () => {
  expect(art('await webView.CoreWebView2.ExecuteScriptAsync("zeige(\'" + text + "\')");')).toEqual(['CS-WEBVIEW!@1'])
  expect(art('await web.ExecuteScriptAsync($"setze({wert})");')).toEqual(['CS-WEBVIEW!@1'])
  expect(art('var s = string.Format("setze({0})", wert);\nawait web.ExecuteScriptAsync(s);')).toEqual(['CS-WEBVIEW!@2'])
  expect(art('web.CoreWebView2.Settings.AreDevToolsEnabled = true;')).toEqual(['CS-WEBVIEW@1'])
  expect(art('einstellungen.AreHostObjectsAllowed = true;')).toEqual(['CS-WEBVIEW@1'])
  expect(art('web.CoreWebView2.AddHostObjectToScript("bruecke", new Bruecke());')).toEqual(['CS-WEBVIEW@1'])
})

test('CS-WEBVIEW: fester Text, Konstante, Parameter, false, Text und Kommentar bleiben still', () => {
  expect(art('await web.ExecuteScriptAsync("document.title");')).toEqual([])
  expect(art('const string Skript = "init()";\nawait web.ExecuteScriptAsync(Skript + ";");')).toEqual([])
  expect(art('const int Breite = 300;\nawait web.ExecuteScriptAsync($"setze({Breite})");')).toEqual([])
  expect(art('async Task Los(string skript) {\n  await web.ExecuteScriptAsync(skript);\n}')).toEqual([])
  expect(art('web.CoreWebView2.Settings.AreDevToolsEnabled = false;')).toEqual([])
  expect(art('s.AreDevToolsEnabled = istEntwicklung;')).toEqual([])
  expect(art('// web.ExecuteScriptAsync("f(" + x + ")"); AreDevToolsEnabled = true')).toEqual([])
  expect(art('var t = "AddHostObjectToScript(x)";')).toEqual([])
})

test('CS-DLL: eine DLL nur über ihren Namen geladen ist ein Hinweis', () => {
  expect(art('var h = LoadLibrary("hilfe.dll");')).toEqual(['CS-DLL@1'])
  expect(art('var h = NativeMethods.LoadLibraryW("hilfe.dll");')).toEqual(['CS-DLL@1'])
  expect(art('var h = LoadLibraryEx("hilfe.dll", IntPtr.Zero, 0);')).toEqual(['CS-DLL@1'])
  expect(art('var h = NativeLibrary.Load("sqlite3");')).toEqual(['CS-DLL@1'])
  expect(art('NativeLibrary.TryLoad(@"lib\\x.dll", out var h);')).toEqual(['CS-DLL@1'])
  expect(art('var name = "hilfe.dll";\nvar h = LoadLibrary(name);')).toEqual(['CS-DLL@2'])
})

test('CS-DLL: voller Pfad, Path.Combine, LOAD_LIBRARY_SEARCH, die Erklärung der Funktion, ähnliche Namen und Text bleiben still', () => {
  expect(art('var h = LoadLibrary(@"C:\\Programme\\Baere\\hilfe.dll");')).toEqual([])
  expect(art('var h = LoadLibrary("\\\\\\\\server\\\\freigabe\\\\hilfe.dll");')).toEqual([])
  expect(art('var h = LoadLibrary(Path.Combine(AppContext.BaseDirectory, "hilfe.dll"));')).toEqual([])
  expect(art('var h = LoadLibraryEx("hilfe.dll", IntPtr.Zero, LOAD_LIBRARY_SEARCH_SYSTEM32);')).toEqual([])
  expect(art('[DllImport("kernel32", CharSet = CharSet.Unicode)]\nstatic extern IntPtr LoadLibrary(string lpFileName);')).toEqual([])
  expect(art('void Laden(string pfad) { var h = LoadLibrary(pfad); }')).toEqual([])
  expect(art('var h = MeinLoadLibrary("hilfe.dll");')).toEqual([])
  expect(art('var s = "LoadLibrary(\\"hilfe.dll\\")";')).toEqual([])
})

test('CS-TEMPDATEI: Path.GetTempFileName ist ein Hinweis, GetTempPath, GetRandomFileName, Text und Kommentar nicht', () => {
  expect(art('var p = Path.GetTempFileName();')).toEqual(['CS-TEMPDATEI@1'])
  expect(art('var p = System.IO.Path.GetTempFileName();', 'D:\\p\\Kasse.Tests\\T.cs')).toEqual(['CS-TEMPDATEI@1'])
  expect(art('var p = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());')).toEqual([])
  expect(art('// Path.GetTempFileName() nicht mehr')).toEqual([])
  expect(art('var s = "Path.GetTempFileName()";')).toEqual([])
})

test('CS-REGEX: Suchmuster aus einer Variable oder zusammengesetzt ist ein Hinweis', () => {
  expect(art('bool Passt(string text, string muster) => Regex.IsMatch(text, muster);')).toEqual(['CS-REGEX@1'])
  expect(art('void F(string m) { var r = new Regex(m, RegexOptions.IgnoreCase); }')).toEqual(['CS-REGEX@1'])
  expect(art('var s = Regex.Replace(text, "^" + vorne, "");')).toEqual(['CS-REGEX@1'])
  expect(art('var teile = Regex.Split(zeile, trenner);')).toEqual(['CS-REGEX@1'])
  expect(art('var ms = Regex.Matches(text, $"{wort}+");')).toEqual(['CS-REGEX@1'])
  expect(art('var m = System.Text.RegularExpressions.Regex.Match(text, eingabe.Text);')).toEqual(['CS-REGEX@1'])
  expect(art('var ok = Regex.IsMatch(s, kurz ? muster : "^x$");')).toEqual(['CS-REGEX@1'])
  expect(art('var ok = Regex.IsMatch(s, "(?:" + string.Join("|", namen) + ")");')).toEqual(['CS-REGEX@1'])
})

test('CS-REGEX: fester Text, Konstante, Regex.Escape, Muster-Objekt und Text bleiben still', () => {
  expect(art('var r = new Regex("^[0-9]+$");')).toEqual([])
  expect(art('var r = new Regex(@"\\d+", RegexOptions.Compiled);')).toEqual([])
  expect(art('const string Muster = @"^\\w+$";\nvar ok = Regex.IsMatch(text, Muster);')).toEqual([])
  expect(art('static readonly string Muster = "^[a-z]+$";\nvar ok = Regex.IsMatch(text, Muster);')).toEqual([])
  expect(art('var m = "^[a-z]+$";\nvar ok = Regex.IsMatch(text, m);')).toEqual([])
  expect(art('var ok = Regex.IsMatch(text, Regex.Escape(wort));')).toEqual([])
  expect(art('var ok = Regex.IsMatch(text, "^" + Regex.Escape(wort) + "$");')).toEqual([])
  expect(art('var ok = Regex.IsMatch(text, "^" + Regex.Escape(w) + (w.Length <= 3 ? "$" : ""));')).toEqual([])
  expect(art('var s = Regex.Replace(t, "(?:" + string.Join("|", namen.Select(Regex.Escape)) + ")", "");')).toEqual([])
  expect(art('var s = Regex.Replace(t, "(?:" + string.Join("|", namen.Select(n => Regex.Escape(n))) + ")", "");')).toEqual([])
  expect(art('var ok = meinRegex.IsMatch(eingabe);')).toEqual([])
  expect(art('var x = "Regex.IsMatch(text, muster)";')).toEqual([])
})

test('C#-Zusatzmuster: Prüfdateien bekommen nur Hinweise; Spalte ab 1, ein Fund je Regel und Zeile', () => {
  const sql = 'cmd.CommandText = "SELECT * FROM T WHERE a = " + a;'
  expect(art(sql, 'D:\\p\\Kasse.Tests\\DatenTest.cs')).toEqual(['CS-SQL@1'])
  expect(art(sql, 'D:\\p\\Tests\\Programm.cs')).toEqual(['CS-SQL@1'])
  expect(art('new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, AccessControlType.Allow);', 'D:\\p\\App.Probe\\Rechte.cs')).toEqual(['CS-RECHTE@1'])
  expect(art('await w.ExecuteScriptAsync("f(" + x + ")");', 'D:\\p\\Pruefung\\Web.cs')).toEqual(['CS-WEBVIEW@1'])
  expect(csZusatzMuster('', 'D:\\p\\Leer.cs')).toEqual([])
  const f = csZusatzMuster('  x.CommandText = "SELECT a FROM b WHERE c = " + c;', D)
  expect(f.map(x => [x.line, x.col, x.code])).toEqual([[1, 5, 'CS-SQL']])
  expect(f[0]?.text ?? '').toContain('Parameter')
  expect(art('var c = new SqlCommand("SELECT * FROM T WHERE a = " + a, con) { CommandText = "SELECT * FROM T WHERE b = " + b };')).toEqual(['CS-SQL!@1'])
})
