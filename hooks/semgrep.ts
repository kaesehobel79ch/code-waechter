// Datenfluss mit eigenen Semgrep-Regeln (Bauplan "höchstes Niveau" Stufe 2 Punkt 10, 27.11.2026 "Alle drei Stufen"): Text aus
// einer Quelle (Netz, Befehlszeile, Konsole, Datei) erreicht ein Ziel (SQL, Programmstart, Code, Pfad, Deserialisierung, Protokoll).
// Semgrep (https://semgrep.dev, LGPL-2.1) läuft lokal, ohne Konto, mit --metrics=off und nur mit den Regeln unten.
//
// GRENZE (Semgrep-Doku, docs/writing-rules/data-flow/taint-mode/overview, gelesen 28.11.2026): "Interprocedural taint analysis is a
// Semgrep Pro feature." und "Taint propagators only work intraprocedurally". Ohne Konto verfolgt Semgrep einen Wert also nur INNERHALB
// einer Funktion: gibt eine Funktion den Text an eine andere weiter, sieht diese Prüfung den Weg nicht. Pro (--pro, --pro-intrafile,
// semgrep login) kommt nicht in Frage (Konto, Cloud).
//
// Gemessen 28.11.2026 mit Semgrep 1.186.0 (pipx, Python 3.14.7):
//   Ein Lauf über die Kopie einer Datei im Arbeitsordner (alle 33 Regeln, --jobs=1): 2,7 bis 3,0 s bei 3 bis 70 KB, 5,8 s bei 388 KB
//   (register.tsx); elf Projekte eines Entwicklers (385 Dateien) je ein Aufruf: zusammen 59 s, das grösste 14,7 s.
//   Rückgabe 0 mit und ohne Funde und bei Syntaxfehlern der Datei (die stehen unter "errors" mit "path"); 2 bei einem Pfad, den es
//   nicht gibt ("Invalid scanning root", dann ist gar nichts geprüft); 7 bei einer kaputten oder fehlenden Regeldatei.
//   "paths.scanned" nennt jede ausgewertete Datei. .pyw, .mts und .cts kennt Semgrep nicht (fehlen dort still) - sie laufen in einem
//   eigenen Aufruf mit --scan-unknown-extensions und nur den Regeln ihrer Sprache (sonst würde z. B. .pyw auch als C# gelesen).
//   Ausdrücklich genannte Dateien prüft Semgrep auch unter tests\, node_modules\, *.min.* und in .gitignore (gemessen).
//   Die Quelltextzeile zeigt Semgrep ohne Anmeldung nicht ("requires login"); der Wächter braucht sie nicht. Eine Syntax-Meldung
//   enthält dagegen Text der Datei - der kommt nie in die Meldung, nur Art und Zeile.
//   Python: ein Ausschnitt x[1:] verliert in Semgrep die Markierung (gemessen: open(sys.argv[1][2:]) blieb still). Für die Quellen
//   selbst stehen die Ausschnitte darum in den Regeln (sys.argv[1:], self.path[1:]); ein Ausschnitt einer Zwischenvariable bleibt eine
//   Grenze. "# nosemgrep" bzw. "// nosemgrep" in der Zeile beachtet Semgrep selbst (gemessen), "code-waechter:ok SICHERHEIT" der Wächter.
//
// Einstufung: eine Quelle aus dem Netz (Web-Anfrage, Socket, Antwort eines Abrufs) ist ein Fehler, nur beim Protokoll ein Hinweis.
// Befehlszeile, Konsole und Dateiinhalt sind Hinweise (bei eigenen Werkzeugen gewollt, wie PY-PFAD in sicherheit.ts). In Prüfdateien
// (PRUEF_PFAD) ist alles ein Hinweis. Steht derselbe Fund aus Netz und lokal in einer Zeile, gilt der aus dem Netz.

import { t } from './i18n'
import { GITLEAKS_VORHER, OK_SICHER, PRUEF_PFAD, daten, rein } from './sicherheit'
import type { Ergebnis, SFund, Umgebung } from './sicherheit'

export const SEMGREP_BEFEHL = 'py -3.14 -m pipx install semgrep'
// Zeitgrenze je Aufruf beim Schreiben einer Datei (gemessen 28.11.2026: 2,7 bis 5,9 s je Lauf).
export const SEMGREP_MS = 120000
export const SEMGREP_DATEI = /\.(?:pyw?|cs|[cm]?js|jsx|[cm]?ts|tsx)$/i
// Windows erlaubt höchstens 32'767 Zeichen je Befehlszeile; die Dateien eines Aufrufs bleiben darunter (Rest für Programm und Schalter).
export const BEFEHLSZEILE_MAX = 30000

export type Ziel = 'SQL' | 'PROGRAMM' | 'CODE' | 'PFAD' | 'DESER' | 'PROTOKOLL'
export type Herkunft = 'NETZ' | 'LOKAL'
type Sprache = 'PY' | 'CS' | 'JS'
type Muster = Record<string, unknown>

export const ZIELE: Ziel[] = ['SQL', 'PROGRAMM', 'CODE', 'PFAD', 'DESER', 'PROTOKOLL']
const SPRACHEN: Record<Sprache, string[]> = { PY: ['python'], CS: ['csharp'], JS: ['javascript', 'typescript'] }

// ---- Bausteine der Regeln (Semgrep-Syntax: pattern, pattern-either, pattern-inside, metavariable-regex, focus-metavariable)
const p = (pattern: string): Muster => ({ pattern })
const re = (metavariable: string, regex: string): Muster => ({ 'metavariable-regex': { metavariable, regex } })
const eins = (muster: string[]): Muster => (muster.length === 1 ? p(muster[0] ?? '') : { 'pattern-either': muster.map(p) })
const rahmen = (r: string[]): Muster => (r.length === 1 ? { 'pattern-inside': r[0] } : { 'pattern-either': r.map(x => ({ 'pattern-inside': x })) })
// Muster mit Bedingungen; Quelle bzw. Ziel ist der ganze Treffer.
const mit = (muster: string[], extra: Muster[] = []): Muster => (extra.length === 0 && muster.length === 1 ? p(muster[0] ?? '') : { patterns: [eins(muster), ...extra] })
// Ziel ist nur der Teil $X (SQL: nur das Abfrage-Argument, Parameter daneben bleiben sicher).
const fokus = (muster: string[], extra: Muster[] = [], mv = '$X'): Muster => ({ patterns: [eins(muster), ...extra, { 'focus-metavariable': mv }] })
// Muster innerhalb eines Rahmens (Funktion, Klasse, Import)
const innen = (r: string[], muster: string[], extra: Muster[] = [], mv?: string): Muster =>
  ({ patterns: [rahmen(r), eins(muster), ...extra, ...(mv ? [{ 'focus-metavariable': mv }] : [])] })
// Quelle, die eine Funktion durch ihr Argument füllt (socket.Receive(puffer))
const seite = (muster: string[], extra: Muster[] = [], mv = '$B'): Muster => ({ 'by-side-effect': true, patterns: [eins(muster), ...extra, { 'focus-metavariable': mv }] })
// Python: Ausschnitte der Quelle selbst (siehe Kopf)
const scheiben = (e: string): string[] => [e, `${e}[$A:]`, `${e}[:$B]`, `${e}[$A:$B]`]

const ZAHL_PY = ['int(...)', 'float(...)']
const ZAHL_CS = [mit(['$T.Parse(...)'], [re('$T', '^(int|long|short|byte|sbyte|uint|ulong|ushort|double|float|decimal|Int16|Int32|Int64|UInt16|UInt32|UInt64|Double|Single|Decimal|Guid)$')]),
  mit(['Convert.$M(...)'], [re('$M', '^To(Int16|Int32|Int64|UInt16|UInt32|UInt64|Double|Single|Decimal|Byte|Boolean)$')])]
const ZAHL_JS = ['Number(...)', 'parseInt(...)', 'parseFloat(...)']
// Shell als Programm (cmd /c, powershell -Command, bash -c, .bat/.cmd): jedes weitere Argument ist Befehlstext. Der Text eines festen
// Programmnamens steht mit Anführungszeichen in $CMD (gemessen 28.11.2026: "cmd", r"C:\...\cmd.exe", 'tool.bat').
const SHELL = '([^"\'`]*[\\\\/])?(cmd|cmd\\.exe|powershell|powershell\\.exe|pwsh|pwsh\\.exe|bash|bash\\.exe|sh|zsh|wsl|wsl\\.exe|[^"\'`]*\\.(bat|cmd))'
const SHELL_PY = `(?i)^[rbuf]*["']${SHELL}["']$`
const SHELL_JS = `(?i)^["'\`]${SHELL}["'\`]$`
// Prüfung gegen einen festen Ordner (Schlussprüfung 28.11.2026, Befund 4): basename, Path(...).name, Path.GetFileName und
// encodeURIComponent lassen ".." und "." durch (gemessen; aus "abc/" macht os.path.basename sogar ""), Path.Combine(basis, "..")
// zeigt dann über den Ordner. Bereinigt ist ein Pfad erst, wenn sein VOLLER Pfad (realpath, Path.GetFullPath, path.resolve) mit
// startswith geprüft ist; ab dieser Prüfung gilt die Variable als sauber (by-side-effect). startswith ohne vollen Pfad zählt nicht
// ("basis/.." beginnt mit "basis"). Grenzen: ob die Prüfung den Zweig wirklich sperrt, sieht die Regel nicht; geprüft sein muss eine
// Variable (gemessen: in os.path.realpath(os.path.join(basis, n)).startswith(...) wird n nicht bereinigt, zwei Aufrufe tief wirkt
// by-side-effect nicht; dann bleibt der Fund). Gemessen 28.11.2026: Bereiche "if (...) { ... }" bzw. "...\nif ..." liefen auf
// einem grossen Prüfprogramm (1,4 MB, 16'781 Zeilen ohne Main) in die Zeitgrenze von Semgrep (Timeout FLUSS-CS-PFAD-NETZ und -LOKAL, die
// Datei wäre für Pfade ungeprüft); diese Form nicht (10,8 s für alle Regeln wie vorher 10,6 s).
const pruefung = (zuweisung: string[], pruefen: string[], extra: Muster[] = []): Muster =>
  ({ 'by-side-effect': true, patterns: [...(zuweisung.length > 0 ? [rahmen(zuweisung)] : []), eins(pruefen), ...extra, { 'focus-metavariable': '$P' }] })

// ======================================================================================== Python
const PY_WEB_FLASK = '^(args|form|values|json|files|cookies|headers|data|stream|path|full_path|url|base_url|view_args|get_json|get_data)$'
const PY_WEB_DJANGO = '^(GET|POST|COOKIES|FILES|META|body|headers|data|query_params|path|path_info)$'
const PY_ABRUF = '^(get|post|put|patch|delete|head|options|request|stream)$'
const PY_QUELLEN: Record<Herkunft, Muster[]> = {
  NETZ: [
    // Flask (from flask import request) und Django/Django REST (request bzw. self.request in einer Ansicht)
    mit([...scheiben('flask.request.$P'), 'flask.request.$P(...)'], [re('$P', PY_WEB_FLASK)]),
    mit(scheiben('$R.$P'), [re('$R', '^(self\\.)?request$'), re('$P', PY_WEB_DJANGO)]),
    // http.server (BaseHTTPRequestHandler): Pfad, Kopfzeilen und Inhalt der Anfrage
    innen(['class $C(..., $K, ...):\n    ...'], [...scheiben('self.path'), 'self.headers', 'self.rfile'], [re('$K', '(BaseHTTPRequestHandler|SimpleHTTPRequestHandler)$')]),
    // Sockets
    mit(['$S.recv(...)', '$S.recvfrom(...)', '$S.recvmsg(...)']),
    seite(['$S.recv_into($B, ...)', '$S.recvfrom_into($B, ...)']),
    // Antworten von Abrufen
    mit(['requests.$M(...)', 'httpx.$M(...)'], [re('$M', PY_ABRUF)]),
    p('urllib.request.urlopen(...)'),
    innen(['$S = requests.Session(...)\n...', 'with requests.Session(...) as $S:\n    ...', '$S = httpx.Client(...)\n...', 'with httpx.Client(...) as $S:\n    ...'],
      ['$S.$M(...)'], [re('$M', PY_ABRUF)]),
  ],
  LOKAL: [
    // Befehlszeile (auch argparse), Konsole, Dateiinhalt
    mit([...scheiben('sys.argv'), 'sys.argv[$I][$A:]', '$P.parse_args(...)', '$P.parse_known_args(...)']),
    mit(['input(...)', 'sys.stdin']),
    mit(['open(...)', 'io.open(...)', 'codecs.open(...)', '$P.read_text(...)', '$P.read_bytes(...)']),
  ],
}
const PY_SUBPROCESS = '^(run|call|check_call|check_output|Popen)$'
const PY_ZIELE: Record<Ziel, Muster[]> = {
  SQL: [fokus(['$C.execute($X, ...)', '$C.executemany($X, ...)', '$C.executescript($X, ...)', '$C.exec_driver_sql($X, ...)',
    'sqlalchemy.text($X, ...)', 'pandas.read_sql($X, ...)', 'pandas.read_sql_query($X, ...)'])],
  PROGRAMM: [
    fokus(['os.system($X)', 'os.popen($X, ...)', 'subprocess.getoutput($X, ...)', 'subprocess.getstatusoutput($X, ...)',
      'asyncio.create_subprocess_shell($X, ...)', 'asyncio.create_subprocess_exec($X, ...)', 'os.startfile($X, ...)']),
    fokus(['subprocess.$F($X, ..., shell=True, ...)', 'subprocess.$F([$X, ...], ...)'], [re('$F', PY_SUBPROCESS)]),
    // Befehl als Text auch ohne shell=True (Schlussprüfung Befund 2): Windows zerlegt den Text selbst, der Absender wählt Programm und
    // Argumente. Eine Liste (auch in einer Variablen, die mit [...] beginnt) ist das sichere Gegenstück und kein Ziel.
    fokus(['subprocess.$F($X, ...)'], [re('$F', PY_SUBPROCESS), { 'pattern-not': 'subprocess.$F([...], ...)' }, { 'pattern-not-inside': '$X = [...]\n...' }]),
    // Shell als Programm (["cmd", "/c", text], create_subprocess_exec("cmd", "/c", text)): jedes weitere Element
    fokus(['subprocess.$F([$CMD, ..., $X, ...], ...)'], [re('$F', PY_SUBPROCESS), re('$CMD', SHELL_PY)]),
    fokus(['asyncio.create_subprocess_exec($CMD, ..., $X, ...)'], [re('$CMD', SHELL_PY)]),
    fokus(['os.$F($X, ...)'], [re('$F', '^(execl|execle|execlp|execlpe|execv|execve|execvp|execvpe)$')]),
    fokus(['os.$F($MODUS, $X, ...)'], [re('$F', '^(spawnl|spawnle|spawnlp|spawnlpe|spawnv|spawnve|spawnvp|spawnvpe)$')]),
  ],
  CODE: [fokus(['eval($X, ...)', 'exec($X, ...)', 'importlib.import_module($X, ...)', '__import__($X, ...)'])], // code-waechter:ok SEC-EVAL (Muster für Semgrep)
  PFAD: [
    fokus(['open($X, ...)', 'io.open($X, ...)', 'codecs.open($X, ...)', 'flask.send_file($X, ...)', 'tarfile.open($X, ...)',
      'shutil.unpack_archive($X, ...)']),
    // ZipFile über einem Speicher-Objekt öffnet keinen Pfad (Schlussprüfung Befund 5: zipfile.ZipFile(io.BytesIO(r.content)) beim Laden
    // eines Updates). Kein Bereiniger: die Namen IM Archiv bleiben markiert, open(os.path.join(ziel, name)) ist weiter ein Fund (Zip-Slip).
    fokus(['zipfile.ZipFile($X, ...)'], [{ 'pattern-not': 'zipfile.ZipFile(io.BytesIO(...), ...)' }, { 'pattern-not-inside': '$X = io.BytesIO(...)\n...' }]),
    fokus(['os.$F($X, ...)'], [re('$F', '^(remove|unlink|rmdir|removedirs|rename|renames|replace|mkdir|makedirs|listdir|scandir|walk|chmod|truncate)$')]),
    fokus(['os.$F($A, $X, ...)'], [re('$F', '^(rename|renames|replace|link|symlink)$')]),
    fokus(['shutil.$F($X, ...)'], [re('$F', '^(rmtree|copy|copy2|copyfile|copytree|move)$')]),
    fokus(['shutil.$F($A, $X, ...)'], [re('$F', '^(copy|copy2|copyfile|copytree|move)$')]),
    // pathlib: Path(x).read_text() bzw. p = Path(x); p.unlink(). Ohne replace: das hat auch jeder Text (gemessen 28.11.2026: 9 falsche
    // Hinweise wie f.read().replace("\r\n", "\n") in eigenen Werkzeugen); os.replace bleibt oben. Bei jedem Empfänger nur Namen, die
    // allein pathlib hat; open, rename, replace, rmdir, mkdir und glob haben auch ZipFile, DataFrame und Text (Schlussprüfung Befund 5:
    // z.open("manifest.json"), df.rename(columns=...)) - sie zählen nur an einem pathlib-Pfad.
    fokus(['$X.$M(...)'], [re('$M', '^(read_text|write_text|read_bytes|write_bytes|unlink|touch|iterdir|rglob)$')]),
    { patterns: [{ 'pattern-either': [
      { patterns: [p('$X.$M(...)'), { 'metavariable-pattern': { metavariable: '$X', 'pattern-either': ['pathlib.Path(...)', 'pathlib.PurePath(...)', '$A / $B'].map(p) } }] },
      { patterns: [rahmen(['$X = pathlib.Path(...)\n...', '$X = $A / $B\n...']), p('$X.$M(...)')] }] },
    re('$M', '^(open|rename|replace|rmdir|mkdir|glob|symlink_to|hardlink_to)$'), { 'focus-metavariable': '$X' }] },
  ],
  DESER: [
    fokus(['pickle.$F($X, ...)', 'dill.$F($X, ...)', 'marshal.$F($X, ...)'], [re('$F', '^(load|loads|Unpickler)$')]),
    fokus(['jsonpickle.decode($X, ...)', 'pandas.read_pickle($X, ...)', 'shelve.open($X, ...)', 'yaml.unsafe_load($X, ...)', 'yaml.unsafe_load_all($X, ...)']),
    // yaml.load ohne sicheren Leser (SafeLoader, CSafeLoader, BaseLoader)
    { patterns: [eins(['yaml.load($X, ...)', 'yaml.load_all($X, ...)']),
      ...['SafeLoader', 'CSafeLoader', 'BaseLoader'].flatMap(l => [
        { 'pattern-not': `yaml.load($X, Loader=yaml.${l})` }, { 'pattern-not': `yaml.load($X, yaml.${l})` },
        { 'pattern-not': `yaml.load_all($X, Loader=yaml.${l})` }, { 'pattern-not': `yaml.load_all($X, yaml.${l})` }]),
      { 'focus-metavariable': '$X' }] },
  ],
  PROTOKOLL: [
    mit(['logging.$M(...)'], [re('$M', '^(debug|info|warning|warn|error|critical|exception|log)$')]),
    mit(['$L.$M(...)'], [re('$L', '(?i)^(self\\.)?_*(log|logger|logging)$'), re('$M', '^(debug|info|warning|warn|error|critical|exception|log)$')]),
  ],
}
// Voller Pfad in Python: os.path.realpath/abspath/normpath und pathlib resolve() mit is_relative_to.
const PY_VOLL = re('$N', '^(realpath|abspath|normpath)$')
const PY_PRUEFUNG: Muster[] = [
  pruefung(['$P = os.path.$N(...)\n...'], ['$P.startswith(...)'], [PY_VOLL]),
  pruefung([], ['os.path.$N($P).startswith(...)'], [PY_VOLL]),
  pruefung(['$P = $Q.resolve(...)\n...'], ['$P.is_relative_to(...)']),
  pruefung([], ['$P.resolve(...).is_relative_to(...)']),
]
const PY_REINIGER: Record<Ziel, Muster[]> = {
  SQL: ZAHL_PY.map(p),
  // Kein shlex.quote (Schlussprüfung Befund 1, Python-Doku shlex: "only designed for Unix shells", quote() auf Windows nicht korrekt):
  // cmd.exe beachtet die Einfachanführungszeichen nicht ("x & calc" startet calc), und als Programm selbst schützt es nie.
  PROGRAMM: ZAHL_PY.map(p),
  CODE: ZAHL_PY.map(p),
  // secure_filename entfernt ".." und Trenner; basename und Path(...).name nicht (siehe PY_PRUEFUNG).
  PFAD: [...[...ZAHL_PY, 'werkzeug.utils.secure_filename(...)'].map(p), ...PY_PRUEFUNG],
  DESER: [],
  // Zeilenumbrüche: nur \r UND \n zusammen (Schlussprüfung Befund 8: ein einzelnes replace lässt das andere durch).
  PROTOKOLL: [...ZAHL_PY, 'repr(...)', '$X.replace("\\r", ...).replace("\\n", ...)', '$X.replace("\\n", ...).replace("\\r", ...)'].map(p),
}

// ======================================================================================== C#
const CS_ANFRAGE = '^(Query|QueryString|Form|Headers|Cookies|Body|BodyReader|RouteValues|Path|PathBase|Params|Url|RawUrl|InputStream|Files|ServerVariables|UserAgent|UrlReferrer)$'
const CS_ABRUF = '^(GetStringAsync|GetByteArrayAsync|GetStreamAsync|ReadAsStringAsync|ReadAsByteArrayAsync|ReadAsStreamAsync|DownloadString|DownloadData|DownloadStringTaskAsync|DownloadDataTaskAsync|UploadString|UploadData|UploadValues)$'
const CS_QUELLEN: Record<Herkunft, Muster[]> = {
  NETZ: [
    // ASP.NET (Request.Query ...) und HttpListener (context.Request.QueryString, .Url, .InputStream)
    mit(['Request.$P', '$C.Request.$P'], [re('$P', CS_ANFRAGE)]),
    // Die Anfrage in einer Variablen (Beispiel der Microsoft-Doku zu HttpListener: HttpListenerRequest request = context.Request;) oder
    // als Parameter (ASP.NET Core: (HttpRequest req) => req.Query[...]); Schlussprüfung Befund 3. "var" passt nicht auf "$T $V" (gemessen).
    innen(['$T $V = $C.Request;\n...', 'var $V = $C.Request;\n...', '$V = $C.Request;\n...', '$R $M(..., HttpRequest $V, ...) { ... }',
      '$R $M(..., HttpListenerRequest $V, ...) { ... }', '(..., HttpRequest $V, ...) => $B'], ['$V.$P'], [re('$P', CS_ANFRAGE)]),
    // Sockets und TCP/UDP
    seite(['$S.Receive($B, ...)', '$S.ReceiveFrom($B, ...)', '$S.ReceiveAsync($B, ...)', '$S.ReceiveFromAsync($B, ...)']),
    mit(['$U.Receive(ref $E)', '$U.ReceiveAsync()', '$T.GetStream()']),
    // Antworten von Abrufen (HttpClient, HttpContent, WebClient)
    mit(['$H.$M(...)'], [re('$M', CS_ABRUF)]),
    mit(['$H.GetFromJsonAsync<$TYP>(...)', '$H.ReadFromJsonAsync<$TYP>(...)', '$H.GetFromJsonAsync(...)', '$H.ReadFromJsonAsync(...)']),
  ],
  LOKAL: [
    // Befehlszeile: Main(string[] args), WPF OnStartup/Startup (StartupEventArgs e: e.Args), Environment
    innen(['$R Main(string[] $A) { ... }'], ['$A']),
    // Programm ohne Main (Vorlage von "dotnet new console", Microsoft-Doku top-level-statements: "args" ohne Deklaration); nicht in einer
    // Methode, Klasse oder einem Lambda mit eigenem "args" (Schlussprüfung Befund 3)
    { patterns: [p('args'), ...['$R $M(...) { ... }', 'class $K { ... }', 'struct $K { ... }', '(..., args, ...) => $B'].map(x => ({ 'pattern-not-inside': x }))] },
    innen(['$R $M(..., StartupEventArgs $E, ...) { ... }'], ['$E.Args']),
    mit(['Environment.GetCommandLineArgs()', 'Environment.CommandLine']),
    // Konsole und Dateiinhalt
    mit(['Console.ReadLine()', 'Console.In.ReadLine()', 'Console.In.ReadToEnd()']),
    mit(['File.$M(...)'], [re('$M', '^(ReadAllText|ReadAllTextAsync|ReadAllLines|ReadAllLinesAsync|ReadAllBytes|ReadAllBytesAsync|ReadLines|ReadLinesAsync|OpenText|OpenRead)$')]),
    p('new StreamReader(...)'),
  ],
}
const CS_SQL_TYP = '^([\\w.]+\\.)?(SqlCommand|SqliteCommand|SQLiteCommand|MySqlCommand|NpgsqlCommand|OleDbCommand|OdbcCommand|OracleCommand|SqlCeCommand|SqlDataAdapter|SQLiteDataAdapter|MySqlDataAdapter|NpgsqlDataAdapter|OleDbDataAdapter|OdbcDataAdapter)$'
const CS_DAPPER = '^(Query|QueryAsync|QueryFirst|QueryFirstAsync|QueryFirstOrDefault|QueryFirstOrDefaultAsync|QuerySingle|QuerySingleAsync|QuerySingleOrDefault|QuerySingleOrDefaultAsync|QueryMultiple|QueryMultipleAsync|Execute|ExecuteAsync|ExecuteScalar|ExecuteScalarAsync|ExecuteReader|ExecuteReaderAsync)$'
const CS_VERBINDUNG = '(?i)^(.*\\.)?_?(db|conn|connection|con|cn|cnn|database|sql)$'
const CS_PSI = ['var $P = new ProcessStartInfo(...);\n...', 'ProcessStartInfo $P = new ProcessStartInfo(...);\n...', 'var $P = new ProcessStartInfo { ... };\n...',
  'ProcessStartInfo $P = new ProcessStartInfo { ... };\n...', '$P = new ProcessStartInfo(...);\n...']
const CS_DATEI = '^(ReadAllText|ReadAllTextAsync|ReadAllLines|ReadAllLinesAsync|ReadAllBytes|ReadAllBytesAsync|ReadLines|ReadLinesAsync|WriteAllText|WriteAllTextAsync|WriteAllLines|WriteAllLinesAsync|WriteAllBytes|WriteAllBytesAsync|AppendAllText|AppendAllTextAsync|AppendAllLines|AppendAllLinesAsync|AppendText|Delete|Copy|Move|Replace|Open|OpenRead|OpenWrite|OpenText|Create|CreateText|SetAttributes|CreateSymbolicLink)$'
const CS_ORDNER = '^(Delete|CreateDirectory|Move|GetFiles|GetDirectories|GetFileSystemEntries|EnumerateFiles|EnumerateDirectories|EnumerateFileSystemEntries|SetCurrentDirectory)$'
// Ströme statt Pfade (StreamReader/StreamWriter): Text, Typen und Quellen eines Stroms (CS_ANFRAGE, $T.GetStream(), CS_ABRUF)
const CS_KEIN_STROM = '(?is)^(?!.*(stream|strom)($|\\W|async)|.*\\.body$|body$).*$'
const CS_STROM_TYP = ['Stream', 'MemoryStream', 'NetworkStream', 'FileStream', 'BufferedStream', 'GZipStream', 'DeflateStream', 'BrotliStream', 'SslStream', 'CryptoStream']
const CS_STROM = ['$C.Request.Body', 'Request.Body', '$C.InputStream', '$T.GetStream()', 'await $H.GetStreamAsync(...)', 'await $H.ReadAsStreamAsync(...)',
  '$H.ReadAsStream(...)', '$H.OpenReadStream(...)', '$H.GetResponseStream()']
const CS_FORMATIERER = '^(BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)$'
const CS_PROTOKOLL = '(?i)^(.*\\.)?_?(log|logger|logwriter|logfile|protokoll)$'
const CS_ZIELE: Record<Ziel, Muster[]> = {
  SQL: [
    fokus(['new $T($X, ...)'], [re('$T', CS_SQL_TYP)]),
    fokus(['$C.CommandText = $X', 'new $T { ..., CommandText = $X, ... }', 'new $T(...) { ..., CommandText = $X, ... }']),
    fokus(['$D.$M($X, ...)'], [re('$M', '^(ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw)$')]),
    fokus(['$D.SqlQueryRaw<$TYP>($X, ...)']),
    // Dapper (Methoden der Verbindung)
    fokus(['$C.$M($X, ...)', '$C.$M<$TYP>($X, ...)'], [re('$C', CS_VERBINDUNG), re('$M', CS_DAPPER)]),
  ],
  PROGRAMM: [
    fokus(['Process.Start($X, ...)', 'Process.Start($A, $X)', 'System.Diagnostics.Process.Start($X, ...)', 'System.Diagnostics.Process.Start($A, $X)',
      'new ProcessStartInfo($X, ...)', 'new ProcessStartInfo($A, $X)', '$P.StartInfo.FileName = $X', '$P.StartInfo.Arguments = $X',
      'new ProcessStartInfo { ..., FileName = $X, ... }', 'new ProcessStartInfo { ..., Arguments = $X, ... }',
      'new ProcessStartInfo(...) { ..., FileName = $X, ... }', 'new ProcessStartInfo(...) { ..., Arguments = $X, ... }']),
    innen(CS_PSI, ['$P.FileName = $X', '$P.Arguments = $X'], [], '$X'),
  ],
  CODE: [
    fokus(['CSharpScript.$M($X, ...)'], [re('$M', '^(EvaluateAsync|RunAsync|Create)$')]),
    fokus(['Assembly.$M($X, ...)'], [re('$M', '^(Load|LoadFrom|LoadFile|UnsafeLoadFrom)$')]),
    fokus(['Type.GetType($X, ...)']),
  ],
  PFAD: [
    fokus(['File.$M($X, ...)'], [re('$M', CS_DATEI)]),
    fokus(['File.$M($A, $X, ...)'], [re('$M', '^(Copy|Move|Replace)$')]),
    fokus(['Directory.$M($X, ...)'], [re('$M', CS_ORDNER)]),
    fokus(['Directory.Move($A, $X)']),
    fokus(['new $T($X, ...)'], [re('$T', '^([\\w.]+\\.)?(FileStream|FileInfo|DirectoryInfo)$')]),
    // StreamReader(string)/StreamWriter(string) öffnen bzw. überschreiben eine Datei (Microsoft-Doku, Konstruktoren; Schlussprüfung
    // Befund 9). Ein Strom ist kein Pfad: new StreamReader(Request.Body), client.GetStream(), await http.GetStreamAsync(...), Variablen
    // vom Typ Stream/MemoryStream ..., ein Name mit stream/strom/body oder eine Variable, die einen solchen Strom bekam (gemessen 28.11.2026).
    fokus(['new $T($X, ...)'], [re('$T', '^([\\w.]+\\.)?(StreamReader|StreamWriter)$'), re('$X', CS_KEIN_STROM),
      ...CS_STROM_TYP.map(s => ({ 'pattern-not': `new $T((${s} $S), ...)` })),
      ...CS_STROM.flatMap(q => [`var $X = ${q};\n...`, `$X = ${q};\n...`]).map(x => ({ 'pattern-not-inside': x }))]),
    fokus(['ZipFile.$M($X, ...)'], [re('$M', '^(ExtractToDirectory|OpenRead|Open|CreateFromDirectory)$')]),
    fokus(['ZipFile.$M($A, $X, ...)'], [re('$M', '^(ExtractToDirectory|CreateFromDirectory)$')]),
    fokus(['$E.ExtractToFile($X, ...)']),
  ],
  DESER: [
    fokus(['new $T(...).Deserialize($X, ...)'], [re('$T', CS_FORMATIERER)]),
    innen(['$T $F = new $T(...);\n...', 'var $F = new $T(...);\n...'], ['$F.Deserialize($X, ...)'], [re('$T', CS_FORMATIERER)], '$X'),
    // Json.NET mit Typnamen aus den Daten (TypeNameHandling ausser None)
    fokus(['JsonConvert.DeserializeObject($X, ..., new JsonSerializerSettings { ..., TypeNameHandling = TypeNameHandling.$V, ... }, ...)',
      'JsonConvert.DeserializeObject<$TYP>($X, ..., new JsonSerializerSettings { ..., TypeNameHandling = TypeNameHandling.$V, ... }, ...)'],
    [re('$V', '^(All|Auto|Objects|Arrays)$')]),
  ],
  PROTOKOLL: [
    mit(['$L.$M(...)'], [re('$M', '^Log(Trace|Debug|Information|Warning|Error|Critical)$')]),
    mit(['Log.$M(...)'], [re('$M', '^(Verbose|Debug|Information|Warning|Error|Fatal|Write)$')]),
    mit(['$L.$M(...)'], [re('$L', CS_PROTOKOLL), re('$M', '^(Trace|Debug|Info|Warn|Error|Fatal|Log|InfoFormat|DebugFormat|WarnFormat|ErrorFormat|FatalFormat|Write|WriteLine)$')]),
    fokus(['File.$M($P, $X, ...)'], [re('$M', '^(AppendAllText|AppendAllTextAsync|AppendAllLines|AppendAllLinesAsync)$'), re('$P', '(?i)(log|protokoll)')]),
  ],
}
// Voller Pfad in C#: Path.GetFullPath, geprüft mit StartsWith ("var" und Typ getrennt, siehe oben).
const CS_PRUEFUNG: Muster[] = [
  pruefung(['var $P = Path.GetFullPath(...);\n...', '$T $P = Path.GetFullPath(...);\n...', '$P = Path.GetFullPath(...);\n...'], ['$P.StartsWith(...)']),
  pruefung([], ['Path.GetFullPath($P).StartsWith(...)']),
]
const CS_REINIGER: Record<Ziel, Muster[]> = {
  SQL: ZAHL_CS,
  PROGRAMM: ZAHL_CS,
  CODE: ZAHL_CS,
  // Path.GetFileName("..") gibt ".." zurück (Microsoft-Doku: ohne Trenner und Wurzel kommt der Pfad unverändert), siehe CS_PRUEFUNG.
  PFAD: [...ZAHL_CS, ...CS_PRUEFUNG],
  DESER: [],
  // \r UND \n (auch als Zeichen '\r'), ReplaceLineEndings nur mit festem Text ohne Zeilenumbruch: ohne Argument setzt es
  // Environment.NewLine ein (Microsoft-Doku), der Umbruch bleibt.
  PROTOKOLL: [...ZAHL_CS, ...['$X.Replace("\\r", ...).Replace("\\n", ...)', '$X.Replace("\\n", ...).Replace("\\r", ...)',
    "$X.Replace('\\r', ...).Replace('\\n', ...)", "$X.Replace('\\n', ...).Replace('\\r', ...)"].map(p),
  mit(['$X.ReplaceLineEndings($R)'], [re('$R', '^("[^"\\\\\\r\\n]*"|(string|String)\\.Empty)$')])],
}

// ======================================================================================== JavaScript/TypeScript (auch Cloudflare-Worker)
const JS_ANFRAGE = '(?i)^(\\w+\\.)?(req|request)$'
const JS_DATEN = '^(query|body|params|headers|cookies|signedCookies|url|originalUrl|path|baseUrl|files|file)$'
const JS_LESEN = '^(get|header|param|json|text|formData|arrayBuffer|blob|query|queries|parseBody)$'
const JS_SOCKET_DATA = '(?i)^(.*\\.)?(socket|sock|conn|connection|client|res|response)$'
// server: Cloudflare-Worker (Doku workers/examples/websockets: const [client, server] = Object.values(webSocketPair);
// server.addEventListener('message', ...)) und Node-UDP (server.on('message', (msg, rinfo) => ...)); Schlussprüfung Befund 7
const JS_SOCKET_MSG = '(?i)^(.*\\.)?(socket|sock|ws|websocket|wss|conn|connection|client|server|window|self)$'
const FSP = ['fs/promises', 'node:fs/promises']
// Voller Pfad in JS: path.resolve, normalize und join (join normalisiert laut Node-Doku, anders als os.path.join und Path.Combine)
const JS_VOLL = re('$N', '^(resolve|normalize|join)$')
// Aufrufe des Moduls fs bzw. fs/promises (import { readFile } from 'fs/promises', import fsp from 'fs/promises', require(...))
const fsAufruf = (methoden: string, argumente: string, alsZiel: boolean): Muster[] => {
  const ende = alsZiel ? [{ 'focus-metavariable': '$X' }] : []
  return [
    { patterns: [eins([`fs.$M(${argumente})`, `fs.promises.$M(${argumente})`]), re('$M', methoden), ...ende] },
    { patterns: [rahmen(FSP.map(m => `import { ..., $M, ... } from '${m}'\n...`)), p(`$M(${argumente})`), re('$M', methoden), ...ende] },
    { patterns: [rahmen(FSP.flatMap(m => [`import $F from '${m}'\n...`, `import * as $F from '${m}'\n...`, `$F = require('${m}')\n...`])),
      p(`$F.$M(${argumente})`), re('$M', methoden), ...ende] },
  ]
}
// Rückruf, dessen erster Wert aus dem Netz kommt: socket.on('data', d => ...), ws.addEventListener('message', e => ...)
const rueckruf = (vorlagen: string[]): string[] => vorlagen.flatMap(v => [v.replace('CB', '($D, ...) => { ... }'), v.replace('CB', 'function ($D, ...) { ... }')])
const JS_QUELLEN: Record<Herkunft, Muster[]> = {
  NETZ: [
    // Express, Hono (c.req), Koa (ctx.request), Worker (request.url, await request.json(), request.headers.get)
    mit(['$REQ.$P'], [re('$REQ', JS_ANFRAGE), re('$P', JS_DATEN)]),
    mit(['$REQ.$M(...)'], [re('$REQ', JS_ANFRAGE), re('$M', JS_LESEN)]),
    // Sockets und WebSockets
    innen(rueckruf(["$S.on('data', CB)"]), ['$D'], [re('$S', JS_SOCKET_DATA)]),
    innen(rueckruf(["$S.on('message', CB)", "$S.addEventListener('message', CB)", '$S.onmessage = CB']), ['$D'], [re('$S', JS_SOCKET_MSG)]),
    // Durable Object im Ruhezustand (Doku durable-objects/best-practices/websockets: async webSocketMessage(ws, message))
    innen(['class $K { ... webSocketMessage($W, $D) { ... } ... }', 'class $K { ... async webSocketMessage($W, $D) { ... } ... }'], ['$D']),
    // Antworten von Abrufen
    mit(['fetch(...)', 'axios(...)']),
    mit(['axios.$M(...)'], [re('$M', '^(get|post|put|patch|delete|head|options|request)$')]),
  ],
  LOKAL: [
    p('process.argv'),
    // Konsole (readline, prompt) und Dateiinhalt
    mit(['$RL.question(...)', 'prompt(...)', 'window.prompt(...)']),
    innen(rueckruf(['$RL.question($Q, CB)']), ['$D']),
    p('fs.readFileSync(...)'),
    ...fsAufruf('^(readFile|readFileSync)$', '...', false),
  ],
}
const JS_FS_PFAD = '^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|createReadStream|createWriteStream|open|openSync|rename|renameSync|copyFile|copyFileSync|cp|cpSync|readdir|readdirSync|opendir|opendirSync|truncate|truncateSync|symlink|symlinkSync|link|linkSync|chmod|chmodSync)$'
const JS_FS_ZWEI = '^(rename|renameSync|copyFile|copyFileSync|cp|cpSync|symlink|symlinkSync|link|linkSync)$'
const JS_DB = '(?i)^(.*\\.)?(db|d1|database|sql|sqlite|sqlite3|conn|connection|pool|client|knex|sequelize|tx|trx|pg|mysql)$'
const JS_ZIELE: Record<Ziel, Muster[]> = {
  SQL: [
    fokus(['$DB.$M($X, ...)'], [re('$DB', JS_DB), re('$M', '^(prepare|exec|query|execute|raw|unsafe)$')]),
    fokus(['$DB.$M($X, ...)'], [re('$DB', '(?i)^(.*\\.)?(db|database|sqlite|sqlite3)$'), re('$M', '^(run|all|get|each)$')]),
    fokus(['$PRISMA.$queryRawUnsafe($X, ...)', '$PRISMA.$executeRawUnsafe($X, ...)']),
  ],
  PROGRAMM: [
    fokus(['child_process.$F($X, ...)'], [re('$F', '^(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)$')]),
    fokus(['child_process.$F($C, $X, {..., shell: true, ...})'], [re('$F', '^(spawn|spawnSync|execFile|execFileSync)$')]),
    // Shell als Programm (spawn('cmd.exe', ['/c', text]), execFile('powershell', ['-Command', text]); Node-Doku: .bat/.cmd laufen über
    // cmd.exe): jedes Element der Liste bzw. die Liste selbst (Schlussprüfung Befund 2)
    fokus(['child_process.$F($CMD, [..., $X, ...], ...)', 'child_process.$F($CMD, $X, ...)'], [re('$F', '^(spawn|spawnSync|execFile|execFileSync)$'), re('$CMD', SHELL_JS)]),
  ],
  CODE: [
    fokus(['eval($X)', 'new vm.Script($X, ...)']), // code-waechter:ok SEC-EVAL (Muster für Semgrep)
    fokus(['vm.$F($X, ...)'], [re('$F', '^(runInThisContext|runInNewContext|runInContext|compileFunction)$')]),
    mit(['new Function(...)', 'Function(...)']), // code-waechter:ok SEC-EVAL (Muster für Semgrep)
  ],
  PFAD: [
    ...fsAufruf(JS_FS_PFAD, '$X, ...', true),
    ...fsAufruf(JS_FS_ZWEI, '$A, $X, ...', true),
    fokus(['$RES.$M($X, ...)'], [re('$RES', '^(res|response|reply)$'), re('$M', '^(sendFile|download)$')]),
  ],
  DESER: [fokus(['$S.unserialize($X, ...)', 'v8.deserialize($X)'])],
  PROTOKOLL: [mit(['console.$M(...)'], [re('$M', '^(log|info|warn|error|debug|trace)$')])],
}
const JS_REINIGER: Record<Ziel, Muster[]> = {
  SQL: ZAHL_JS.map(p),
  PROGRAMM: [...ZAHL_JS, 'encodeURIComponent(...)'].map(p),
  CODE: ZAHL_JS.map(p),
  // path.basename("..") und encodeURIComponent("..") geben ".." zurück; bereinigt nur der volle Pfad (JS_VOLL), geprüft mit startsWith
  PFAD: [...ZAHL_JS.map(p), pruefung(['$P = path.$N(...)\n...'], ['$P.startsWith(...)'], [JS_VOLL]), pruefung([], ['path.$N(..., $P).startsWith(...)'], [JS_VOLL])],
  DESER: [],
  PROTOKOLL: [...ZAHL_JS, 'encodeURIComponent(...)', 'JSON.stringify(...)'].map(p),
}

const QUELLEN: Record<Sprache, Record<Herkunft, Muster[]>> = { PY: PY_QUELLEN, CS: CS_QUELLEN, JS: JS_QUELLEN }
const ZIEL_MUSTER: Record<Sprache, Record<Ziel, Muster[]>> = { PY: PY_ZIELE, CS: CS_ZIELE, JS: JS_ZIELE }
const REINIGER: Record<Sprache, Record<Ziel, Muster[]>> = { PY: PY_REINIGER, CS: CS_REINIGER, JS: JS_REINIGER }

export type Regel = { id: string; mode: 'taint'; languages: string[]; severity: 'ERROR' | 'WARNING'; message: string } & Record<string, unknown>

// Eine Quelle gilt nur als Ganzes (exact: true). Ohne das zählt Semgrep auch jeden Teil des Treffers als Quelle (gemessen 28.11.2026:
// die Quelle open(...) machte in open("fest.txt") den festen Namen zum "Pfad aus einer Datei"); mit exact nur echte Wege.
const genau = (q: Muster): Muster => ('by-side-effect' in q ? q : { exact: true, ...q })

// Alle Regeln: je Sprache, Ziel und Herkunft eine; ein Protokoll-Eintrag aus Befehlszeile oder Datei ist kein Befund.
export function semgrepRegeln(): Regel[] {
  const regeln: Regel[] = []
  for (const s of ['PY', 'CS', 'JS'] as Sprache[]) {
    for (const z of ZIELE) {
      for (const h of ['NETZ', 'LOKAL'] as Herkunft[]) {
        if (z === 'PROTOKOLL' && h === 'LOKAL') continue
        const reiniger = REINIGER[s][z]
        regeln.push({
          id: `FLUSS-${s}-${z}-${h}`, mode: 'taint', languages: SPRACHEN[s], severity: h === 'NETZ' && z !== 'PROTOKOLL' ? 'ERROR' : 'WARNING',
          message: `FLUSS-${s}-${z}-${h}`, 'pattern-sources': QUELLEN[s][h].map(genau), ...(reiniger.length > 0 ? { 'pattern-sanitizers': reiniger } : {}),
          'pattern-sinks': ZIEL_MUSTER[s][z],
        })
      }
    }
  }
  return regeln
}

// Regeldatei (JSON ist gültiges YAML; Semgrep liest sie mit --config, gemessen 28.11.2026). sprache: nur die Regeln dieser Sprache,
// für Dateien mit einer Endung, die Semgrep nicht kennt.
export function semgrepRegelText(sprache?: 'python' | 'typescript'): string {
  const alle = semgrepRegeln()
  const auswahl = sprache === undefined ? alle : alle.filter(r => r.languages.includes(sprache)).map(r => ({ ...r, languages: [sprache] }))
  return `${JSON.stringify({ rules: auswahl }, null, 1)}\n`
}

// ---- Meldung je Regel (Sprache wie eingestellt)
const ZIEL_TEXT: Record<Ziel, [string, string]> = {
  SQL: ['SQL-Abfrage enthält Text {h} - Werte als Parameter übergeben (?, @name, $1), nie in den SQL-Text einsetzen.',
    'SQL query contains text {h} - pass values as parameters (?, @name, $1), never insert them into the SQL text.'],
  PROGRAMM: ['Programmstart mit Text {h} - festes Programm, Argumente als Liste, keine Shell (shell=True, cmd /c, exec).',
    'program start with text {h} - fixed program, arguments as a list, no shell (shell=True, cmd /c, exec).'],
  CODE: ['Text {h} wird als Code ausgeführt oder geladen (eval, exec, Function, Assembly.Load) - nie mit fremdem Text.',
    'text {h} is run or loaded as code (eval, exec, Function, Assembly.Load) - never with foreign text.'],
  PFAD: ['Dateipfad enthält Text {h} - mit ../ wird jede Datei lesbar, überschreibbar oder löschbar. Den vollen Pfad bilden (realpath, Path.GetFullPath, path.resolve) und prüfen, dass er im festen Ordner liegt; der Dateiname allein (basename) lässt "..", "." und "" durch.',
    'file path contains text {h} - with ../ any file becomes readable, writable or deletable. Build the full path (realpath, Path.GetFullPath, path.resolve) and check that it lies inside the fixed folder; the file name alone (basename) lets "..", "." and "" through.'],
  DESER: ['Daten {h} werden unsicher deserialisiert (pickle, yaml.load, BinaryFormatter, TypeNameHandling) - das kann fremden Code ausführen. JSON oder yaml.safe_load nehmen.',
    'data {h} is deserialised unsafely (pickle, yaml.load, BinaryFormatter, TypeNameHandling) - this can run foreign code. Use JSON or yaml.safe_load.'],
  PROTOKOLL: ['Text {h} geht ungefiltert ins Protokoll - Zeilenumbrüche können falsche Einträge vortäuschen. \\r und \\n vorher ersetzen.',
    'text {h} goes into the log unfiltered - line breaks can fake entries. Replace \\r and \\n first.'],
}
const HERKUNFT_TEXT: Record<Herkunft, [string, string]> = {
  NETZ: ['aus dem Netz (Web-Anfrage, Socket oder Antwort eines Abrufs)', 'from the network (web request, socket or response of a request)'],
  LOKAL: ['aus Befehlszeile, Konsole oder Datei', 'from the command line, console or a file'],
}

export function semgrepText(id: string): string {
  const m = /^FLUSS-(PY|CS|JS)-(SQL|PROGRAMM|CODE|PFAD|DESER|PROTOKOLL)-(NETZ|LOKAL)$/.exec(id)
  if (!m) return t(`Semgrep-Regel ${rein(id, 60)}`, `Semgrep rule ${rein(id, 60)}`)
  const z = ZIEL_TEXT[m[2] as Ziel]
  const h = HERKUNFT_TEXT[m[3] as Herkunft]
  const lokal = m[3] === 'LOKAL' ? t(' Bei einem eigenen Werkzeug oft gewollt; kommt der Text von anderen, gilt das oben.', ' Often intended in your own tool; if others supply the text, the above applies.') : ''
  return `${t(z[0], z[1]).replace('{h}', t(h[0], h[1]))}${lokal} ${t('(Datenfluss innerhalb einer Funktion)', '(data flow within one function)')}`
}

// ---- Aufruf und Auswertung
// Unbekannte Endungen (siehe Kopf): je Sprache ein eigener Aufruf mit --scan-unknown-extensions.
const UNBEKANNT: { re: RegExp; sprache: 'python' | 'typescript' }[] = [{ re: /\.pyw$/i, sprache: 'python' }, { re: /\.[cm]ts$/i, sprache: 'typescript' }]

// --jobs=1: gemessen 28.11.2026 über ein Prüfprogramm (23 Dateien, dieselben Kopien dreimal): mit den 14 Fäden der Vorgabe 27,
// 29 und 29 Funde ohne jede Fehlermeldung, mit einem Faden dreimal 29 - gleich schnell (14 s); 135 C#-Dateien 5 statt 3,7 s.
export function semgrepArgv(exe: string, regeln: string, ausgabe: string, dateien: string[], unbekannt: boolean): string[] {
  return [exe, '--metrics=off', '--disable-version-check', '--quiet', '--json', '--no-rewrite-rule-ids', '--jobs=1', '--config', regeln, '--output', ausgabe,
    ...(unbekannt ? ['--scan-unknown-extensions'] : []), ...dateien]
}

// Stapel, deren Dateinamen zusammen unter BEFEHLSZEILE_MAX bleiben (je Name mit Anführungszeichen und Leerzeichen).
export function stapeln(dateien: string[], max = BEFEHLSZEILE_MAX): string[][] {
  const stapel: string[][] = []
  let jetzt: string[] = []
  let laenge = 0
  for (const f of dateien) {
    const l = f.length + 3
    if (jetzt.length > 0 && laenge + l > max) {
      stapel.push(jetzt)
      jetzt = []
      laenge = 0
    }
    jetzt.push(f)
    laenge += l
  }
  if (jetzt.length > 0) stapel.push(jetzt)
  return stapel
}

const schluessel = (p: string): string => p.trim().replace(/\//g, '\\').toLowerCase()
const ohneHerkunft = (id: string): string => id.replace(/-(NETZ|LOKAL)$/, '')

export type SemgrepLesung = { funde: Map<string, SFund[]>; luecken: Map<string, string[]>; fehler?: string }

// Fehler einer Datei: nur Art und Zeile - die Meldung von Semgrep enthält Text der Datei (gemessen bei "Syntax error"). Die Art ist
// ein Text ("Syntax error") oder eine Liste (["PartialParsing", [Stellen]], gemessen 28.11.2026 an gültigem C# 12 und TypeScript:
// Sammlungsausdrücke [..], Hauptkonstruktoren class X(int a), "out string?" in einem Objekt, "-->" in einem regulären Ausdruck).
function dateiFehler(e: any): string {
  const art = String((Array.isArray(e?.type) ? e.type[0] : e?.type) ?? '')
  const zeile = Number(e?.spans?.[0]?.start?.line) || Number(/:(\d+):/.exec(String(e?.message ?? ''))?.[1]) || 0
  const wo = zeile > 0 ? t(` in Zeile ${zeile}`, ` in line ${zeile}`) : ''
  if (/syntax|lexical|pars/i.test(art)) {
    return t(`Semgrep kann die Datei${wo} nicht lesen (Syntaxfehler oder Schreibweise, die Semgrep nicht kennt), dieser Teil ist nicht ausgewertet`,
      `Semgrep cannot read the file${wo} (syntax error or notation Semgrep does not know), that part is not analysed`)
  }
  return t(`Semgrep: ${daten(art, 60)}${wo}, Datei nicht ganz ausgewertet`, `Semgrep: ${daten(art, 60)}${wo}, file not fully analysed`)
}

// json: Ausgabe von Semgrep (--json); dateien: die echten Dateien; ziele: die Pfade, die Semgrep bekam (gleiche Reihenfolge, Kopien im
// Arbeitsordner, siehe semgrepPruefen); texte: Inhalt je echter Datei (für "code-waechter:ok SICHERHEIT").
export function semgrepLesen(json: string, dateien: string[], texte: Map<string, string>, ziele: string[] = dateien): SemgrepLesung {
  const funde = new Map<string, SFund[]>()
  const luecken = new Map<string, string[]>()
  const luecke = (f: string, text: string) => luecken.set(f, [...(luecken.get(f) ?? []), text])
  let j: any
  try {
    j = JSON.parse(json)
  } catch {
    return { funde, luecken, fehler: t('Ausgabe nicht lesbar', 'output not readable') }
  }
  if (!j || !Array.isArray(j.results)) return { funde, luecken, fehler: t('Ausgabe nicht lesbar', 'output not readable') }
  const nachPfad = new Map(dateien.map((f, i) => [schluessel(ziele[i] ?? f), f]))
  // Ein Fehler ohne geprüfte Datei (Regeldatei, Aufruf) heisst: der Lauf als Ganzes zählt nicht.
  for (const e of Array.isArray(j.errors) ? j.errors : []) {
    const f = nachPfad.get(schluessel(String(e?.path ?? '')))
    if (f) luecke(f, dateiFehler(e))
    else return { funde: new Map(), luecken: new Map(), fehler: `${rein(String(e?.type ?? '?'), 60)}: ${rein(String(e?.message ?? e?.short_msg ?? ''), 160)}` }
  }
  const zeilen = new Map<string, string[]>()
  for (const r of j.results) {
    const f = nachPfad.get(schluessel(String(r?.path ?? '')))
    if (!f) continue
    const id = String(r?.check_id ?? '?')
    const line = Number(r?.start?.line) || 1
    const z = zeilen.get(f) ?? (texte.get(f) ?? '').split(/\r?\n/)
    zeilen.set(f, z)
    if (OK_SICHER.test(z[line - 1] ?? '')) continue
    const liste = funde.get(f) ?? []
    liste.push({ line, col: Number(r?.start?.col) || 1, code: id, text: semgrepText(id), scanner: 'Semgrep',
      schwer: String(r?.extra?.severity ?? '') === 'ERROR' && !PRUEF_PFAD.test(f) })
    funde.set(f, liste)
  }
  // Je Zeile und Ziel ein Fund; aus dem Netz geht vor lokal.
  for (const [f, liste] of funde) {
    const gesehen = new Set<string>()
    funde.set(f, liste
      .sort((a, b) => a.line - b.line || Number(b.code.endsWith('-NETZ')) - Number(a.code.endsWith('-NETZ')) || a.col - b.col)
      .filter(x => {
        const k = `${x.line}|${ohneHerkunft(x.code)}`
        if (gesehen.has(k)) return false
        gesehen.add(k)
        return true
      }))
  }
  const gelesen = new Set((Array.isArray(j.paths?.scanned) ? j.paths.scanned : []).map((x: unknown) => schluessel(String(x))))
  const ausgelassen = Array.isArray(j.skipped_rules) ? j.skipped_rules.map((x: any) => String(x?.rule_id ?? x?.id ?? x)) : []
  for (const [i, f] of dateien.entries()) {
    if (!gelesen.has(schluessel(ziele[i] ?? f)) && !luecken.has(f)) luecke(f, t('Semgrep hat die Datei übersprungen', 'Semgrep skipped the file'))
    if (ausgelassen.length > 0) luecke(f, t(`Semgrep hat Regeln übersprungen: ${daten(ausgelassen.join(', '), 120)}`, `Semgrep skipped rules: ${daten(ausgelassen.join(', '), 120)}`))
  }
  return { funde, luecken }
}

const meldung = (err: unknown): string => String((err as { message?: string })?.message ?? err)

// Endung klein (Kopie im Arbeitsordner): Semgrep erkennt die Sprache an der Endung.
const endung = (f: string): string => (/\.[^.\\/]+$/.exec(f)?.[0] ?? '').toLowerCase()

// Eine Liste von Dateien prüfen (beim Schreiben eine, im /scan alle der drei Sprachen). frist: Zeit für den nächsten Aufruf in ganzen ms
// (höchstens 600000); art unterscheidet die Hilfsdateien von Sofortprüfung und Ordner-Scan. Ohne u.semgrep gehört die Prüfung nicht zur
// Umgebung; fehlt das Programm, bricht es ab oder reicht die Zeit nicht, steht das bei jeder betroffenen Datei unter luecken.
// Geprüft wird eine Kopie im Arbeitsordner der Mod (kopien: schon angelegte, z. B. der Spiegel des Ordner-Scans; sonst schreibt diese
// Funktion den gelesenen Text selbst hin). Gemessen 28.11.2026: liegt eine ausdrücklich genannte Datei in einem grossen
// Projektordner (Git-Ablage), braucht Semgrep 1.186.0 je Datei 6,1 bis 6,7 s allein für die Zielsuche (get_targets, auch mit --no-git-ignore) - drei
// Dateien 23,5 s; dieselben drei als Kopie im Temp-Ordner 3,4 s mit denselben Funden. Ohne Text bleibt die echte Datei das Ziel.
export async function semgrepPruefen(u: Umgebung, dateien: string[], texte: Map<string, string>, frist: () => Promise<number>, art = '',
  kopien?: Map<string, string>): Promise<Map<string, Ergebnis>> {
  const erg = new Map<string, Ergebnis>(dateien.map(f => [f, { funde: [], luecken: [], liefen: [] }]))
  if (!u.semgrep || dateien.length === 0) return erg
  const luecke = (liste: string[], text: string) => {
    for (const f of liste) erg.get(f)?.luecken.push(text)
  }
  const kaputt = (liste: string[], grund: string) => luecke(liste, t(`Semgrep lief nicht: ${grund}`, `Semgrep did not run: ${grund}`))
  let exe: string | undefined
  let arbeit: string
  try {
    exe = await u.semgrep()
    arbeit = await u.workDir()
  } catch (err) {
    kaputt(dateien, rein(meldung(err)))
    return erg
  }
  if (!exe) {
    luecke(dateien, t(`Semgrep fehlt (einmalig: ${SEMGREP_BEFEHL})`, `Semgrep missing (once: ${SEMGREP_BEFEHL})`))
    return erg
  }
  const kennung = u.kennung.replace(/[^\w-]/g, '_').slice(0, 64) || 'chat'
  // Kopien: <Arbeitsordner>\semgrep-<Chat><art>\<Nummer><endung>; gelingt das Schreiben nicht, wird die echte Datei geprüft.
  const ziel = new Map<string, string>()
  for (const [i, f] of dateien.entries()) {
    const fertig = kopien?.get(f)
    const text = texte.get(f)
    if (fertig !== undefined || text === undefined) {
      ziel.set(f, fertig ?? f)
      continue
    }
    const kopie = `${arbeit}\\semgrep-${kennung}${art}\\${i}${endung(f)}`
    try {
      await u.write(kopie, text)
      ziel.set(f, kopie)
    } catch {
      // Kopie nicht anlegbar: die echte Datei geht an Semgrep (langsamer, aber geprüft)
      ziel.set(f, f)
    }
  }
  const zielVon = (f: string): string => ziel.get(f) ?? f
  const gruppen: { name: string; sprache?: 'python' | 'typescript'; dateien: string[] }[] = [
    { name: '', dateien: dateien.filter(f => !UNBEKANNT.some(x => x.re.test(f))) },
    ...UNBEKANNT.map(x => ({ name: `-${x.sprache}`, sprache: x.sprache, dateien: dateien.filter(f => x.re.test(f)) })),
  ]
  for (const g of gruppen) {
    if (g.dateien.length === 0) continue
    // Die Regeln liegen im Arbeitsordner der Mod und werden nur neu geschrieben, wenn sie sich geändert haben.
    const regeln = `${arbeit}\\semgrep-regeln${g.name}.json`
    try {
      const inhalt = semgrepRegelText(g.sprache)
      if ((await u.read(regeln)) !== inhalt) await u.write(regeln, inhalt)
    } catch (err) {
      kaputt(g.dateien, t(`Regeln nicht schreibbar (${rein(meldung(err), 120)})`, `rules not writable (${rein(meldung(err), 120)})`))
      continue
    }
    const echt = new Map(g.dateien.map(f => [zielVon(f), f]))
    for (const ziele of stapeln(g.dateien.map(zielVon))) {
      const stapel = ziele.map(z => echt.get(z) ?? z)
      const zeit = await frist()
      if (zeit < 1000) {
        luecke(stapel, t('Semgrep: Zeitgrenze des Scans erreicht', 'Semgrep: scan time limit reached'))
        continue
      }
      // Ausgabe in eine Datei: viele Funde werden so nie abgeschnitten (wie bei den anderen Scannern im Ordner-Scan).
      const aus = `${arbeit}\\semgrep-${kennung}${art}${g.name}.json`
      try {
        await u.write(aus, GITLEAKS_VORHER)
        const r = await u.run(semgrepArgv(exe, regeln, aus, ziele, g.sprache !== undefined), { cwd: arbeit, timeoutMs: zeit })
        if (!r.ok) {
          kaputt(stapel, rein(r.reason))
          continue
        }
        const inhalt = await u.read(aus)
        if (inhalt === undefined || inhalt.trim() === GITLEAKS_VORHER) {
          const rest = `${r.stderr}${r.stdout}`.trim().split(/\r?\n/).pop() ?? ''
          kaputt(stapel, t('keine Ausgabe geschrieben', 'no output written') + (rest ? `: ${daten(rest)}` : '') + (r.exitCode !== 0 ? t(` (Code ${r.exitCode})`, ` (code ${r.exitCode})`) : ''))
          continue
        }
        const l = semgrepLesen(inhalt, stapel, texte, ziele)
        if (l.fehler !== undefined) {
          kaputt(stapel, daten(l.fehler))
          continue
        }
        // Rückgabe 0 auch mit Funden (siehe Kopf); jeder andere Code ohne erkannte Ursache gilt nie als "geprüft".
        if (r.exitCode !== 0) {
          kaputt(stapel, t(`Code ${r.exitCode}`, `code ${r.exitCode}`))
          continue
        }
        for (const f of stapel) {
          const e = erg.get(f)
          if (!e) continue
          e.funde.push(...(l.funde.get(f) ?? []))
          const lu = l.luecken.get(f) ?? []
          e.luecken.push(...lu)
          if (lu.length === 0) e.liefen.push('Semgrep')
        }
      } catch (err) {
        kaputt(stapel, rein(meldung(err)))
      }
    }
  }
  return erg
}
