# Code-Wächter / Code Guard

**English below.**

Eine Mod für Claude Code unter Windows. Sie prüft jede Datei, die Claude schreibt oder ändert, sofort danach und meldet Fehler, Sicherheitslücken und Verbesserungen direkt an Claude zurück, damit sie gleich behoben werden. In der rechten Seitenleiste steht alles nach Sprache bzw. Projekt gegliedert; ein behobener Fehler steht wieder als „in Ordnung“ da, Einträge älter als 48 Stunden verschwinden. Bleiben nach einer Antwort rote oder gelbe Meldungen offen, meldet die Mod sie Claude von selbst zum Beheben (jede Meldung einmal, dieselbe Datei höchstens dreimal je Sitzung).

Freie Software unter der MIT-Lizenz: Jeder darf sie nutzen, verändern und weitergeben.

## Was geprüft wird

| Bereich | Prüfung |
| --- | --- |
| C# / .NET, XAML | Projekt übersetzen (Namen, Typen, Warnungen und Analyse-Regeln als Vorschläge); eine C#-Datei ohne Projekt oder vom Projekt ausgeschlossen wird in einem freigegebenen Ordner allein übersetzt (Einstellungen und usings des Projekts, das sie ausschliesst, sonst Standard; fehlende Namen mit den Dateien dieses Projekts bzw. den übrigen C#-Dateien des Ordners, was dann noch fehlt, steht offen als eingeschränkt), sonst Syntax mit Roslyn |
| C#: Härtung (Hinweise) | `catch` ohne `when`, das jeden Fehler zu "leer" macht (`return null`); Schleife über eine Antwort von aussen (Netzaufruf), die ohne Grenze sammelt; bewusste Stellen mit `code-waechter:ok HAERTUNG` |
| C#: Bedrohungen beim Schreiben | Schlüssel aus einem Kennwort mit festem Salz und Programmstart aus einem festen Temp-Ordner mit Adminrechten als Fehler; als Hinweis: Programmstart aus einem festen Temp-Ordner, zu wenige PBKDF2-Runden, Bild aus dem Netz ohne Grössengrenze, Entschlüsseln, das Text ohne Kennung durchlässt, Startschalter, der löscht, Übernahme aller Eigenschaften per Reflection, erst prüfen und dann kürzen, eingelesene Liste ohne Obergrenze, Befehl nur am Leerzeichen getrennt, Geheimnis in Protokoll oder Meldung. Prüfprojekte (`Tests`, `X.Tests`, `X.Probe`) zählen nicht. Alle Funde stehen in **einer** Datei `Haertungsprotokoll.txt` in der Ablage, ein Abschnitt je Programm, Projekt oder Mod; ein Eintrag verschwindet, sobald die Datei ohne den Fund geprüft wurde |
| KI-Fehlerarten (alle Code-Dateien) | im neu geschriebenen Text: eingebaute Geheimnisse (Schlüssel, Token, private Schlüssel) und Sicherheitslücken in C#, die das Übersetzen nicht meldet (abgeschaltete Zertifikatsprüfung, unsichere Deserialisierung, XML mit fremden Dateien), als Fehler; Debug-Reste, Merkposten (`TODO:`/`FIXME:`), leere Fänge (`catch {}`, auch mit `when`, `except: pass`) und `async void` ohne `try` als Hinweis; bewusste Stellen mit `code-waechter:ok KI`. In Prüfdateien (`.test.`) zählen nur abgeschaltete Prüfsätze (`it.skip`, `[Ignore]`, `Skip =` …) |
| Sicherheits-Scanner (nach dem Schreiben) | je nach Dateiart DevSkim (C#, C, C++), Cppcheck (C, C++; `.h` als C++), Bandit (Python), Gitleaks (jede geprüfte Datei und Einstellungsdateien `.env`, `.ini`, `.cfg`, `.conf`, `.properties`), dazu eigene Muster für C#: Harmony (`UnpatchAll()` ohne Kennung, nicht statische Patch-Methode, Kennung ohne Punkt) und `Process.Start`. Fehler: Geheimnisse (Gitleaks ohne die Regel `generic-api-key`, die Übersetzungsschlüssel für Schlüssel hält), Cppcheck `error`, DevSkim `Critical` (`MD5` nur als eigenes Wort), Bandit hoch/hoch, die Harmony-Fehler; sonst Hinweis. Geheimnisse stehen nie im Klartext in Meldung oder Bericht. Alle Funde zusätzlich gebündelt in `security-report.txt` in der Ablage. Fehlt ein Scanner, lief er nicht durch oder hat er die Datei übersprungen, steht das offen beim ✔ |
| C# und WPF: Abstürze | Fehler, die das Übersetzen durchlässt und die erst beim Ausführen abstürzen: Formate wie `"H"` statt `"%H"`, `int.Parse` auf ein Eingabefeld (`.Text`), falsche Platzhalter; in XAML falsche Werte (z. B. `Width="12x"`), fehlende `StaticResource`-Namen, ein Stil an Stelle einer Farbe |
| C / C++ | `cl.exe` (Visual Studio), C nach C17, Header für sich allein (C-Header als C) |
| Python, Blender-Skripte | pyflakes, dazu Ruff (Fehlerquellen, Leistung, Sicherheit); typische Blender-Schreibweisen (`bpy.props` als Annotation, `importlib.reload`) gelten nicht als Fehler |
| PHP | `php -l`, Sicherheitsmuster (SQL-Einschleusung, XSS auch in Vorlagen, Befehle, Dateipfade …), PHPStan (falsche Aufrufe sind Fehler) |
| JavaScript / TypeScript / JSX | `node --check`, `tsc` (Schreibweise, JSX auch in `.js`, CommonJS, Dekoratoren, Ungenutztes), ESLint (sichere Laufzeitfehler sind Fehler), Sicherheitsmuster |
| HTML, CSS, XML, JSON, YAML, TOML | Aufbau bzw. Syntax; HTML: nicht geschlossene Elemente; YAML: eigene Tags (`!Ref`, `!secret`), doppelte Schlüssel |
| SQL | sqlglot (grobe Schreibweise; Dialekt einstellbar) |
| Java, Kotlin | Eclipse-Übersetzer (ohne Annotation-Prozessoren), `kotlinc`: Schreibweise und Typen |
| Rust, Go, Ruby | `rustc` ohne Standardbibliothek, `gofmt -e`, `ruby -c` |
| Lua (z. B. Landwirtschafts-Simulator) | `luac 5.1 -p` |
| Shell, PowerShell, Perl | `bash -n`, Parser von PowerShell 7 (sonst 5.1), `perl -c`; `.cmd`/`.bat` mit PowerShell-Teil: der PowerShell-Teil mit dem Parser, der Batch-Kopf mit dem Sprachpaket |
| Unity | Szenen, Prefabs, Assets (Unity-YAML), `.meta` (guid, doppelte guids), C#-Skripte ohne `.csproj`: mit den Bibliotheken des installierten Unity-Editors der Projektversion übersetzt (fehlt er: nur Schreibweise), C#-Vorschläge (teure Aufrufe in `Update`, `CompareTag`, leere Methoden) |
| Unreal Engine | `X.generated.h` als letzte Einbindung, `GENERATED_BODY()`, UCLASS nur in Headern, Zeiger ohne `UPROPERTY()`, `.uproject` / `.uplugin` |
| Godot | GDScript (`.gd`) mit gdtoolkit; C# wie oben |
| VB.NET, F# | mit Projekt (`.vbproj`, `.fsproj`) übersetzen wie C#; ohne Projekt VB.NET mit `vbc` (Schreibweise, Namen, Typen), F# mit `fsc --parseonly` (Schreibweise) – beides aus dem .NET-SDK |
| Shader | HLSL, Unreal `.usf`/`.ush`: `dxc` (Windows-SDK oder geladen); GLSL je Stufe (`.vert`, `.frag`, `.comp` …): `glslang`; Unity (`.shader`, `.cginc`, Shader im Unity-Projekt): Aufbau (Klammern, `CGPROGRAM`/`ENDCG`, `#if`-Zweige) – den Shadercode selbst übersetzt nur Unity |
| Zig, Luau (Roblox), SCSS/Sass, Bicep | `zig ast-check`, `luau-analyze` (Typen als Vorschlag), Dart Sass, `bicep build` |
| Assembler | MASM mit `ml64 /Zs` (Visual Studio); NASM und GNU-Assembler: offen nicht geprüft |
| R | `parse()` mit einem installierten R (`Rscript --vanilla`) |
| Vue | `<script>` mit `tsc`, Zeilen wie in der `.vue`-Datei; Blöcke geschlossen |
| Sprachpakete (tree-sitter), Fund = Fehler | Dart, Scala, Haskell, OCaml, Elixir, Fortran, Solidity, Terraform/HCL, CMake, Ada, Odin, VHDL, Arduino, Starlark/Bazel, Kotlin-Skript (`.kts`), Svelte, MATLAB |
| Sprachpakete, Fund = mögliche Fehlerstelle | Swift, Julia, Pascal/Delphi, Common Lisp, Verilog, SystemVerilog, Zsh, Puppet, Gradle, WGSL, Batch, Nix, GLSL (`.glsl`), CUDA, Makefile; ohne Zig, Luau, Bicep auch diese |
| Ohne Prüfprogramm (offen nicht geprüft) | Objective-C, Groovy, Slang, `.fx`-Effekte, LESS, Erlang, Clojure, Nim, COBOL, GraphQL, Protocol Buffers, Elm, D, LaTeX, Racket, Scheme, Crystal, Gleam, Haxe, Vala |
| Jede Datei | Zugangsdaten im Code (Schlüssel, Tokens, auch in sehr langen Zeilen) und vergessene Git-Konfliktmarken |

Fehlt ein Prüfprogramm, heißt es offen **NICHT GEPRÜFT** mit Grund, nie ein falsches „in Ordnung“. Fehler, die nur beim Bedienen eines Programms auftreten, findet der Wächter nicht: Er startet das geprüfte Programm nie.

**Wie verlässlich die Sprachpakete sind:** Jede Sprache wurde an echtem Code großer öffentlicher Projekte gemessen (je 16 bis 40 Dateien). Nur wo dabei keine einzige gültige Datei als fehlerhaft galt, ist ein Fund ein Fehler. Bei den übrigen Sprachen meldete die Grammatik auch gültigen Code; dort nennt der Wächter die Stelle nur als mögliche Fehlerstelle („nicht geprüft“), nie als Fehler. Die Aufbauprüfung für Unity-Shader lief an 2309 Shader-Dateien aus Unity 2022.3 und 6000.6 (auch URP und HDRP) ohne Falschmeldung und fand 30 von 30 eingebauten Fehlern.

## Sicherheit

- Was Code eines Projekts ausführen kann (Projekt übersetzen, `perl -c`, PHPStan, Prüfskripte eines Projekts), läuft **nur in freigegebenen Ordnern** (Einstellung „Freigegebene Ordner“). Überall sonst wird nur die Schreibweise geprüft. Liegt über dem Projekt eine Bau-Einstellungsdatei (`Directory.Build.props`/`.targets`, `global.json` …) ausserhalb der freigegebenen Ordner, wird ebenfalls nicht übersetzt.
- Programme werden nur mit vollem Pfad gestartet, nie aus dem Projektordner.
- Inhalte aus geprüften Dateien (auch Datei- und Ordnernamen) werden bereinigt und als Daten gekennzeichnet; gefundene Schlüssel werden nie im Klartext wiederholt, auch nicht in Meldungen der Prüfprogramme. Fehlermeldungen zu eingebundenen Dateien ausserhalb des Projektordners erscheinen ohne deren Text.
- Ordner mit `.code-guard-skip` und nicht verfolgte Verknüpfungen (Junctions) nennt `/scan` immer; ein solcher Scan gilt nie als ganz geprüft.
- `/waechter-werkzeuge` lädt Prüfprogramme nur vom Hersteller, mit fester Fassung und SHA-256-Prüfsumme (npm-Pakete über eine mitgelieferte Lock-Datei, pip mit festen Prüfsummen), ohne Installation und ohne Paket-Skripte. Ein vorhandener Ordner, der nicht von der Mod stammt, wird nie angefasst.
- Eine Stelle lässt sich bewusst von einem Muster ausnehmen (Kommentar am Zeilenende, z. B. `// code-waechter:ok SEC-EVAL`); die Meldung nennt solche Stellen immer. Für Zugangsdaten gilt das nie.

## Befehle

- `/waechter` – Seitenleiste öffnen
- `/waechter-leeren` – Anzeige der Seitenleiste leeren (die Fehlerberichte bleiben)
- `/scan <Projekt | all | Ordner | Datei>` – ganze Projekte prüfen und einen Fehlerbericht schreiben
- `/waechter-werkzeuge` – Prüfprogramme anzeigen; `/waechter-werkzeuge install <Name>` oder `install all` lädt fehlende

## Projektliste und Scan

`/scan` liest die Projekte aus `Projekte.txt` in der Ablage (Einstellung „Ablage“, sonst `%USERPROFILE%\Code-Waechter`). Fehlt die Datei, legt der Wächter eine Vorlage an. Eine Zeile je Projekt:

```
Name | Ordner | Projektleiter-Chat
```

Der Projektleiter-Chat ist freiwillig: Läuft ein Chat mit diesem Namen, bekommt er die gefundenen Fehler als Nachricht. Ordner mit einer Datei `.code-waechter-auslassen` oder `.code-guard-skip` lässt der Scan samt Unterordnern aus (z. B. heruntergeladene Programme); der Bericht nennt jeden ausgelassenen Ordner. Binärdateien (ein Nullbyte in den ersten 8000 Bytes, z. B. ein Spielmodell mit der Endung eines Shaders) und NuGet-Ablagen `packages\<Paket>.<Fassung>` prüft der Wächter nicht; der Bericht nennt die übergangenen Binärdateien.

## Einstellungen

| Einstellung | Bedeutung |
| --- | --- |
| Sprache | `auto` (Anzeigesprache von Windows), `de` oder `en` |
| Freigegebene Ordner | nur hier wird übersetzt und werden Projektskripte gestartet; mehrere mit `;` trennen, z. B. `D:\Projekte`. Leer: nirgends |
| Ordner für Prüfprogramme | Ziel von `/waechter-werkzeuge`; leer: `%LOCALAPPDATA%\Code-Waechter\Werkzeuge` |
| Ablage | Ordner für `Projekte.txt` und Fehlerberichte |
| Python-Aufruf | z. B. `py` oder `py -3.14`; für die gründliche Python-Prüfung muss dort pyflakes installiert sein |
| SQL-Dialekt | z. B. `tsql`, `mysql`, `postgres`, `sqlite`, `oracle` |

## Voraussetzungen

- Windows 10 oder 11, 64 Bit.
- Claude Code: im Terminal, in der Desktop-App (Bereich „Code“) oder in VS Code. Im normalen Chat auf claude.ai und in Cloud-Sitzungen läuft die Mod nicht.
- Python (z. B. über den Python-Starter `py`): für die Prüfungen von Python, XML, JSON, YAML, HTML, CSS, SQL und zum Laden der Sprachpakete.
- Je nach Sprache das passende Programm, falls vorhanden: .NET-SDK (C#, VB.NET, F#), Visual Studio mit C++ (C/C++, Assembler), Windows-SDK (HLSL). Fehlende Prüfprogramme lädt `/waechter-werkzeuge`; was fehlt, meldet die Mod offen als „nicht geprüft“.
- Für die Sicherheits-Scanner (einmalig, jeder einzeln möglich, in einem normalen Fenster - nicht als Administrator, sonst lehnt winget Gitleaks ab): `dotnet tool install --global Microsoft.CST.DevSkim.CLI`, `winget install Cppcheck.Cppcheck`, `winget install Gitleaks.Gitleaks`, und Bandit mit dem Python der Einstellung „Python-Befehl“, z. B. `py -m pip install bandit`.

## Installation

In Claude Code eingeben (ab Claude Code 2.1.275):

```
/plugin install code-waechter --marketplace kaesehobel79ch/code-waechter
```

Oder in der Eingabeaufforderung bzw. PowerShell, in zwei Schritten:

```
claude plugin marketplace add kaesehobel79ch/code-waechter
```

```
claude plugin install code-waechter@kaese-hobel
```

Danach:

1. Claude Code neu starten oder `/reload-plugins` eingeben.
2. Die Einstellungen der Mod öffnen und die freigegebenen Ordner eintragen, z. B. `D:\Projekte` (nur dort werden Projekte übersetzt):

   ```
   /plugin configure code-waechter@kaese-hobel
   ```

3. Die Prüfprogramme laden: `/waechter-werkzeuge install all` (oder einzeln, z. B. `/waechter-werkzeuge install treesitter`). `/waechter-werkzeuge` allein zeigt, was da ist und was fehlt.

Neue Fassungen holen:

```
claude plugin update code-waechter@kaese-hobel
```

Wichtig: Wie jede Mod läuft der Code-Wächter mit den Rechten des Benutzers. Er startet Prüfprogramme, aber nie das geprüfte Programm selbst, und übersetzt Projekte nur in freigegebenen Ordnern (siehe „Sicherheit“).

## Hinweis zur Entwicklung

Bei der Entwicklung dieses Programms wurde KI-Unterstützung eingesetzt. Der Quellcode wurde durch den Entwickler geprüft, angepasst und für dieses Projekt zusammengestellt.

---

# Code Guard (English)

A Claude Code mod for Windows: it checks every file Claude writes or edits right afterwards and reports errors, security holes and improvements back to Claude so they get fixed immediately. The right sidebar groups everything by language or project; a fixed error shows as "OK" again, entries older than 48 hours disappear. If red or yellow entries are still open after an answer, the mod reports them to Claude by itself to be fixed (each entry once, the same file at most three times per session).

Free software under the MIT license: anyone may use, change and share it.

It covers C#/.NET and XAML (a C# file without a project, or excluded by its project, is compiled on its own in a trusted folder, with the settings and usings of the project that excludes it or defaults, together with that project's files or the other C# files of its folder if names are missing; including mistakes that only crash at run time, such as `"H"` instead of `"%H"`, `int.Parse` on an input field, invalid XAML values or missing `StaticResource` names), VB.NET, F#, C/C++, MASM assembler, Python and Blender scripts, PHP, JavaScript/TypeScript/JSX, Vue, Svelte, HTML, CSS, SCSS/Sass, XML, JSON, YAML, TOML, SQL, Java, Kotlin, Rust, Go, Zig, Ruby, Lua, Luau, Shell, Batch (including `.cmd`/`.bat` files with a PowerShell part, which is checked by the PowerShell parser), PowerShell, Perl, R, shaders (HLSL with dxc, GLSL with glslang, Unity structure only, CUDA, WGSL), Bicep, Unity (C# scripts without a `.csproj` are compiled against the installed Unity editor of the project's version), Unreal Engine, Godot and, through tree-sitter language packages, Swift, Dart, Scala, Haskell, OCaml, Elixir, Julia, Fortran, Pascal, Ada, Odin, Lisp, MATLAB, Solidity, Terraform, CMake, Makefile, Nix, Verilog, SystemVerilog and VHDL (see the table above). Language packages were measured on real code from large public projects; only where no valid file was ever flagged is a finding reported as an error, otherwise it is reported as a possible error location ("not checked"), never as an error. Languages without a reliable checker on Windows (Objective-C, Groovy, Erlang, Clojure and others) are reported openly as not checked. If a checker is missing it says **NOT CHECKED** with the reason, never a false "OK". In every code file, newly written text is also checked for typical mistakes of AI-written code: embedded secrets and C# security holes the build does not report (certificate check switched off, unsafe deserialization, XML loading outside files) as errors; debug leftovers, TODO/FIXME notes, empty catches (also with `when`) and `async void` without `try` as hints; in test files (`.test.`) only switched-off tests (`it.skip`, `[Ignore]`, `Skip =` …); mark deliberate spots with `code-waechter:ok KI`. C# files are also checked for known threats while writing: a key derived from a password with a fixed salt and a program started from a fixed Temp folder with admin rights are errors; a program started from a fixed Temp folder, too few PBKDF2 iterations, a network image decoded without a size limit, decryption that lets unmarked text through, a start switch that deletes, copying all properties by reflection, check-then-cut, a loaded list without a limit, a command split only at the space and a secret in a log or message are hints (test projects `Tests`, `X.Tests`, `X.Probe` do not count; deliberate spots `code-waechter:ok HAERTUNG`). All findings are collected in **one** file `Haertungsprotokoll.txt` in the storage folder, one section per program, project or mod; an entry disappears once the file is checked without that finding. C# builds also run all .NET security rules. After every write the matching security scanners run as well: DevSkim (C#, C, C++), Cppcheck (C, C++), Bandit (Python), Gitleaks (every checked file plus .env, .ini, .cfg, .conf, .properties) and own C# patterns for Harmony patches and `Process.Start`; all findings are also collected in `security-report.txt` in the storage folder, secrets never in clear text. Install them once in a normal (not administrator) window with `dotnet tool install --global Microsoft.CST.DevSkim.CLI`, `winget install Cppcheck.Cppcheck`, `winget install Gitleaks.Gitleaks` and `<your Python command> -m pip install bandit`; a missing scanner is reported as not checked. It never starts the program being checked, so errors that only appear while using a program are not found.

**Security:** anything that could run a project's code (building, `perl -c`, PHPStan, project scripts) runs only in folders you trust (setting "Trusted folders"); elsewhere only the syntax is checked. A project is not built either if MSBuild would read a build settings file above it (`Directory.Build.props`/`.targets`, `global.json` …) from outside the trusted folders. Programs are started by full path only, never from the project folder. File content shown in messages (file and folder names included) is sanitised and marked as data; secrets found are never repeated in clear text, not even in checker messages; errors in included files outside the project folder are shown without their text. `/scan` always names skipped folders and links it did not follow. `/waechter-werkzeuge install all` downloads checkers straight from the vendor, pinned version and SHA-256 checksum, no installation, no package scripts.

**Commands:** `/waechter` (sidebar), `/waechter-leeren` (clear the sidebar, reports stay), `/scan <project | all | folder | file>`, `/waechter-werkzeuge [install <name> | install all]`. Projects for `/scan` are listed in `Projekte.txt` (one line per project: `name | folder | lead chat`). Folders containing `.code-guard-skip` are skipped. Binary files (a null byte in the first 8000 bytes, e.g. a game model with a shader extension) and NuGet folders `packages\<name>.<version>` are not checked; the report lists the binary files passed over. Messages are in German or English (setting "Language": auto, de, en).

**Requirements:** Windows 10 or 11 (64-bit); Claude Code in the terminal, the desktop app (Code tab) or VS Code – not the claude.ai chat or cloud sessions; Python (e.g. the `py` launcher) for Python, XML, JSON, YAML, HTML, CSS, SQL and for installing the language packages; the .NET SDK, Visual Studio with C++ or the Windows SDK for the languages that use them. Missing checkers are installed with `/waechter-werkzeuge`; anything missing is reported openly as "not checked".

**Install** inside Claude Code (Claude Code 2.1.275 or later):

```
/plugin install code-waechter --marketplace kaesehobel79ch/code-waechter
```

Or from a shell, in two steps:

```
claude plugin marketplace add kaesehobel79ch/code-waechter
```

```
claude plugin install code-waechter@kaese-hobel
```

Then restart Claude Code or run `/reload-plugins`, enter your trusted folders in the mod settings (`/plugin configure code-waechter@kaese-hobel`), and run `/waechter-werkzeuge install all`. Update with `claude plugin update code-waechter@kaese-hobel`.

Like every mod, Code Guard runs with your user rights. It starts checkers but never the program being checked, and builds projects only in trusted folders.

## Development note

AI assistance was used in developing this program. The source code was reviewed, adapted and assembled for this project by the developer.

## License

MIT, see [LICENSE](LICENSE).
