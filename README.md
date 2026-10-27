# Code-Wächter / Code Guard

**English below.**

Eine Mod für Claude Code unter Windows. Sie prüft jede Datei, die Claude schreibt oder ändert, sofort danach und meldet Fehler, Sicherheitslücken und Verbesserungen direkt an Claude zurück, damit sie gleich behoben werden. In der rechten Seitenleiste steht alles nach Sprache bzw. Projekt gegliedert; behobene Fehler werden als „behoben“ markiert, Einträge älter als 48 Stunden verschwinden.

Freie Software unter der MIT-Lizenz: Jeder darf sie nutzen, verändern und weitergeben.

## Was geprüft wird

| Bereich | Prüfung |
| --- | --- |
| C# / .NET, XAML | Projekt übersetzen (Namen, Typen, Warnungen und Analyse-Regeln als Vorschläge), sonst Syntax mit Roslyn |
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
| Shell, PowerShell, Perl | `bash -n`, Parser von PowerShell 7 (sonst 5.1), `perl -c` |
| Unity | Szenen, Prefabs, Assets (Unity-YAML), `.meta` (guid, doppelte guids), C#-Vorschläge (teure Aufrufe in `Update`, `CompareTag`, leere Methoden) |
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

- Was Code eines Projekts ausführen kann (Projekt übersetzen, `perl -c`, PHPStan, Prüfskripte eines Projekts), läuft **nur in freigegebenen Ordnern** (Einstellung „Freigegebene Ordner“). Überall sonst wird nur die Schreibweise geprüft.
- Programme werden nur mit vollem Pfad gestartet, nie aus dem Projektordner.
- Inhalte aus geprüften Dateien werden bereinigt und als Daten gekennzeichnet; gefundene Schlüssel werden nie im Klartext wiederholt.
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

Der Projektleiter-Chat ist freiwillig: Läuft ein Chat mit diesem Namen, bekommt er die gefundenen Fehler als Nachricht. Ordner mit einer Datei `.code-waechter-auslassen` oder `.code-guard-skip` lässt der Scan samt Unterordnern aus (z. B. heruntergeladene Programme); der Bericht nennt jeden ausgelassenen Ordner.

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

A Claude Code mod for Windows: it checks every file Claude writes or edits right afterwards and reports errors, security holes and improvements back to Claude so they get fixed immediately. The right sidebar groups everything by language or project; fixed errors are marked "fixed", entries older than 48 hours disappear.

Free software under the MIT license: anyone may use, change and share it.

It covers C#/.NET and XAML (including mistakes that only crash at run time, such as `"H"` instead of `"%H"`, `int.Parse` on an input field, invalid XAML values or missing `StaticResource` names), VB.NET, F#, C/C++, MASM assembler, Python and Blender scripts, PHP, JavaScript/TypeScript/JSX, Vue, Svelte, HTML, CSS, SCSS/Sass, XML, JSON, YAML, TOML, SQL, Java, Kotlin, Rust, Go, Zig, Ruby, Lua, Luau, Shell, Batch, PowerShell, Perl, R, shaders (HLSL with dxc, GLSL with glslang, Unity structure only, CUDA, WGSL), Bicep, Unity, Unreal Engine, Godot and, through tree-sitter language packages, Swift, Dart, Scala, Haskell, OCaml, Elixir, Julia, Fortran, Pascal, Ada, Odin, Lisp, MATLAB, Solidity, Terraform, CMake, Makefile, Nix, Verilog, SystemVerilog and VHDL (see the table above). Language packages were measured on real code from large public projects; only where no valid file was ever flagged is a finding reported as an error, otherwise it is reported as a possible error location ("not checked"), never as an error. Languages without a reliable checker on Windows (Objective-C, Groovy, Erlang, Clojure and others) are reported openly as not checked. If a checker is missing it says **NOT CHECKED** with the reason, never a false "OK". It never starts the program being checked, so errors that only appear while using a program are not found.

**Security:** anything that could run a project's code (building, `perl -c`, PHPStan, project scripts) runs only in folders you trust (setting "Trusted folders"); elsewhere only the syntax is checked. Programs are started by full path only, never from the project folder. File content shown in messages is sanitised and marked as data; secrets found are never repeated in clear text. `/waechter-werkzeuge install all` downloads checkers straight from the vendor, pinned version and SHA-256 checksum, no installation, no package scripts.

**Commands:** `/waechter` (sidebar), `/waechter-leeren` (clear the sidebar, reports stay), `/scan <project | all | folder | file>`, `/waechter-werkzeuge [install <name> | install all]`. Projects for `/scan` are listed in `Projekte.txt` (one line per project: `name | folder | lead chat`). Folders containing `.code-guard-skip` are skipped. Messages are in German or English (setting "Language": auto, de, en).

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
