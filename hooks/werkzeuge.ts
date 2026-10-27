// Prüfprogramme, die der Code-Wächter auf Befehl selbst lädt (/waechter-werkzeuge).
// Alles kommt direkt vom Hersteller, mit fester Fassung und Prüfsumme: Dateien mit SHA-256, npm-Pakete über die mitgelieferte
// package-lock.json (npm ci, jede Fassung und Prüfsumme fest), pip-Pakete mit --require-hashes. Alles landet in einem eigenen Ordner
// der Mod. Nichts wird installiert, nichts an Windows geändert, keine Paket-Skripte laufen (npm --ignore-scripts, pip nur fertige Pakete).
//
// Checkers the Code Guard downloads on request. Everything comes straight from the vendor, pinned version and checksum,
// into the mod's own folder. Nothing is installed, Windows is not changed, no package scripts run.

import { t } from './i18n'
import { ESLINT_LOCK, ESLINT_PACKAGE, TYPESCRIPT_LOCK, TYPESCRIPT_PACKAGE } from './locks'
import { isAbsolute, resolveExe } from './prozess'

export type ToolId =
  | 'php' | 'node' | 'typescript' | 'eslint' | 'ruff' | 'phpstan' | 'lua' | 'pyyaml'
  | 'go' | 'ruby' | 'rust' | 'jre' | 'ecj' | 'kotlin' | 'sqlglot' | 'gdscript'
  | 'pyembed' | 'treesitter' | 'zig' | 'luau' | 'sass' | 'glslang' | 'dxc' | 'bicep'

type Pip = { spec: string; hashes: string[] }

type Source =
  // zip: ganzes Archiv auspacken; datei: eine Datei; tar: mit tar.exe von Windows (zip, 7z, tar.xz), nur die genannten Teile,
  // strip: so viele Ordnerebenen am Anfang weglassen
  | { art: 'zip' | 'datei'; url: string; sha256: string; name: string }
  | { art: 'tar'; url: string; sha256: string; name: string; teile: string[]; strip: number }
  | { art: 'npm'; paket: string; lock: string }
  // python: feste Python-Fassung für fertige Pakete (die reine Python-Fassung des Pakets läuft dann auch unter anderen)
  | { art: 'pip'; pakete: Pip[]; python?: string }

export type ToolDef = {
  id: ToolId
  titel: string
  version: string
  mb: number
  wofuer: [string, string] // Deutsch, Englisch
  quelle: Source
  exe: string // Pfad im Werkzeugordner, an dem das Programm nach dem Laden liegt
  braucht?: ToolId[]
}

export const TOOLS: ToolDef[] = [
  {
    id: 'php',
    titel: 'PHP',
    version: '8.5.12',
    mb: 35,
    wofuer: ['Schreibweise von PHP-Dateien (php -l)', 'syntax of PHP files (php -l)'],
    quelle: {
      art: 'zip',
      // Archiv-Adresse: unter releases/ liegt nur die neueste Fassung, ältere wandern nach archives/ (belegt an 8.5.11).
      url: 'https://downloads.php.net/~windows/releases/archives/php-8.5.12-nts-Win32-vs17-x64.zip',
      sha256: '2ab242af38d76bdf417cde5ec048b1bcd76a5a40f39a3d15d5f046f38571c477',
      name: 'php.zip',
    },
    exe: 'php\\php.exe',
  },
  {
    id: 'node',
    titel: 'Node.js',
    version: '24.22.1',
    mb: 36,
    wofuer: ['Schreibweise von JavaScript (node --check); Grundlage für TypeScript und ESLint', 'JavaScript syntax (node --check); needed for TypeScript and ESLint'],
    quelle: {
      art: 'zip',
      url: 'https://nodejs.org/dist/v24.22.1/node-v24.22.1-win-x64.zip',
      sha256: 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5',
      name: 'node.zip',
    },
    exe: 'node\\node.exe',
  },
  {
    id: 'typescript',
    titel: 'TypeScript',
    version: '7.0.2',
    mb: 30,
    wofuer: ['Schreibweise von TypeScript und JSX, ungenutzter Code', 'TypeScript and JSX syntax, unused code'],
    quelle: { art: 'npm', paket: TYPESCRIPT_PACKAGE, lock: TYPESCRIPT_LOCK },
    exe: 'typescript\\node_modules\\typescript\\bin\\tsc',
    braucht: ['node'],
  },
  {
    id: 'eslint',
    titel: 'ESLint',
    version: '10.13.0',
    mb: 10,
    wofuer: ['Logikfehler und Verbesserungsvorschläge in JavaScript', 'logic bugs and suggestions in JavaScript'],
    quelle: { art: 'npm', paket: ESLINT_PACKAGE, lock: ESLINT_LOCK },
    exe: 'eslint\\node_modules\\eslint\\bin\\eslint.js',
    braucht: ['node'],
  },
  {
    id: 'ruff',
    titel: 'Ruff',
    version: '0.17.1',
    mb: 10,
    wofuer: ['Verbesserungsvorschläge, Leistung und Sicherheit in Python', 'suggestions, performance and security in Python'],
    quelle: {
      art: 'zip',
      url: 'https://github.com/astral-sh/ruff/releases/download/0.17.1/ruff-x86_64-pc-windows-msvc.zip',
      sha256: 'a841fb7e59680508b9394bfea32e369b3907cc6620a491c65d8d1f479498db82',
      name: 'ruff.zip',
    },
    exe: 'ruff\\ruff.exe',
  },
  {
    id: 'phpstan',
    titel: 'PHPStan',
    version: '2.3.1',
    mb: 30,
    wofuer: ['Logikfehler in PHP (nur in freigegebenen Ordnern)', 'logic bugs in PHP (trusted folders only)'],
    quelle: {
      art: 'datei',
      url: 'https://github.com/phpstan/phpstan/releases/download/2.3.1/phpstan.phar',
      sha256: '85157dba3d95d77ca603d2b7303aa78a538f9e3b56ccad07dd794c53aa96d1ae',
      name: 'phpstan.phar',
    },
    exe: 'phpstan\\phpstan.phar',
    braucht: ['php'],
  },
  {
    id: 'lua',
    titel: 'Lua 5.1',
    version: '5.1.5',
    mb: 1,
    wofuer: ['Schreibweise von Lua 5.1 (Landwirtschafts-Simulator und andere Spiele)', 'Lua 5.1 syntax (Farming Simulator and other games)'],
    quelle: {
      art: 'zip',
      url: 'https://sourceforge.net/projects/luabinaries/files/5.1.5/Tools%20Executables/lua-5.1.5_Win64_bin.zip/download',
      sha256: '5f34cf7d40a20a587ea351482a4207d93b92ef6f1983e910a13338253819fe93',
      name: 'lua.zip',
    },
    exe: 'lua\\luac5.1.exe',
  },
  {
    id: 'pyyaml',
    titel: 'PyYAML',
    version: '6.0.3',
    mb: 1,
    wofuer: ['YAML-Dateien und Unity-Szenen genau prüfen (braucht Python)', 'YAML files and Unity scenes in detail (needs Python)'],
    quelle: {
      art: 'pip',
      // Das fertige Paket für Python 3.14: unter anderen Fassungen läuft es als reine Python-Fassung (getestet mit 3.15).
      python: '3.14',
      pakete: [
        {
          spec: 'pyyaml==6.0.3',
          hashes: [
            '5cf4e27da7e3fbed4d6c3d8e797387aaad68102272f8f9752883bc32d61cb87b',
            '2e71d11abed7344e42a8849600193d15b6def118602c4c176f748e4583246007',
            'bdb2c67c6c1390b63c6ff89f210c8fd09d9a1217a465701eac7316313c915e4c',
            '9f3bfb4965eb874431221a3ff3fdcddc7e74e3b07799e0e84ca4a0f867d449bf',
            '5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b',
            '79005a0d97d5ddabfeeea4cf676af11e647e41d81c9a7722a193022accdb6b7c',
            '4a2e8cebe2ff6ab7d1050ecd59c25d4c8bd7e6f400f5f82b96557ac0abafd0ac',
            '4ad1906908f2f5ae4e5a8ddfce73c320c2a1429ec52eafd27138b7f1cbe341c9',
          ],
        },
      ],
    },
    exe: 'pyyaml\\yaml\\__init__.py',
  },
  {
    id: 'go',
    titel: 'Go (gofmt)',
    version: '1.27.3',
    mb: 79,
    wofuer: ['Schreibweise von Go (gofmt -e); geladen wird das Go-Paket, behalten nur gofmt.exe', 'Go syntax (gofmt -e); the Go package is downloaded, only gofmt.exe is kept'],
    quelle: {
      art: 'tar',
      url: 'https://go.dev/dl/go1.27.3.windows-amd64.zip',
      sha256: 'f26081f438319757f8a1b46d7d0b2c5ec7583d4038e485e0aa725cfde7885fff',
      name: 'go.zip',
      teile: ['go/bin/gofmt.exe'],
      strip: 2,
    },
    exe: 'go\\gofmt.exe',
  },
  {
    id: 'ruby',
    titel: 'Ruby',
    version: '4.0.7',
    mb: 18,
    wofuer: ['Schreibweise von Ruby (ruby -c); behalten werden nur ruby.exe und seine DLLs', 'Ruby syntax (ruby -c); only ruby.exe and its DLLs are kept'],
    quelle: {
      art: 'tar',
      url: 'https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-4.0.7-2/rubyinstaller-4.0.7-2-x64.7z',
      sha256: 'fd380a84a2de4443899f4be4f9d33c0f87859c27b8bce29f0bf7fe0c36cb4b93',
      name: 'ruby.7z',
      teile: ['rubyinstaller-4.0.7-2-x64/bin/ruby.exe', 'rubyinstaller-4.0.7-2-x64/bin/*.dll', 'rubyinstaller-4.0.7-2-x64/bin/ruby_builtin_dlls'],
      strip: 1,
    },
    exe: 'ruby\\bin\\ruby.exe',
  },
  {
    id: 'rust',
    titel: 'Rust (rustc)',
    version: '1.99.1',
    mb: 77,
    wofuer: ['Schreibweise von Rust (rustc ohne Standardbibliothek; entpackt rund 200 MB)', 'Rust syntax (rustc without the standard library; about 200 MB unpacked)'],
    quelle: {
      art: 'tar',
      url: 'https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-x86_64-pc-windows-msvc.tar.xz',
      sha256: '7da83c2af1f209606b0160f25174d2867c7c7b73667c32c9e5fbcef4f5f45348',
      name: 'rustc.tar.xz',
      teile: ['rustc-1.99.1-x86_64-pc-windows-msvc/rustc/bin/rustc.exe', 'rustc-1.99.1-x86_64-pc-windows-msvc/rustc/bin/rustc_driver-*.dll'],
      strip: 2,
    },
    exe: 'rust\\bin\\rustc.exe',
  },
  {
    id: 'jre',
    titel: 'Java-Laufzeit (Temurin)',
    version: '25.0.4.1',
    mb: 58,
    wofuer: ['Grundlage für die Java- und Kotlin-Prüfung', 'needed for the Java and Kotlin checks'],
    quelle: {
      art: 'tar',
      url: 'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jre_x64_windows_hotspot_25.0.4.1_1.zip',
      sha256: '4c95451cea98556def2c54f7782933f52a26d4a36bd85e1d59f0364464828b07',
      name: 'jre.zip',
      teile: [],
      strip: 1,
    },
    exe: 'jre\\bin\\java.exe',
  },
  {
    id: 'ecj',
    titel: 'Java (Eclipse-Übersetzer ECJ)',
    version: '3.46.100',
    mb: 3,
    wofuer: ['Java-Dateien prüfen: Schreibweise und Typen (ohne Annotation-Prozessoren)', 'Java files: syntax and types (without annotation processors)'],
    quelle: {
      art: 'datei',
      url: 'https://repo1.maven.org/maven2/org/eclipse/jdt/ecj/3.46.100/ecj-3.46.100.jar',
      // Maven Central nennt nur SHA-1 (a06c482c…, stimmt); die SHA-256 ist an der geladenen Datei gemessen (22.10.2026).
      sha256: '74c93172475fee0cd4e6eefb44233516dd40525642da35d009146d97ea598229',
      name: 'ecj.jar',
    },
    exe: 'ecj\\ecj.jar',
    braucht: ['jre'],
  },
  {
    id: 'kotlin',
    titel: 'Kotlin',
    version: '2.4.21',
    mb: 90,
    wofuer: ['Kotlin-Dateien prüfen: Schreibweise und Typen', 'Kotlin files: syntax and types'],
    quelle: {
      art: 'tar',
      url: 'https://github.com/JetBrains/kotlin/releases/download/v2.4.21/kotlin-compiler-2.4.21.zip',
      sha256: '7cc140e76daf416a0424a5557f99afd7ca89ebd463ea1101261e3e01c33e75cd',
      name: 'kotlin.zip',
      teile: [],
      strip: 1,
    },
    exe: 'kotlin\\lib\\kotlin-compiler.jar',
    braucht: ['jre'],
  },
  {
    id: 'sqlglot',
    titel: 'SQL (sqlglot)',
    version: '30.24.0',
    mb: 1,
    wofuer: ['grobe Schreibweise von SQL-Dateien (braucht Python)', 'rough syntax of SQL files (needs Python)'],
    quelle: { art: 'pip', pakete: [{ spec: 'sqlglot==30.24.0', hashes: ['9488828cc018453b7a3ba01e65d2749c9a731314c14583695163ca1f358203fe'] }] },
    exe: 'sqlglot\\sqlglot\\__init__.py',
  },
  {
    id: 'gdscript',
    titel: 'GDScript (gdtoolkit)',
    version: '4.5.0',
    mb: 1,
    wofuer: ['Schreibweise von Godot-Skripten (.gd, braucht Python 3.10 bis 3.15)', 'syntax of Godot scripts (.gd, needs Python 3.10 to 3.15)'],
    quelle: {
      art: 'pip',
      pakete: [
        { spec: 'gdtoolkit==4.5.0', hashes: ['f25c5bf7f7fe861e1127164c5d73e0a7fb204ec74cf05d375b76a5dcf8610cdb'] },
        { spec: 'lark==1.2.2', hashes: ['c2276486b02f0f1b90be155f2c8ba4a8e194d42775786db622faccd652d8e80c'] },
        {
          spec: 'regex==2026.9.29',
          hashes: [
            '23ae6fdad9e63e54038f5ef78aba2933faca61e24d432786589e737bc5522ebb',
            '1043aedf5917caa861bcb25a9c11460049656bdf0017a90a309fa8f255467725',
            'fdd88ed5e20b1bcdd234421e454962c971aa44b653bdb7f1ea9ef683e90fb649',
            '61956f074ecd123f55adca68ee3eab46e6a07ad3f8e64e6db95dfacb444f55c4',
            '1c2a0026062abcc321a53db4a185ceba0b59a66b5d37b0808917a88b55a5257f',
            'bf48516e35cf848390ea68850aba53e7c333720d2945b4d2c25b69fc5171723f',
            'b3e445b66c80b4eb4234e855ce94d9adc183eedbd632816228d89930b91b2c5b',
            'e2c89e9b762c57f59d5e99ee8b20202adb892e35f8d3485741340999ca55058e',
          ],
        },
      ],
    },
    exe: 'gdscript\\gdtoolkit\\__init__.py',
  },
  {
    id: 'pyembed',
    titel: 'Python 3.14 (eigene Fassung der Mod)',
    version: '3.14.7',
    mb: 13,
    wofuer: ['feste Python-Fassung für die Sprachpakete (tree-sitter), unabhängig vom installierten Python', 'fixed Python version for the language packages (tree-sitter), independent of the installed Python'],
    quelle: {
      art: 'zip',
      // Prüfsumme von python.org (release_file, sha256_sum), an der geladenen Datei nachgemessen (27.10.2026).
      url: 'https://www.python.org/ftp/python/3.14.7/python-3.14.7-embed-amd64.zip',
      sha256: 'd297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15',
      name: 'pyembed.zip',
    },
    exe: 'pyembed\\python.exe',
  },
  {
    id: 'treesitter',
    titel: 'Sprachpakete (tree-sitter)',
    version: '0.26.0',
    mb: 10,
    wofuer: [
      'Schreibweise von Swift, Dart, Scala, Haskell, OCaml, Elixir, Julia, Fortran, Pascal, Ada, Odin, Lisp, MATLAB, Solidity, Terraform, CMake, Makefile, Batch, Zsh, Nix, Starlark, Puppet, Gradle, Kotlin-Skript, Svelte, GLSL, CUDA, WGSL, Arduino, Verilog, SystemVerilog, VHDL (braucht Python für das Laden)',
      'syntax of Swift, Dart, Scala, Haskell, OCaml, Elixir, Julia, Fortran, Pascal, Ada, Odin, Lisp, MATLAB, Solidity, Terraform, CMake, Makefile, Batch, Zsh, Nix, Starlark, Puppet, Gradle, Kotlin script, Svelte, GLSL, CUDA, WGSL, Arduino, Verilog, SystemVerilog, VHDL (needs Python to install)',
    ],
    quelle: {
      art: 'pip',
      // Fertige Pakete für Python 3.14; ausgeführt werden sie mit der eigenen Python-Fassung der Mod (pyembed).
      python: '3.14',
      pakete: [
        { spec: 'tree-sitter==0.26.0', hashes: ['a4033fecc8f606c7f2e8b8014d0057b74668a7f0152763606f7bc25c5f9ec64c'] },
        { spec: 'tree-sitter-dart==0.1.0', hashes: ['ee1d5f2109d2a206583227cfc4e2b0890f48700a0796207c2eecb5c3d7f23f63'] },
        { spec: 'tree-sitter-scala==0.26.3', hashes: ['55dfb401aae8904f912c51d8a59671f1807a20a82b9c2b61b6e81121bbca81d0'] },
        { spec: 'tree-sitter-haskell==0.24.1', hashes: ['e8e3292d4dc2782913cebb589b59e094ab3f656c7ef078d327843c04a0f30e3c'] },
        { spec: 'tree-sitter-ocaml==0.26.0', hashes: ['828a59dd11c5c11db7cbee516571782d3c85fd8dfeaa5fc42179f1c97d5c9b80'] },
        { spec: 'tree-sitter-elixir==0.3.5', hashes: ['c0b5df229405d42ba5c94254d92e414b1f200be8422561d243ae5b3558e84f76'] },
        { spec: 'tree-sitter-fortran==0.6.0', hashes: ['cccd5bce1cdebcf34d3a130ecf4944bc409ddc93096317e3249838ffdaf927eb'] },
        { spec: 'tree-sitter-solidity==1.2.13', hashes: ['3f700a305167e39b984d38dceddf45a56e898124a923bf5cb6bb4b149c2c7063'] },
        { spec: 'tree-sitter-hcl==1.2.0', hashes: ['4ac026d83d72216444963dfb603fc3e1806aca0a5cb3c236d14e82f20fb7b5de'] },
        { spec: 'tree-sitter-cmake==0.7.2.post1', hashes: ['c1b7a754e17442087df3efccea6535a9f2a8c4b4bf558e31fd3caccd8d1ce830'] },
        { spec: 'tree-sitter-ada==0.9.1', hashes: ['54dd3ce8c64eddb41a46a9b6eabeb32dd9a022ff2fde96a60d87eeae6b824e9e'] },
        { spec: 'tree-sitter-odin==1.3.0', hashes: ['7f4413fdb8c38cafc13da48bb7cecd06fd0d4e2848723ccf4b3115dada726ad2'] },
        { spec: 'tree-sitter-vhdl==2.0.3', hashes: ['d436c01f0fe5eb83d7161d56a3a7e33d22ecce1f089993a653df7e263c66e626'] },
        { spec: 'tree-sitter-arduino==0.24.0', hashes: ['eafa967977c11ce3e1201b64cd0b0e18548d55fcdd6926f3740bfd8a05b673c7'] },
        { spec: 'tree-sitter-starlark==1.3.0', hashes: ['53026cd8899785eb65fbad4aa8f87026cac777cb0ff121d133ae093daddb4ae3'] },
        { spec: 'tree-sitter-kotlin==1.1.0', hashes: ['d4d3f330f515ba8b91da04a5335eb9ff3ce071c7b7855958912f2560f6e14976'] },
        { spec: 'tree-sitter-svelte==1.0.2', hashes: ['febd1573c9469a1d4ce199801fd63d144d21e0f09e1458b1637ffb00f473ce0e'] },
        { spec: 'tree-sitter-matlab==1.3.1', hashes: ['505d5efdcbd1d76b7134eb7e79727265135c92f2cadbe119930604b5c65fdb46'] },
        { spec: 'tree-sitter-swift==0.7.4', hashes: ['6edfdeff86d842e7ee54f2a5d77dad9b6d9cc8b9f1ae0342e1c4349c44348803'] },
        { spec: 'tree-sitter-julia==0.23.1', hashes: ['13031aa4c9ac7d0665aa3ecd9fbc6f9c6afd601c68f6ae67a8eeaca01465aeed'] },
        { spec: 'tree-sitter-pascal==0.11.0', hashes: ['99346d54c928d42c820c0aa262f6acbf4fb2856d69016f1df11f834f681b45e0'] },
        { spec: 'tree-sitter-commonlisp==0.4.1', hashes: ['5990660d55567565fee2dd609b4500c6fd0049c82d5ea195779d7c6dd78a75cc'] },
        { spec: 'tree-sitter-verilog==1.0.3', hashes: ['da82da153a8d515941da26d84d51b6b79d0fe42d0a0de19845562c3b1dd091c1'] },
        { spec: 'tree-sitter-systemverilog==0.4.1', hashes: ['ed3af21d1c9265d3e9dc16bef66b97b5ef22e9c5bc6b6a03ec4417b451b2fec2'] },
        { spec: 'tree-sitter-zsh==0.63.4', hashes: ['98fb2c190ac2c4e1a11eb971d1ef819e42f90dd453cf362f2284664a8f5b6dc4'] },
        { spec: 'tree-sitter-puppet==1.3.0', hashes: ['ba0edc4e8adab5e3f4a64025fe1a9511ea1927369a0d2c3b9e3a1b92b75eea9b'] },
        { spec: 'tree-sitter-groovy==0.1.2', hashes: ['bb8b20e2c92a18509ad3b830aeba9f5754778903e7dfd6999c3efb3c79c43d76'] },
        { spec: 'tree-sitter-wgsl-bevy==0.1.4', hashes: ['b7d87a6102530d6aab11ef8b69e1730a259889dc98b794ddd3352419b6f8b198'] },
        { spec: 'tree-sitter-batch==0.11.1', hashes: ['755ca1e2dcbc06e62e7e254fd99b40bcef8d35a927fb8f123c72c60baf4bc6f5'] },
        { spec: 'tree-sitter-nix==0.1.0', hashes: ['9294bf94c2ece0b4e64c32f0de57b9ac861577bae81fac2dfabf954cfd25700e'] },
        { spec: 'tree-sitter-glsl==0.2.0', hashes: ['6d35e1d56aa634afc73ca75c465e47633109a38c62e37dc5b874b6566219edc8'] },
        { spec: 'tree-sitter-cuda==0.21.2', hashes: ['8e1e184181211a633263de2a379bc87a31677a3af91c4e9762b1a5ea6187a578'] },
        { spec: 'tree-sitter-make==1.1.1', hashes: ['0f6325bf5255bfdb3895aa18cbf3618734bc94f31bd89447559137675160a424'] },
        { spec: 'tree-sitter-zig==1.1.2', hashes: ['7b94f00a0e69231ac4ebf0aa763734b9b5637e0ff13634ebfe6d13fadece71e9'] },
        { spec: 'tree-sitter-luau==1.2.0', hashes: ['c8f86b022fe6d1a784e26fa2e898f1459a3f4d31555bed31bf6dda9c72e46f6d'] },
        { spec: 'tree-sitter-bicep==1.1.0', hashes: ['fe3e9621d427e826e2b6aa9fcd3eeba5527c7fec0fa640cfd1fa2a2ae7a67494'] },
      ],
    },
    exe: 'treesitter\\tree_sitter\\__init__.py',
    braucht: ['pyembed'],
  },
  {
    id: 'zig',
    titel: 'Zig',
    version: '0.17.0',
    mb: 96,
    wofuer: ['Zig-Dateien prüfen (zig ast-check); geladen wird das Zig-Paket, behalten nur zig.exe', 'Zig files (zig ast-check); the Zig package is downloaded, only zig.exe is kept'],
    quelle: {
      art: 'tar',
      // Prüfsumme aus ziglang.org/download/index.json, an der geladenen Datei nachgemessen (27.10.2026).
      url: 'https://ziglang.org/download/0.17.0/zig-x86_64-windows-0.17.0.zip',
      sha256: 'b5663f69581dcf391293fbf16c06cb80d81d806545ce618b4d0bab7f0eb8c428',
      name: 'zig.zip',
      teile: ['zig-x86_64-windows-0.17.0/zig.exe'],
      strip: 1,
    },
    exe: 'zig\\zig.exe',
  },
  {
    id: 'luau',
    titel: 'Luau (Roblox)',
    version: '0.744',
    mb: 3,
    wofuer: ['Luau-Dateien prüfen (luau-analyze)', 'Luau files (luau-analyze)'],
    quelle: {
      art: 'zip',
      // Prüfsumme aus der GitHub-Freigabe (digest), an der geladenen Datei nachgemessen (27.10.2026).
      url: 'https://github.com/luau-lang/luau/releases/download/0.744/luau-windows.zip',
      sha256: 'fde3e22c557aac6afe20a34e8050b7d8c290fa42638c04274a307ed5d0ef0db8',
      name: 'luau.zip',
    },
    exe: 'luau\\luau-analyze.exe',
  },
  {
    id: 'sass',
    titel: 'Sass (Dart Sass)',
    version: '1.106.1',
    mb: 5,
    wofuer: ['SCSS- und Sass-Dateien prüfen (übersetzt sie, ohne etwas zu schreiben)', 'SCSS and Sass files (compiles them without writing anything)'],
    quelle: {
      art: 'zip',
      url: 'https://github.com/sass/dart-sass/releases/download/1.106.1/dart-sass-1.106.1-windows-x64.zip',
      sha256: 'a6e5bf97187af4a175279eabb6316af597d6e4b06ec2099ae961dc553655d8e1',
      name: 'sass.zip',
    },
    exe: 'sass\\src\\dart.exe',
  },
  {
    id: 'glslang',
    titel: 'GLSL (glslang, Khronos)',
    version: '16.6.0',
    mb: 14,
    wofuer: ['GLSL-Shader (.vert, .frag, .comp …) prüfen; behalten wird nur glslang.exe', 'GLSL shaders (.vert, .frag, .comp …); only glslang.exe is kept'],
    quelle: {
      art: 'tar',
      url: 'https://github.com/KhronosGroup/glslang/releases/download/16.6.0/glslang-16.6.0-windows-x86_64-release.zip',
      sha256: '82bf434e69b9bb4829de7e2b4bc2c5e7a7861e53d66cf75e5cc70f5f694a8d9b',
      name: 'glslang.zip',
      teile: ['bin/glslang.exe'],
      strip: 1,
    },
    exe: 'glslang\\glslang.exe',
  },
  {
    id: 'dxc',
    titel: 'HLSL (DirectX Shader Compiler, Microsoft)',
    version: '1.9.2609',
    mb: 31,
    wofuer: ['HLSL-Shader prüfen (nur nötig ohne Windows-SDK, das dxc schon mitbringt)', 'HLSL shaders (only needed without the Windows SDK, which already ships dxc)'],
    quelle: {
      art: 'zip',
      url: 'https://github.com/microsoft/DirectXShaderCompiler/releases/download/v1.9.2609/dxc_2026_09_29.zip',
      sha256: 'ad31b1fc8443175d204f77a611fdb3ef2ec42759bdc2f1167368de24a4a7e7f1',
      name: 'dxc.zip',
    },
    exe: 'dxc\\bin\\x64\\dxc.exe',
  },
  {
    id: 'bicep',
    titel: 'Bicep (Azure)',
    version: '0.48.1',
    mb: 119,
    wofuer: ['Bicep-Dateien prüfen (bicep build ohne Laden fremder Module)', 'Bicep files (bicep build without restoring external modules)'],
    quelle: {
      art: 'datei',
      url: 'https://github.com/Azure/bicep/releases/download/v0.48.1/bicep-win-x64.exe',
      sha256: '398af294cf16ac4becdbd008a77d148d0e8e91492309a6b60ec911b7e1cab082',
      name: 'bicep.exe',
    },
    exe: 'bicep\\bicep.exe',
  },
]

// ---- Ordner der Werkzeuge: eingestellt (werkzeug_ordner), sonst %LOCALAPPDATA%\Code-Waechter\Werkzeuge.
let configured = ''

export function setToolDirOption(value: string): void {
  configured = value.trim().replace(/[\\/]+$/, '')
}

// Nie ein Ordner, in den andere Benutzer schreiben dürfen (C:\Users\Public): dort könnte jemand ein Prüfprogramm austauschen.
export async function toolDir($: any): Promise<string> {
  if (configured.length > 0) return configured.replace(/\//g, '\\')
  let base = ''
  try {
    base = String((await $.env.get('LOCALAPPDATA')) ?? '')
  } catch {
    base = ''
  }
  if (!isAbsolute(base)) throw new Error(t('LOCALAPPDATA ist nicht gesetzt; bitte den Ordner für Prüfprogramme einstellen', 'LOCALAPPDATA is not set; please set the checker folder'))
  return `${base}\\Code-Waechter\\Werkzeuge`
}

// Voller Pfad eines geladenen Werkzeugs, oder undefined.
export async function toolPath($: any, id: ToolId): Promise<string | undefined> {
  const def = TOOLS.find(x => x.id === id)
  if (!def) return undefined
  try {
    const p = `${await toolDir($)}\\${def.exe}`
    return (await $.fs.exists(p)) ? p : undefined
  } catch {
    return undefined
  }
}

// ---- Laden
// PowerShell lädt, vergleicht die Prüfsumme und packt aus. Werte kommen über die Umgebung, nie in den Befehlstext.
// Schutz:
// - Ein schon vorhandener Zielordner wird nur ersetzt, wenn er die Marke der Mod trägt (sonst gehört er dem Benutzer und bleibt unberührt).
// - Ein Zip mit Einträgen außerhalb des Zielordners ("..", Laufwerk, führender Schrägstrich) wird verworfen; tar.exe verweigert solche
//   Einträge von sich aus.
// - Alle Pfade wörtlich (-LiteralPath, WebClient): eckige Klammern im Ordnernamen sind kein Suchmuster.
// - Jeder Ladevorgang hat seinen eigenen Zwischenordner, der am Ende immer verschwindet; eine Sperrdatei je Werkzeug verhindert, dass
//   zwei Chats gleichzeitig dasselbe Werkzeug laden.
export const TOOL_MARK = '.code-waechter-werkzeug'

const DOWNLOAD_PS = [
  "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'",
  '[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12',
  `$ziel=$env:CW_ZIEL;$marke=Join-Path $ziel '${TOOL_MARK}'`,
  "if((Test-Path -LiteralPath $ziel) -and -not (Test-Path -LiteralPath $marke)){Write-Output 'CW_FREMD';exit 5}",
  '[IO.Directory]::CreateDirectory($env:CW_DIR)|Out-Null',
  "$sperre=Join-Path $env:CW_DIR ('.laedt_'+$env:CW_ID)",
  "if((Test-Path -LiteralPath $sperre) -and ((Get-Item -LiteralPath $sperre).LastWriteTime -lt (Get-Date).AddMinutes(-30))){Remove-Item -LiteralPath $sperre -Force}",
  "try{[IO.File]::Open($sperre,'CreateNew').Dispose()}catch{Write-Output 'CW_BESETZT';exit 6}",
  "$tmp=Join-Path $env:CW_DIR ('_laden_'+[guid]::NewGuid().ToString('N'));$code=0",
  'try{' +
    '[IO.Directory]::CreateDirectory($tmp)|Out-Null;$datei=Join-Path $tmp $env:CW_NAME;' +
    "$w=New-Object Net.WebClient;$w.Headers['User-Agent']='Wget/1.21 (code-waechter)';$w.DownloadFile($env:CW_URL,$datei);" +
    '$h=(Get-FileHash -LiteralPath $datei -Algorithm SHA256).Hash.ToLower();' +
    "if($h -ne $env:CW_SHA){Write-Output ('CW_SHA_FALSCH '+$h);$code=3}else{" +
      "$x=Join-Path $tmp 'x';" +
      "if($env:CW_ART -eq 'zip'){" +
        'Add-Type -AssemblyName System.IO.Compression.FileSystem;$z=[IO.Compression.ZipFile]::OpenRead($datei);$bad=$false;' +
        "foreach($e in $z.Entries){$n=$e.FullName.Replace([char]92,[char]47);if($n.StartsWith('/') -or $n -match '^[A-Za-z]:' -or ('/'+$n+'/').Contains('/../')){$bad=$true}};$z.Dispose();" +
        "if($bad){Write-Output 'CW_ZIP_UNSICHER';$code=4}else{Expand-Archive -LiteralPath $datei -DestinationPath $x -Force}" +
      "}elseif($env:CW_ART -eq 'tar'){" +
        "[IO.Directory]::CreateDirectory($x)|Out-Null;$teile=@($env:CW_TEILE -split '\\|' | Where-Object {$_});" +
        '& (Join-Path $env:SystemRoot \'System32\\tar.exe\') -xf $datei -C $x --strip-components $env:CW_STRIP @teile;' +
        "if($LASTEXITCODE -ne 0){Write-Output ('CW_TAR_FEHLER '+$LASTEXITCODE);$code=4}" +
      '}else{[IO.Directory]::CreateDirectory($x)|Out-Null;Move-Item -LiteralPath $datei -Destination (Join-Path $x $env:CW_NAME)};' +
      'if($code -eq 0){' +
        'if(Test-Path -LiteralPath $ziel){Remove-Item -LiteralPath $ziel -Recurse -Force};' +
        '$k=@(Get-ChildItem -LiteralPath $x -Force);' +
        "if($env:CW_ART -eq 'zip' -and $k.Count -eq 1 -and $k[0].PSIsContainer){Move-Item -LiteralPath $k[0].FullName -Destination $ziel}else{Move-Item -LiteralPath $x -Destination $ziel};" +
        "Set-Content -LiteralPath $marke -Value 'code-waechter' -Encoding ascii;Write-Output 'CW_FERTIG'" +
      '}' +
    '}' +
  '}finally{Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $sperre -Force -ErrorAction SilentlyContinue}',
  'exit $code',
].join(';')

// Marke prüfen für npm- und pip-Pakete (die ins Ziel installieren statt es zu ersetzen).
async function foreignTarget($: any, ziel: string): Promise<boolean> {
  try {
    return (await $.fs.exists(ziel)) && !(await $.fs.exists(`${ziel}\\${TOOL_MARK}`))
  } catch {
    return false
  }
}

type Run = { ok: boolean; exitCode: number; out: string; reason: string }

async function run($: any, argv: string[], env: Record<string, string>, timeoutMs: number, cwd?: string): Promise<Run> {
  // Nur mit vollem Pfad starten (prozess.ts), und im Werkzeugordner arbeiten statt im Ordner des Projekts.
  const exe = await resolveExe($, argv[0] ?? '')
  if (!exe) return { ok: false, exitCode: -1, out: '', reason: t(`Programm "${argv[0]}" nicht gefunden`, `program "${argv[0]}" not found`) }
  try {
    const r = await $.process.run([exe, ...argv.slice(1)], { env, timeoutMs, cwd })
    return { ok: true, exitCode: r.exitCode, out: `${r.stdout ?? ''}\n${r.stderr ?? ''}`, reason: '' }
  } catch (err) {
    return { ok: false, exitCode: -1, out: '', reason: String((err as { message?: string })?.message ?? err).slice(0, 200) }
  }
}

// Mit Abhängigkeiten, in der richtigen Reihenfolge (Node vor TypeScript, PHP vor PHPStan, Java-Laufzeit vor Java und Kotlin).
export function withDependencies(ids: ToolId[]): ToolId[] {
  const out: ToolId[] = []
  const add = (id: ToolId) => {
    if (out.includes(id)) return
    for (const dep of TOOLS.find(x => x.id === id)?.braucht ?? []) add(dep)
    out.push(id)
  }
  for (const id of ids) add(id)
  return out
}

// Was wirklich geladen werden muss: die gewünschten Werkzeuge samt Abhängigkeiten, ohne die schon vorhandenen.
export async function toInstall($: any, ids: ToolId[]): Promise<ToolDef[]> {
  const out: ToolDef[] = []
  for (const id of withDependencies(ids)) {
    if (await toolPath($, id)) continue
    const def = TOOLS.find(x => x.id === id)
    if (def) out.push(def)
  }
  return out
}

const short = (s: string): string =>
  s
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200)

// Lädt ein Werkzeug. Rückgabe: Meldungszeile.
export async function installTool($: any, def: ToolDef, python: string[]): Promise<string> {
  const dir = await toolDir($)
  const ziel = `${dir}\\${def.id}`
  const q = def.quelle
  const foreign = t(
    `✖ ${def.titel}: der Ordner ${ziel} gibt es schon und er gehört nicht der Mod; er bleibt unberührt (selbst löschen oder einen anderen Werkzeugordner einstellen).`,
    `✖ ${def.titel}: the folder ${ziel} already exists and does not belong to the mod; it is left alone (delete it yourself or choose another checker folder).`,
  )
  let r: Run
  if (q.art === 'zip' || q.art === 'datei' || q.art === 'tar') {
    r = await run(
      $,
      ['powershell', '-NoProfile', '-NonInteractive', '-Command', DOWNLOAD_PS],
      {
        CW_DIR: dir,
        CW_ID: def.id,
        CW_NAME: q.name,
        CW_URL: q.url,
        CW_SHA: q.sha256,
        CW_ZIEL: ziel,
        CW_ART: q.art,
        CW_TEILE: q.art === 'tar' ? q.teile.join('|') : '',
        CW_STRIP: q.art === 'tar' ? String(q.strip) : '0',
      },
      // Höchstwert von Claude Code für process.run: 600000 ms. Mit 900000 lehnte Claude Code 2.1.308 jeden Download ab
      // ("init.timeoutMs is a whole number of ms, 1 to 600000", gemessen 27.10.2026).
      600000,
      dir,
    )
    if (r.ok && /CW_FREMD/.test(r.out)) return foreign
    if (r.ok && /CW_BESETZT/.test(r.out)) {
      return t(`✖ ${def.titel}: wird gerade schon geladen (anderer Chat); bitte danach noch einmal versuchen.`, `✖ ${def.titel}: already being installed (another chat); please try again afterwards.`)
    }
    if (r.ok && /CW_ZIP_UNSICHER/.test(r.out)) {
      return t(`✖ ${def.titel}: das Paket enthält Pfade außerhalb des Zielordners, verworfen (nichts geladen).`, `✖ ${def.titel}: the archive contains paths outside the target folder, discarded (nothing installed).`)
    }
    if (r.ok && /CW_SHA_FALSCH/.test(r.out)) {
      return t(`✖ ${def.titel}: Prüfsumme stimmt nicht, Datei verworfen (nichts geladen).`, `✖ ${def.titel}: checksum mismatch, file discarded (nothing installed).`)
    }
  } else if (await foreignTarget($, ziel)) {
    return foreign
  } else if (q.art === 'npm') {
    const node = await toolPath($, 'node')
    if (!node) return t(`✖ ${def.titel}: Node.js fehlt (wird zuerst gebraucht).`, `✖ ${def.titel}: Node.js is missing (needed first).`)
    const nodeDir = node.replace(/\\[^\\]+$/, '')
    try {
      // Marke zuerst: der Ordner gehört ab jetzt der Mod, auch wenn das Laden abbricht (ein neuer Versuch darf ihn ersetzen).
      await $.fs.write(`${ziel}\\${TOOL_MARK}`, 'code-waechter\n')
      await $.fs.write(`${ziel}\\package.json`, q.paket)
      await $.fs.write(`${ziel}\\package-lock.json`, q.lock)
    } catch (err) {
      return t(`✖ ${def.titel}: Paketliste nicht schreibbar (${short(String(err))}).`, `✖ ${def.titel}: could not write the package list (${short(String(err))}).`)
    }
    let path = ''
    try {
      path = String((await $.env.get('PATH')) ?? '')
    } catch {
      path = ''
    }
    // npm ci: genau die Fassungen und Prüfsummen der mitgelieferten package-lock.json; passt etwas nicht, bricht es ab.
    r = await run(
      $,
      [node, `${nodeDir}\\node_modules\\npm\\bin\\npm-cli.js`, 'ci', '--prefix', ziel, '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error'],
      { PATH: `${nodeDir};${path}` },
      600000,
      ziel,
    )
  } else if (q.art === 'pip') {
    // Zwischendatei mit eigenem Namen je Ladevorgang, danach gelöscht.
    const req = `${dir}\\_laden_${def.id}_${Date.now().toString(36)}.txt`
    try {
      await $.fs.write(`${ziel}\\${TOOL_MARK}`, 'code-waechter\n')
      await $.fs.write(req, q.pakete.map(p => `${p.spec} ${p.hashes.map(h => `--hash=sha256:${h}`).join(' ')}`).join('\n') + '\n')
    } catch (err) {
      return t(`✖ ${def.titel}: Hilfsdatei nicht schreibbar (${short(String(err))}).`, `✖ ${def.titel}: could not write helper file (${short(String(err))}).`)
    }
    const forPython = q.python ? ['--python-version', q.python, '--implementation', 'cp', '--platform', 'win_amd64'] : []
    r = await run(
      $,
      [...python, '-m', 'pip', 'install', '--target', ziel, '--upgrade', '--require-hashes', '--only-binary=:all:', '--no-deps', ...forPython, '--disable-pip-version-check', '-r', req],
      { PYTHONSAFEPATH: '1' },
      600000,
      dir, // nicht im Projektordner: "python -m" lädt sonst Module aus dem aktuellen Ordner
    )
    await run($, ['powershell', '-NoProfile', '-NonInteractive', '-Command', 'Remove-Item -LiteralPath $env:CW_DATEI -Force -ErrorAction SilentlyContinue'], { CW_DATEI: req }, 20000, dir)
  } else {
    return t(`✖ ${def.titel}: unbekannte Quelle.`, `✖ ${def.titel}: unknown source.`)
  }
  if (!r.ok) return t(`✖ ${def.titel}: konnte nicht laufen (${r.reason}).`, `✖ ${def.titel}: could not run (${r.reason}).`)
  if (!(await toolPath($, def.id))) {
    const why = short(r.out) || t('keine Rückmeldung', 'no output')
    return t(`✖ ${def.titel}: nicht geladen (${why}).`, `✖ ${def.titel}: not installed (${why}).`)
  }
  if (q.art === 'npm' || q.art === 'pip') {
    try {
      await $.fs.write(`${ziel}\\${TOOL_MARK}`, 'code-waechter\n')
    } catch {
      // ohne Marke wird der Ordner später nur nicht ersetzt
    }
  }
  return t(`✔ ${def.titel} ${def.version} geladen.`, `✔ ${def.titel} ${def.version} installed.`)
}

// Übersicht für den Befehl: was da ist, was fehlt.
export async function toolOverview($: any): Promise<string> {
  let dir = ''
  try {
    dir = await toolDir($)
  } catch (err) {
    return `${t('Code-Wächter Prüfprogramme', 'Code Guard checkers')}: ${short(String((err as { message?: string })?.message ?? err))}`
  }
  const lines = [t(`Code-Wächter Prüfprogramme (Ordner: ${dir})`, `Code Guard checkers (folder: ${dir})`)]
  for (const d of TOOLS) {
    const have = await toolPath($, d.id)
    const what = t(d.wofuer[0], d.wofuer[1])
    lines.push(
      have
        ? `  ✔ ${d.id.padEnd(10)} ${d.titel} ${d.version} – ${what}`
        : `  ✖ ${d.id.padEnd(10)} ${d.titel} ${d.version}, ${d.mb} MB – ${what}`,
    )
  }
  lines.push(
    '',
    t(
      'Laden: /waechter-werkzeuge laden <Name …> oder /waechter-werkzeuge laden alle. Alles direkt vom Hersteller, mit Prüfsumme, ohne Installation.',
      'Install: /waechter-werkzeuge install <name …> or /waechter-werkzeuge install all. Straight from the vendor, checksum-verified, no installation.',
    ),
  )
  return lines.join('\n')
}
