// Zusätzliche C#-Muster für die Sicherheit (27.11.2026, Bauplan freigegeben: "Alle drei Stufen"). Gelesen wird der Code über
// csBereinigt: Kommentare und der Inhalt von Zeichenketten zählen nie als Code. Den Inhalt einer Zeichenkette (SQL-Wörter, Löcher {x}
// in $"...") liest diese Datei an derselben Stelle aus dem Originaltext - csBereinigt lässt Länge und Zeilen gleich.
//
//   CS-SQL        Fehler   SQL-Text aus Teilen zusammengesetzt (+, $"...{x}...", string.Format, string.Concat), darin SELECT...FROM,
//                          INSERT INTO, UPDATE...SET oder DELETE FROM: an CommandText, als erstes Argument von new SqlCommand(...)
//                          und der Befehle der anderen Datenbanken, von ExecuteSqlRaw(Async), FromSqlRaw und SqlQueryRaw - auch über
//                          eine Variable, die in derselben Methode gefüllt wird.
//   CS-RECHTE     Fehler   FileSystemAccessRule / AccessRuleFactory für Jeder, Benutzer oder Authentifizierte Benutzer mit Allow und
//                          FullControl, Modify oder Write.
//   CS-WEBVIEW    Fehler   ExecuteScriptAsync mit zusammengesetztem Text; Hinweis bei AreDevToolsEnabled = true,
//                          AreHostObjectsAllowed = true und AddHostObjectToScript(...).
//   CS-DLL        Hinweis  LoadLibrary, LoadLibraryEx (auch A/W), NativeLibrary.Load/TryLoad mit einem Namen ohne vollen Pfad.
//   CS-TEMPDATEI  Hinweis  Path.GetTempFileName().
//   CS-REGEX      Hinweis  Suchmuster, das kein fester Text und nicht Regex.Escape(...) ist.
//
// Fest (kommt nicht von aussen) ist: eine Zeichenkette ohne Loch, eine Zahl, eine Konstante dieser Datei (const, readonly string mit
// festem Text), nameof(...), Regex.Escape(...), Environment.NewLine, string.Empty und eine lokale Variable, die in ihrem Block bis zur
// Stelle nur Festes bekommt. Ein Methodenparameter, ein Feld ohne festen Text und ein Methodenaufruf zählen als von aussen.
// Prüfdateien (PRUEF_PFAD) bekommen nur Hinweise. Bewusste Stellen: "code-waechter:ok SICHERHEIT" in der Zeile des Fundes.
//
// Diese Datei nutzt die Helfer aus sicherheit.ts nur in Funktionen, nie beim Laden: sicherheit.ts darf sie so ihrerseits einbinden.

import { t } from './i18n'
import { OK_SICHER, PRUEF_PFAD, ausdruckAb, cArgumente, csBereinigt, zeileVon } from './sicherheit'
import type { SFund } from './sicherheit'

// Eine Zeichenkette im Code: start beim ersten $ oder @ davor, ende nach dem schliessenden Anführungszeichen; loecher = Ausdrücke in {...}.
type Lit = { start: number; ende: number; inhalt: string; loecher: string[] }
// sql: ein Textstück enthält SQL-Wörter; zusammen: mit +, Loch oder string.Format/Concat gebaut; dynamisch: ein Teil ist nicht fest.
type Wert = { sql: boolean; zusammen: boolean; dynamisch: boolean }
type Bereich = { von: number; bis: number; plus: boolean }

// ---- CS-SQL. Gemessen 27.11.2026: CA2100 meldet IDbCommand.CommandText mit + nicht, darum eine eigene Regel. Vorbild Sonar S2077
// (github.com/SonarSource/sonar-dotnet, analyzers/rspec/cs/S2077.html: new SqlCommand, CommandText, string.Concat/Format, $"...").
// Nicht gemeldet: FromSql, ExecuteSql(Async), SqlQuery und FromSqlInterpolated nehmen einen FormattableString und machen aus jedem {x}
// einen DbParameter - laut Microsoft "safe against SQL injection" (learn.microsoft.com/ef/core/querying/sql-queries#passing-parameters,
// gelesen 27.11.2026). Für FromSqlRaw und SqlQueryRaw schreibt Microsoft: "never pass a concatenated or interpolated string"
// (learn.microsoft.com/dotnet/api/microsoft.entityframeworkcore.relationaldatabasefacadeextensions.sqlqueryraw).
const SQL_WORTE = /\bSELECT\b[\s\S]*\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b[\s\S]*\bSET\b|\bDELETE\s+FROM\b/i
const SQL_BEFEHL = /\bnew\s+(?:[\w.]+\.)?(?:Sql|Sqlite|SQLite|OleDb|Odbc|Npgsql|MySql)Command\s*\(|\b(?:Sql|Sqlite|SQLite|OleDb|Odbc|Npgsql|MySql)Command\s+@?\w+\s*=\s*new\s*\(/g
const SQL_ROH = /\.\s*(?:ExecuteSqlRawAsync|ExecuteSqlRaw|FromSqlRaw|SqlQueryRaw)\s*(?:<[^<>()]*>)?\s*\(/g
const COMMAND_TEXT = /\bCommandText\s*(\+)?=(?![=>])/g
const ZUSAMMEN_AUFRUF = /\b[Ss]tring\s*\.\s*(?:Format|Concat)\s*\(/

// ---- CS-RECHTE. Vorbild Sonar S2612 (sonar-dotnet, analyzers/rspec/cs/S2612.html): FileSystemAccessRule für "Everyone" mit
// AccessControlType.Allow und FullControl bzw. Write. Dazu die deutschen Namen und die SIDs derselben Gruppen.
const RECHTE_REGEL = /\bnew\s+(?:[\w.]+\.)?FileSystemAccessRule\s*\(|\.\s*AccessRuleFactory\s*\(/g
const JEDER_NAME = /^(?:[^\\]*\\{1,2})?(?:Everyone|Jeder|Authenticated Users|Authentifizierte Benutzer|Users|Benutzer)$/i
const JEDER_SID = /\bWellKnownSidType\s*\.\s*(?:WorldSid|AuthenticatedUserSid|BuiltinUsersSid)\b/
const RECHTE_WEIT = /\bFileSystemRights\s*\.\s*(?:FullControl|Modify|Write)\b/
const ERLAUBT = /\bAccessControlType\s*\.\s*Allow\b/

// ---- CS-WEBVIEW. Microsoft: "Avoid ExecuteScriptAsync with user-provided strings ... use PostWebMessageAsJson instead"
// (learn.microsoft.com/windows/apps/develop/ui/controls/webview2#security-best-practices); "Set AreHostObjectsAllowed to false, if you
// don't expect the web content to access host objects" (learn.microsoft.com/microsoft-edge/webview2/concepts/security).
const SKRIPT = /\bExecuteScriptAsync\s*\(/g
const WV_SCHALTER = /\b(AreDevToolsEnabled|AreHostObjectsAllowed)\s*=\s*true\b/g
const HOST_OBJEKT = /\bAddHostObjectToScript\s*\(/g

// ---- CS-DLL. Microsoft: ohne vollen Pfad sucht Windows die DLL in mehreren Ordnern, auch im aktuellen Ordner ("DLL preloading
// attack"); "specify a fully qualified path" oder LoadLibraryEx mit den LOAD_LIBRARY_SEARCH-Schaltern
// (learn.microsoft.com/windows/win32/dlls/dynamic-link-library-security, gelesen 27.11.2026).
const DLL_LADEN = /\b(LoadLibrary(?:Ex)?[AW]?)\s*\(|\bNativeLibrary\s*\.\s*(Load|TryLoad)\s*\(/g
const VOLLER_PFAD = /^(?:[A-Za-z]:[\\/]|\\\\|\/)/
const SUCHE_FEST = /LOAD_?LIBRARY_?SEARCH/i

// ---- CS-TEMPDATEI. Vorbild Sonar S5445 (sonar-dotnet, analyzers/rspec/cs/S5445.html): der Name steht fest, bevor die Datei angelegt
// ist - ein anderes Programm kann sie dazwischen anlegen. Ersatz laut Sonar: Path.GetRandomFileName() mit FileMode.CreateNew.
const TEMPDATEI = /\bPath\s*\.\s*GetTempFileName\s*\(/g

// ---- CS-REGEX. Microsoft: "applications should not create regular expression patterns from untrusted user-provided values";
// fremden Text mit Regex.Escape einsetzen (learn.microsoft.com/dotnet/standard/base-types/best-practices-regex#use-trusted-patterns,
// CA3012). Bei den statischen Methoden ist das Muster das zweite Argument, bei new Regex das erste.
const REGEX_NEU = /\bnew\s+(?:[\w.]+\.)?Regex\s*\(|\bRegex\s+@?\w+\s*=\s*new\s*\(/g
const REGEX_STATISCH = /(?<![\w.])(?:System\s*\.\s*Text\s*\.\s*RegularExpressions\s*\.\s*)?Regex\s*\.\s*(?:IsMatch|Matches|Match|Replace|Split)\s*\(/g

// Teile, die nie von aussen kommen: Schlüsselwörter, Typnamen, string.Format/Concat/Join selbst (deren Argumente zählen einzeln).
const NEUTRAL = new Set(['true', 'false', 'null', 'new', 'typeof', 'sizeof', 'default', 'is', 'as', 'checked', 'unchecked', 'await', 'int', 'long', 'short', 'byte', 'sbyte', 'uint', 'ulong', 'ushort', 'char', 'bool', 'double', 'float', 'decimal', 'string', 'String', 'object', 'var'])
const NEUTRAL_KETTE = /^(?:Environment\.NewLine|CultureInfo\.(?:InvariantCulture|CurrentCulture)|[Ss]tring\.Empty)$/
const FESTER_AUFRUF = /(?:\bSystem\s*\.\s*Text\s*\.\s*RegularExpressions\s*\.\s*)?\bRegex\s*\.\s*Escape\s*\(|\bnameof\s*\(/g
const ESCAPE_LISTE = /(?<![\w.])@?[A-Za-z_][\w.]*\s*\.\s*Select\s*\(\s*(?:(?:System\s*\.\s*Text\s*\.\s*RegularExpressions\s*\.\s*)?Regex\s*\.\s*Escape|(\w+)\s*=>\s*Regex\s*\.\s*Escape\s*\(\s*\1\s*\))\s*\)/g
const KETTE = /(?<![\w$@.])@?[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*/g
// Typen, unter denen eine lokale Variable einen Text bzw. eine Kennung oder ein Recht hält.
const TEXT_TYP = '(?:var|string|String)'
const RECHTE_TYP = '(?:var|string|String|SecurityIdentifier|NTAccount|IdentityReference|FileSystemRights|AccessControlType)'
// Wie tief eine Variable über andere Variablen verfolgt wird; tiefer zählt sie als von aussen.
const MAX_STUFE = 3

// Ausdruck in einem Loch {x} einer $"..."-Zeichenkette: Texte darin geleert, ohne Format (:N2) und Breite (,10) - in C# stehen ?: im
// Loch immer in Klammern.
function lochAusdruck(s: string): string {
  const ohne = s.replace(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g, m => ' '.repeat(m.length))
  let d = 0
  for (let k = 0; k < ohne.length; k++) {
    const c = ohne[k] ?? ''
    if ('([{'.includes(c)) d++
    else if (')]}'.includes(c)) d--
    else if ((c === ':' || c === ',') && d === 0) return ohne.slice(0, k)
  }
  return ohne
}

// Löcher einer $"..."-Zeichenkette: bei einem $ öffnet { ein Loch ({{ ist ein Zeichen), bei $$ öffnen erst {{ usw. (rohe Texte """).
function loecher(inhalt: string, dollar: number): string[] {
  const out: string[] = []
  let i = 0
  while (i < inhalt.length) {
    if (inhalt[i] !== '{') {
      i++
      continue
    }
    let r = 0
    while (inhalt[i + r] === '{') r++
    i += r
    if (dollar === 1 ? r % 2 === 0 : r < dollar) continue
    let d = 1
    let k = i
    for (; k < inhalt.length; k++) {
      if (inhalt[k] === '{') d++
      else if (inhalt[k] === '}' && --d === 0) break
    }
    out.push(lochAusdruck(inhalt.slice(i, k)))
    i = k + 1
  }
  return out
}

// Alle Zeichenketten der Datei. Im bereinigten Code stehen nur noch die Anführungszeichen, der Inhalt kommt aus dem Originaltext.
// Wie csBereinigt: eine gewöhnliche Zeichenkette endet spätestens am Zeilenende, eine wörtliche (@) nicht, eine rohe an """.
function zeichenketten(text: string, code: string): Lit[] {
  const out: Lit[] = []
  let i = 0
  for (;;) {
    const k = code.indexOf('"', i)
    if (k === -1) break
    let p = k
    while (p > 0 && (code[p - 1] === '$' || code[p - 1] === '@')) p--
    const vor = code.slice(p, k)
    const dollar = vor.split('$').length - 1
    let auf = k + 1
    let zu: number
    let ende: number
    if (code.startsWith('"""', k)) {
      auf = k + 3
      const e = code.indexOf('"""', auf)
      zu = e === -1 ? code.length : e
      ende = Math.min(code.length, zu + 3)
    } else {
      const e = code.indexOf('"', auf)
      const nl = code.indexOf('\n', auf)
      zu = e === -1 ? (nl === -1 ? code.length : nl) : e
      if (!vor.includes('@') && nl !== -1 && nl < zu) zu = nl
      ende = code[zu] === '"' ? zu + 1 : zu
    }
    const inhalt = text.slice(auf, zu)
    out.push({ start: p, ende, inhalt, loecher: dollar > 0 ? loecher(inhalt, dollar) : [] })
    i = Math.max(ende, k + 1)
  }
  return out
}

// Regex.Escape(...) und nameof(...) samt Klammerinhalt durch Leerzeichen ersetzen: sie liefern nie fremden Code ins Muster bzw. den Text.
// Ebenso x.Select(Regex.Escape) und x.Select(v => Regex.Escape(v)): jedes Stück ist geschützt (gemessen 27.11.2026:
// ein Programm setzt so string.Join("|", ...) zusammen).
function festeAufrufeLeeren(text: string): string {
  const s = text.replace(ESCAPE_LISTE, m => m.replace(/[^\n]/g, ' '))
  const o = s.split('')
  for (const m of s.matchAll(FESTER_AUFRUF)) {
    const a = m.index ?? 0
    let d = 0
    let k = a + m[0].length - 1
    for (; k < s.length; k++) {
      if (s[k] === '(') d++
      else if (s[k] === ')' && --d === 0) break
    }
    for (let x = a; x <= k && x < o.length; x++) if (o[x] !== '\n') o[x] = ' '
  }
  return o.join('')
}

// Die Bedingung vor ? in "b ? x : y" leeren: sie wählt nur aus, der Wert ist x oder y (gemessen 27.11.2026: Prüfprogramm eines Chatbots,
// Zeile 10759, "..." + Regex.Escape(w) + (w.Length <= 3 ? "..." : "") zählte sonst als fremdes Muster). ?? ?. ?[ und int? bleiben.
function bedingungenLeeren(s: string): string {
  const o = s.split('')
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '?' || s[i - 1] === '?' || /[?.[)>,]/.test(s[i + 1] ?? '')) continue
    let d = 0
    let k = i - 1
    for (; k >= 0; k--) {
      const c = s[k] ?? ''
      if (c === ')' || c === ']' || c === '}') d++
      else if (c === '(' || c === '[' || c === '{') {
        if (d === 0) break
        d--
      } else if (d === 0 && (c === ',' || c === ';' || c === ':' || c === '?' || (c === '=' && !/[=!<>]/.test(s[k - 1] ?? '') && s[k + 1] !== '='))) break
    }
    for (let x = k + 1; x < i; x++) if (o[x] !== '\n') o[x] = ' '
  }
  return o.join('')
}

export function csZusatzMuster(text: string, file: string): SFund[] {
  const pruef = PRUEF_PFAD.test(file)
  const code = csBereinigt(text)
  const roh = text.split(/\r?\n/)
  const lits = zeichenketten(text, code)
  // Tiefe der geschweiften Klammern vor jeder Stelle: eine lokale Variable gilt nur in dem Block, in dem sie erklärt wird.
  const tiefe = new Int32Array(code.length + 1)
  for (let k = 0, d = 0; k < code.length; k++) {
    if (code[k] === '{') d++
    else if (code[k] === '}') d = Math.max(0, d - 1)
    tiefe[k + 1] = d
  }
  const umschliesst = (d: number, p: number): boolean => {
    const t0 = tiefe[d] ?? 0
    for (let k = d; k <= p && k < tiefe.length; k++) if ((tiefe[k] ?? 0) < t0) return false
    return true
  }
  const drinnen = (von: number, bis: number): Lit[] => lits.filter(l => l.start >= von && l.ende <= bis)

  // Zuweisungen an eine lokale Variable vor der Stelle at (Erklärung mit Startwert, x = ..., x += ...). undefined: keine Erklärung im
  // umschliessenden Block (Feld oder unbekannt). Ein Parameter oder foreach (var x in ...) hat keine Zuweisung.
  const zuweisungen = (name: string, at: number, typ: string): Bereich[] | undefined => {
    let decl = -1
    for (const m of code.slice(0, at).matchAll(new RegExp(String.raw`\b${typ}\??\s+@?${name}\b(?!\s*[(<])`, 'g'))) {
      if (umschliesst(m.index ?? 0, at)) decl = m.index ?? 0
    }
    if (decl < 0) return undefined
    const out: Bereich[] = []
    for (const m of code.slice(decl, at).matchAll(new RegExp(String.raw`(?<![\w.])@?${name}\s*(\+)?=(?![=>])`, 'g'))) {
      const von = decl + (m.index ?? 0) + m[0].length
      const bis = von + ausdruckAb(code, von).length
      if (bis <= at) out.push({ von, bis, plus: m[1] === '+' })
    }
    return out
  }

  const fest = new Set<string>()
  const lokal = (name: string, at: number, stufe: number): Wert | undefined => {
    const z = zuweisungen(name, at, TEXT_TYP)
    if (z === undefined) return undefined
    const w: Wert = { sql: false, zusammen: false, dynamisch: z.length === 0 || stufe >= MAX_STUFE }
    if (stufe >= MAX_STUFE) return w
    for (const b of z) {
      const r = bewerten(b.von, b.bis, stufe + 1)
      w.sql ||= r.sql
      w.zusammen ||= r.zusammen || b.plus
      w.dynamisch ||= r.dynamisch
    }
    return w
  }
  // Die Namen eines Ausdrucks (Zeichenketten schon geleert) einzeln einordnen; at: Stelle für die Suche nach lokalen Variablen.
  const teile = (s: string, at: number, stufe: number, w: Wert) => {
    for (const m of s.matchAll(KETTE)) {
      const i = m.index ?? 0
      if (/\bnew\s*$/.test(s.slice(Math.max(0, i - 8), i))) continue
      const kette = m[0].replace(/\s+/g, '').replace(/^@/, '').replace(/^(?:this|System)\./, '')
      const kopf = kette.split('.')[0] ?? ''
      if (NEUTRAL.has(kopf) || NEUTRAL_KETTE.test(kette)) continue
      const aufruf = /^\s*[(<]/.test(s.slice(i + m[0].length))
      if (!aufruf && fest.has(kette.split('.').pop() ?? '')) continue
      if (!aufruf && !kette.includes('.')) {
        const v = lokal(kette, at, stufe)
        if (v) {
          w.sql ||= v.sql
          w.zusammen ||= v.zusammen
          w.dynamisch ||= v.dynamisch
          continue
        }
      }
      w.dynamisch = true
    }
  }
  function bewerten(von: number, bis: number, stufe: number): Wert {
    const w: Wert = { sql: false, zusammen: false, dynamisch: false }
    const drin = drinnen(von, bis)
    if (SQL_WORTE.test(drin.map(l => l.inhalt).join(' '))) w.sql = true
    const s = code.slice(von, bis).split('')
    for (const l of drin) for (let k = l.start; k < l.ende; k++) s[k - von] = ' '
    const ohne = bedingungenLeeren(festeAufrufeLeeren(s.join('')))
    if (/\+/.test(ohne) || drin.some(l => l.loecher.length > 0) || ZUSAMMEN_AUFRUF.test(ohne)) w.zusammen = true
    teile(ohne, von, stufe, w)
    for (const l of drin) for (const loch of l.loecher) teile(bedingungenLeeren(festeAufrufeLeeren(loch)), l.start, stufe, w)
    return w
  }
  // Konstanten dieser Datei; readonly string nur mit festem Startwert (ohne Verfolgung lokaler Variablen).
  for (const m of code.matchAll(/\bconst\s+[\w.?<>[\]]+\s+@?(\w+)\s*=/g)) fest.add(m[1] ?? '')
  for (const m of code.matchAll(/\breadonly\s+(?:static\s+)?(?:string|String)\s+@?(\w+)\s*=/g)) {
    const von = (m.index ?? 0) + m[0].length
    if (!bewerten(von, von + ausdruckAb(code, von).length, MAX_STUFE).dynamisch) fest.add(m[1] ?? '')
  }

  // Argumente eines Aufrufs mit ihrer Stelle im Code (offen = Stelle der öffnenden Klammer).
  const argumente = (offen: number): { von: number; bis: number }[] => {
    const out: { von: number; bis: number }[] = []
    let von = offen + 1
    for (const s of cArgumente(code, offen)) {
      out.push({ von, bis: von + s.length })
      von += s.length + 1
    }
    return out
  }
  // Der einzige Inhalt eines Arguments, wenn es genau eine Zeichenkette ohne Loch ist.
  const nurText = (von: number, bis: number): string | undefined => {
    const drin = drinnen(von, bis)
    const l = drin[0]
    if (drin.length !== 1 || !l || l.loecher.length > 0) return undefined
    return (code.slice(von, l.start) + code.slice(l.ende, bis)).trim() === '' ? l.inhalt : undefined
  }
  const einzelName = (von: number, bis: number): string | undefined => /^\s*@?([A-Za-z_]\w*)\s*$/.exec(code.slice(von, bis))?.[1]

  const funde: SFund[] = []
  const gemeldet = new Set<string>()
  const melden = (at: number, kennung: string, rot: boolean, de: string, en: string) => {
    const nr = zeileVon(code, at)
    if (gemeldet.has(`${kennung}|${nr}`) || OK_SICHER.test(roh[nr - 1] ?? '')) return
    gemeldet.add(`${kennung}|${nr}`)
    funde.push({ line: nr, col: at - code.lastIndexOf('\n', at - 1), code: kennung, text: t(de, en), schwer: rot && !pruef, scanner: t('Muster', 'pattern') })
  }

  // CS-SQL
  const sqlPruefen = (at: number, von: number, bis: number, plus: boolean) => {
    const w = bewerten(von, bis, 0)
    if (!w.sql || !(w.zusammen || plus) || !w.dynamisch) return
    melden(at, 'CS-SQL', true,
      'SQL-Text wird aus Teilen zusammengesetzt (+, $"…{x}…", string.Format/Concat) - ein Wert von aussen wird so zum SQL-Befehl (SQL-Einschleusung). Werte als Parameter übergeben (@name mit Parameters.AddWithValue; bei EF Core FromSql/ExecuteSql mit $"…").',
      'SQL text is built from parts (+, $"…{x}…", string.Format/Concat) - an outside value becomes an SQL command (SQL injection). Pass values as parameters (@name with Parameters.AddWithValue; with EF Core FromSql/ExecuteSql with $"…").')
  }
  for (const m of code.matchAll(COMMAND_TEXT)) {
    const von = (m.index ?? 0) + m[0].length
    sqlPruefen(m.index ?? 0, von, von + ausdruckAb(code, von).length, m[1] === '+')
  }
  for (const re of [SQL_BEFEHL, SQL_ROH]) {
    for (const m of code.matchAll(re)) {
      const a = argumente((m.index ?? 0) + m[0].length - 1)[0]
      if (a) sqlPruefen(m.index ?? 0, a.von, a.bis, false)
    }
  }

  // CS-RECHTE: Kennung im ersten Argument, Recht und Allow in den übrigen - direkt oder über eine lokale Variable.
  for (const m of code.matchAll(RECHTE_REGEL)) {
    const args = argumente((m.index ?? 0) + m[0].length - 1)
    if (args.length < 3) continue
    const mitVariable = (a: { von: number; bis: number }): { von: number; bis: number }[] => {
      const name = einzelName(a.von, a.bis)
      return [a, ...(name ? zuweisungen(name, a.von, RECHTE_TYP) ?? [] : [])]
    }
    const wer = mitVariable(args[0] ?? { von: 0, bis: 0 })
    const jeder = wer.some(r => JEDER_SID.test(code.slice(r.von, r.bis)) || drinnen(r.von, r.bis).some(l => JEDER_NAME.test(l.inhalt.trim())))
    const rest = args.slice(1).flatMap(mitVariable).map(r => code.slice(r.von, r.bis)).join(' ')
    if (jeder && RECHTE_WEIT.test(rest) && ERLAUBT.test(rest)) {
      melden(m.index ?? 0, 'CS-RECHTE', true,
        'gibt allen (Jeder, Benutzer oder Authentifizierte Benutzer) Schreib- oder Vollzugriff - so kann jedes Programm auf dem PC die Datei oder den Ordner verändern oder austauschen. Rechte nur dem eigenen Konto oder den Administratoren geben, allen höchstens Lesen.',
        'gives everyone (Everyone, Users or Authenticated Users) write or full access - any program on the PC can change or replace the file or folder. Grant rights only to your own account or administrators, everyone at most read.')
    }
  }

  // CS-WEBVIEW
  for (const m of code.matchAll(SKRIPT)) {
    const a = argumente((m.index ?? 0) + m[0].length - 1)[0]
    if (!a) continue
    const w = bewerten(a.von, a.bis, 0)
    if (w.zusammen && w.dynamisch) {
      melden(m.index ?? 0, 'CS-WEBVIEW', true,
        'ExecuteScriptAsync bekommt zusammengesetzten Text - ein Wert von aussen wird so zu JavaScript, das im Fenster läuft. Werte mit PostWebMessageAsJson schicken, nicht ins Skript einbauen.',
        'ExecuteScriptAsync gets concatenated text - an outside value becomes JavaScript that runs in the window. Send values with PostWebMessageAsJson, do not build them into the script.')
    }
  }
  for (const m of code.matchAll(WV_SCHALTER)) {
    if (m[1] === 'AreDevToolsEnabled') {
      melden(m.index ?? 0, 'CS-WEBVIEW', false,
        'AreDevToolsEnabled = true: im WebView2-Fenster lassen sich die Entwicklerwerkzeuge öffnen und beliebige Skripte ausführen. In der ausgelieferten Fassung auf false setzen.',
        'AreDevToolsEnabled = true: the developer tools can be opened in the WebView2 window and any script can be run. Set it to false in the shipped version.')
    } else {
      melden(m.index ?? 0, 'CS-WEBVIEW', false,
        'AreHostObjectsAllowed = true: Skripte der Seite dürfen C#-Objekte aufrufen. Auf false setzen, wenn die Seite keine Host-Objekte braucht.',
        'AreHostObjectsAllowed = true: scripts of the page may call C# objects. Set it to false if the page needs no host objects.')
    }
  }
  for (const m of code.matchAll(HOST_OBJEKT)) {
    melden(m.index ?? 0, 'CS-WEBVIEW', false,
      'AddHostObjectToScript gibt den Skripten der Seite Zugriff auf ein C#-Objekt - nur für eigene, feste Seiten verwenden und vor jedem Zugriff die Herkunft der Seite (Source) prüfen.',
      'AddHostObjectToScript gives the scripts of the page access to a C# object - use it only for your own fixed pages and check the origin of the page (Source) before each access.')
  }

  // CS-DLL: nur wenn der Name sichtbar ist (Zeichenkette oder lokale Variable mit Zeichenkette) und kein voller Pfad.
  for (const m of code.matchAll(DLL_LADEN)) {
    const args = argumente((m.index ?? 0) + m[0].length - 1)
    const a = args[0]
    if (!a) continue
    if (m[1]?.startsWith('LoadLibraryEx') && SUCHE_FEST.test(code.slice(args[2]?.von ?? 0, args[2]?.bis ?? 0))) continue
    const name = einzelName(a.von, a.bis)
    const z = name ? zuweisungen(name, a.von, TEXT_TYP) : [a]
    const namen = (z ?? []).map(r => nurText(r.von, r.bis))
    if (namen.length === 0 || namen.some(n => n === undefined || VOLLER_PFAD.test(n))) continue
    const wer = m[1] ?? `NativeLibrary.${m[2] ?? 'Load'}`
    melden(m.index ?? 0, 'CS-DLL', false,
      `${wer}() lädt eine DLL nur über ihren Namen - Windows sucht sie dann in mehreren Ordnern, auch im aktuellen, und lädt eine dort untergeschobene DLL. Den vollen Pfad angeben (z. B. Path.Combine(AppContext.BaseDirectory, …)) oder LoadLibraryEx mit LOAD_LIBRARY_SEARCH_SYSTEM32.`,
      `${wer}() loads a DLL by its name only - Windows then searches several folders, including the current one, and loads a DLL planted there. Give the full path (e.g. Path.Combine(AppContext.BaseDirectory, …)) or use LoadLibraryEx with LOAD_LIBRARY_SEARCH_SYSTEM32.`)
  }

  // CS-TEMPDATEI
  for (const m of code.matchAll(TEMPDATEI)) {
    melden(m.index ?? 0, 'CS-TEMPDATEI', false,
      'Path.GetTempFileName() wählt den Namen, bevor die Datei angelegt ist - ein anderes Programm kann sie dazwischen anlegen und mitlesen. Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()) mit FileMode.CreateNew verwenden.',
      'Path.GetTempFileName() picks the name before the file exists - another program can create it in between and read along. Use Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()) with FileMode.CreateNew.')
  }

  // CS-REGEX
  const regexPruefen = (at: number, a: { von: number; bis: number } | undefined) => {
    if (!a || !bewerten(a.von, a.bis, 0).dynamisch) return
    melden(at, 'CS-REGEX', false,
      'Suchmuster ist kein fester Text - fremder Text als Muster kann das Programm lange blockieren oder Falsches finden. Festes Muster verwenden oder den Text mit Regex.Escape(...) einsetzen.',
      'the pattern is not fixed text - outside text as a pattern can block the program for a long time or match the wrong things. Use a fixed pattern or insert the text with Regex.Escape(...).')
  }
  for (const m of code.matchAll(REGEX_NEU)) regexPruefen(m.index ?? 0, argumente((m.index ?? 0) + m[0].length - 1)[0])
  for (const m of code.matchAll(REGEX_STATISCH)) regexPruefen(m.index ?? 0, argumente((m.index ?? 0) + m[0].length - 1)[1])

  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}
