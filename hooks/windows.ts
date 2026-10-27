// Windows-Programme (C# und WPF): Fehler, die das Übersetzen ohne Meldung durchlässt und die erst beim Ausführen abstürzen.
// Alles hier liest nur Text; kein Programm wird gestartet.
//
// Gemessen am 25.10.2026 mit .NET 10 an eigenen Probeprogrammen (XamlReader, jeder Wert einzeln):
//   - C#: Ein einzelner Buchstabe als Format ("H", "Q") ist für .NET ein Kurzformat. Gibt es das Kurzformat nicht, kommt beim
//     Ausführen FormatException: bei ToString, $"{x:H}", "{0:H}", ParseExact und sogar bei TryParseExact. Mit "%H" läuft es.
//   - C#: int.Parse, Convert.ToInt32 und Verwandte stürzen bei leerem oder falschem Text ab; .Text ist eine Eingabe der Oberfläche.
//   - XAML: Werte wie Width="12x", Margin="1,2,3", Grid.Row="a", Background="Rot" oder FontWeight="Fett" übersetzt WPF ohne Meldung,
//     das Fenster stürzt aber beim Öffnen ab. Ebenso ein StaticResource-Name, den es nicht gibt, und ein Stil, der als Farbe dient.
//     210 Musterwerte wurden von .NET beurteilt (80 Abstürze); die Regeln hier melden genau die Werte, die abstürzen.
//
// Windows programs (C# and WPF): mistakes the build lets through that crash at run time. Text only, nothing is started.

import { t } from './i18n'
import { lineOf, lineStarts, stripComments } from './spiele'

export type WinFinding = { file: string; line: number; col: number; code: string; text: string }

// Text aus der Datei in einer Meldung: in «…», ohne Steuerzeichen, gekürzt.
function q(s: string): string {
  const x = s.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, ' ').replace(/[«»]/g, '"')
  return `«${x.length > 60 ? `${x.slice(0, 59)}…` : x}»`
}

// Eine absichtlich so geschriebene Stelle: Kommentar in derselben Zeile, z. B. "// code-waechter:ok CW-PARSE".
function allowed(lines: string[], line: number, code: string): boolean {
  for (const m of (lines[line - 1] ?? '').matchAll(/code-waechter:ok\s+(CW-[A-Z-]+)/g)) if (m[1] === code) return true
  return false
}

// ====================================================================================== C#: Formate
// Gültige Kurzformate je Datentyp, von .NET selbst gemeldet (jeder Buchstabe A-Z und a-z einzeln probiert).
const FORMATS = {
  date: 'DFGMORTUYdfgmorstuy',
  dateOffset: 'DFGMORTYdfgmorstuy',
  timeSpan: 'GTcgt',
  dateOnly: 'DMORYdmory',
  timeOnly: 'ORTort',
  // Datentyp unbekannt (Zahl, Datum, Zeitspanne, Guid, enum): gemeldet wird nur ein Buchstabe, der für keinen gilt
  any: 'BCDEFGMNOPRTUXYbcdefgmnoprstuxy',
}
type FormatKind = keyof typeof FORMATS
const TYPE_FORMAT: Record<string, FormatKind> = {
  DateTime: 'date',
  DateTimeOffset: 'dateOffset',
  TimeSpan: 'timeSpan',
  DateOnly: 'dateOnly',
  TimeOnly: 'timeOnly',
}

function badShortFormat(fmt: string, kind: FormatKind): boolean {
  return /^[A-Za-z]$/.test(fmt) && !FORMATS[kind].includes(fmt)
}

function formatText(fmt: string, kind: FormatKind): string {
  const valid = FORMATS[kind].split('').join(' ')
  return kind === 'any'
    ? t(
        `Format ${q(fmt)}: ein einzelner Buchstabe gilt in .NET als Kurzformat, und dieses gibt es für keinen Datentyp – das stürzt beim Ausführen ab (FormatException). Für das Zeichen allein ${q(`%${fmt}`)} schreiben`,
        `format ${q(fmt)}: a single letter is a standard format in .NET and this one exists for no type – it crashes at run time (FormatException). For the character alone write ${q(`%${fmt}`)}`,
      )
    : t(
        `Format ${q(fmt)}: ein einzelner Buchstabe gilt in .NET als Kurzformat, und dieses gibt es hier nicht – das stürzt beim Ausführen ab (FormatException). Für das Zeichen allein ${q(`%${fmt}`)} schreiben. Gültige Kurzformate: ${valid}`,
        `format ${q(fmt)}: a single letter is a standard format in .NET and this one does not exist here – it crashes at run time (FormatException). For the character alone write ${q(`%${fmt}`)}. Valid standard formats: ${valid}`,
      )
}

// Datum von jetzt: DateTime.Now, DateTimeOffset.UtcNow ...; sonst ist der Datentyp unbekannt.
function receiverKind(before: string): FormatKind {
  const m = /\b(DateTime|DateTimeOffset)\s*\.\s*(?:Now|UtcNow|Today)\s*$/.exec(before)
  return m ? TYPE_FORMAT[m[1]] : 'any'
}

type Literal = { start: number; end: number; interp: boolean; holes: { start: number; end: number }[] }

// Alle Texte ("...", @"...", $"...", $@"...", """...""") mit Anfang und Ende; bei $-Texten die Platzhalter {…}.
// Texte mit $$ (Platzhalter in doppelten Klammern) werden nicht zerlegt.
function literals(src: string): Literal[] {
  const out: Literal[] = []
  const n = src.length
  let i = 0
  while (i < n) {
    const c = src[i]
    if (c === "'") {
      // Zeichen wie 'a', '\'', '"'
      i++
      while (i < n && src[i] !== "'" && src[i] !== '\n') i += src[i] === '\\' ? 2 : 1
      i++
      continue
    }
    if (c !== '"') {
      i++
      continue
    }
    let p = i - 1
    let dollars = 0
    let verbatim = false
    while (p >= 0 && (src[p] === '$' || src[p] === '@')) {
      if (src[p] === '$') dollars++
      else verbatim = true
      p--
    }
    let quotes = 0
    while (src[i + quotes] === '"') quotes++
    if (quotes >= 3) {
      const close = src.indexOf('"'.repeat(quotes), i + quotes)
      const end = close < 0 ? n : close + quotes
      out.push({ start: i, end, interp: false, holes: [] })
      i = end
      continue
    }
    const lit: Literal = { start: i, end: n, interp: dollars === 1, holes: [] }
    i++
    while (i < n) {
      const x = src[i]
      if (verbatim && x === '"' && src[i + 1] === '"') {
        i += 2
        continue
      }
      if (!verbatim && x === '\\') {
        i += 2
        continue
      }
      if (x === '"' || (!verbatim && !lit.interp && x === '\n')) break
      if (lit.interp && x === '{') {
        if (src[i + 1] === '{') {
          i += 2
          continue
        }
        const end = holeEnd(src, i)
        lit.holes.push({ start: i + 1, end })
        i = end + 1
        continue
      }
      i++
    }
    lit.end = Math.min(n, i + 1)
    out.push(lit)
    i = lit.end
  }
  return out
}

// Ende eines Platzhalters {…}: die passende schliessende Klammer, Texte und Klammern darin übersprungen.
function holeEnd(src: string, open: number): number {
  let depth = 0
  for (let i = open; i < src.length; i++) {
    const x = src[i]
    if (x === '"') {
      i++
      while (i < src.length && src[i] !== '"' && src[i] !== '\n') i += src[i] === '\\' ? 2 : 1
      continue
    }
    if (x === '{' || x === '(' || x === '[') depth++
    else if (x === '}' || x === ')' || x === ']') {
      depth--
      if (depth === 0) return i
    }
  }
  return src.length - 1
}

// Format eines Platzhalters: der Text nach dem ersten Doppelpunkt auf oberster Ebene (nicht "::").
function holeFormat(src: string, start: number, end: number): { expr: string; fmt: string; at: number } | undefined {
  let depth = 0
  for (let i = start; i < end; i++) {
    const x = src[i]
    if (x === '"') {
      i++
      while (i < end && src[i] !== '"') i += src[i] === '\\' ? 2 : 1
      continue
    }
    if (x === '(' || x === '[' || x === '{') depth++
    else if (x === ')' || x === ']' || x === '}') depth--
    else if (x === ':' && depth === 0) {
      if (src[i + 1] === ':') {
        i++
        continue
      }
      return { expr: src.slice(start, i).replace(/,\s*-?\d+\s*$/, '').trim(), fmt: src.slice(i + 1, end), at: i + 1 }
    }
  }
  return undefined
}

// Die Argumente eines Aufrufs ab der öffnenden Klammer, als Bereiche; Struktur aus bare (Texte geleert), Inhalt aus kept.
function callArgs(bare: string, open: number): { start: number; end: number }[] {
  const args: { start: number; end: number }[] = []
  let depth = 0
  let from = open + 1
  for (let i = open; i < bare.length; i++) {
    const x = bare[i]
    if (x === '(' || x === '[' || x === '{') depth++
    else if (x === ')' || x === ']' || x === '}') {
      depth--
      if (depth === 0) {
        if (bare.slice(from, i).trim() !== '' || args.length > 0) args.push({ start: from, end: i })
        return args
      }
    } else if (x === ',' && depth === 1) {
      args.push({ start: from, end: i })
      from = i + 1
    }
  }
  return args
}

// Die Formate eines ParseExact-Arguments: ein Text ("H"), eine Liste im Aufruf (new[] { … }, [ … ]) oder eine Variable,
// deren Festlegung in derselben Datei steht (string[] Formen = { … }; string f = "…";). Gemessen: auch ein einziges ungültiges
// Format in einer Liste stürzt ab, sobald die Eingabe zu keinem früheren Format passt ("14:30" läuft, "14" stürzt ab).
function exactFormats(kept: string, bare: string, arg: { start: number; end: number }): { fmt: string; at: number }[] {
  const literalsIn = (from: number, to: number): { fmt: string; at: number }[] =>
    [...kept.slice(from, to).matchAll(/@?"([^"\\\n]*)"/g)].map(m => ({ fmt: m[1], at: from + (m.index ?? 0) }))
  const text = kept.slice(arg.start, arg.end).trim()
  if (/^@?"[^"\\]*"$/.test(text) || /[{[]/.test(text)) return literalsIn(arg.start, arg.end)
  const name = /^(?:this\s*\.\s*)?([A-Za-z_]\w*)$/.exec(text)?.[1]
  if (!name) return []
  const one = new RegExp(`\\b${name}\\s*=\\s*@?"([^"\\\\\\n]*)"\\s*;`).exec(kept)
  if (one) return [{ fmt: one[1], at: (one.index ?? 0) + one[0].indexOf('"') }]
  const list = new RegExp(`\\b${name}\\s*=\\s*(?:new\\s*(?:string)?\\s*\\[\\s*\\]\\s*)?[{[]`).exec(kept)
  if (!list) return []
  const open = (list.index ?? 0) + list[0].length - 1
  let depth = 0
  for (let i = open; i < bare.length; i++) {
    if (bare[i] === '{' || bare[i] === '[') depth++
    else if ((bare[i] === '}' || bare[i] === ']') && --depth === 0) return literalsIn(open, i)
  }
  return []
}

// Bereiche aller try { … }-Blöcke.
function tryBlocks(bare: string): { start: number; end: number }[] {
  const out: { start: number; end: number }[] = []
  for (const m of bare.matchAll(/\btry\s*\{/g)) {
    const open = (m.index ?? 0) + m[0].length - 1
    let depth = 0
    for (let i = open; i < bare.length; i++) {
      if (bare[i] === '{') depth++
      else if (bare[i] === '}' && --depth === 0) {
        out.push({ start: open, end: i })
        break
      }
    }
  }
  return out
}

const PARSE_CALL =
  /\b(?:(?:int|long|short|byte|sbyte|uint|ulong|ushort|double|float|decimal|Int16|Int32|Int64|UInt16|UInt32|UInt64|Double|Single|Decimal|Byte|SByte|DateTime|DateTimeOffset|TimeSpan|DateOnly|TimeOnly|Guid)\s*\.\s*Parse(?:Exact)?|Convert\s*\.\s*To(?:Int16|Int32|Int64|UInt16|UInt32|UInt64|Byte|SByte|Double|Single|Decimal|DateTime))\s*\(/g

const EXACT_CALL = /\b(DateTime|DateTimeOffset|DateOnly|TimeOnly|TimeSpan)\s*\.\s*(?:Try)?ParseExact\s*\(/g

// Fehler in C#, die beim Ausführen sicher oder bei falscher Eingabe abstürzen.
export function csCrashErrors(text: string, file: string): WinFinding[] {
  const { kept, bare } = stripComments(text)
  const starts = lineStarts(text)
  const lines = text.split('\n')
  const errors: WinFinding[] = []
  const add = (index: number, code: string, msg: string): void => {
    const line = lineOf(starts, index)
    if (allowed(lines, line, code)) return
    if (errors.some(e => e.line === line && e.code === code && e.text === msg)) return
    errors.push({ file, line, col: index - starts[line - 1] + 1, code, text: msg })
  }
  const lits = literals(kept)
  const inLiteral = (i: number): boolean => lits.some(l => i > l.start && i < l.end)

  for (const l of lits) {
    if (l.interp) {
      for (const h of l.holes) {
        const f = holeFormat(kept, h.start, h.end)
        if (!f) continue
        const kind = receiverKind(f.expr)
        if (badShortFormat(f.fmt, kind)) add(f.at, 'CW-FORMAT', formatText(f.fmt, kind))
      }
      continue
    }
    // Platzhalter mit Nummer in gewöhnlichen Texten: "{0:H}" für string.Format, Console.WriteLine, AppendFormat ...
    const body = kept.slice(l.start, l.end)
    for (const m of body.matchAll(/(?<!\{)\{\s*\d+\s*(?:,\s*-?\d+\s*)?:([^{}"]*)\}/g)) {
      if (badShortFormat(m[1], 'any')) add(l.start + (m.index ?? 0), 'CW-FORMAT', formatText(m[1], 'any'))
    }
  }

  for (const m of kept.matchAll(/\.\s*ToString\s*\(\s*@?"([^"\\\n]*)"\s*[,)]/g)) {
    const at = m.index ?? 0
    if (inLiteral(at)) continue
    const kind = receiverKind(kept.slice(Math.max(0, at - 80), at))
    if (badShortFormat(m[1], kind)) add(at, 'CW-FORMAT', formatText(m[1], kind))
  }

  for (const m of kept.matchAll(EXACT_CALL)) {
    const at = m.index ?? 0
    if (inLiteral(at)) continue
    const args = callArgs(bare, at + m[0].length - 1)
    if (!args[1]) continue
    const kind = TYPE_FORMAT[m[1]]
    for (const f of exactFormats(kept, bare, args[1])) if (badShortFormat(f.fmt, kind)) add(f.at, 'CW-FORMAT', formatText(f.fmt, kind))
  }

  const tries = tryBlocks(bare)
  for (const m of kept.matchAll(PARSE_CALL)) {
    const at = m.index ?? 0
    if (inLiteral(at) || tries.some(b => at > b.start && at < b.end)) continue
    const first = callArgs(bare, at + m[0].length - 1)[0]
    if (!first || !/\.\s*Text\b/.test(kept.slice(first.start, first.end))) continue
    const call = m[0].replace(/\s+/g, '').replace(/\($/, '')
    add(
      at,
      'CW-PARSE',
      t(
        `${call} auf eine Eingabe der Oberfläche (.Text) stürzt ab, sobald das Feld leer ist oder etwas anderes drin steht (FormatException). TryParse benutzen und bei falscher Eingabe einen Hinweis zeigen`,
        `${call} on user input (.Text) crashes as soon as the field is empty or holds something else (FormatException). Use TryParse and show a hint for wrong input`,
      ),
    )
  }
  return errors.sort((a, b) => a.line - b.line)
}

// ====================================================================================== XAML (WPF)
export const WPF_NS = 'http://schemas.microsoft.com/winfx/2006/xaml/presentation'

type Attr = { name: string; value: string; at: number }
type El = { name: string; attrs: Attr[]; at: number; parent?: El }

function decode(v: string): string {
  return v.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (_, e: string) => {
    if (e === 'lt') return '<'
    if (e === 'gt') return '>'
    if (e === 'amp') return '&'
    if (e === 'quot') return '"'
    if (e === 'apos') return "'"
    const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)
    return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : ''
  })
}

// Die Elemente einer XAML-Datei der Reihe nach, mit Eltern; Kommentare, CDATA und Anweisungen übersprungen.
// Ist der Aufbau kaputt, endet die Liste dort (die XML-Prüfung davor meldet das).
function elements(text: string): El[] {
  const out: El[] = []
  const stack: El[] = []
  const attrRe = /\s+([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/y
  const endRe = /\s*(\/?)>/y
  let i = 0
  while (i < text.length) {
    const lt = text.indexOf('<', i)
    if (lt < 0) break
    if (text.startsWith('<!--', lt)) {
      const e = text.indexOf('-->', lt + 4)
      i = e < 0 ? text.length : e + 3
      continue
    }
    if (text.startsWith('<![CDATA[', lt)) {
      const e = text.indexOf(']]>', lt + 9)
      i = e < 0 ? text.length : e + 3
      continue
    }
    if (text[lt + 1] === '?' || text[lt + 1] === '!') {
      const e = text.indexOf('>', lt + 2)
      i = e < 0 ? text.length : e + 1
      continue
    }
    if (text[lt + 1] === '/') {
      const m = /^<\/([^\s>]+)\s*>/.exec(text.slice(lt, lt + 300))
      if (!m) break
      while (stack.length > 0 && stack.pop()?.name !== m[1]) {
        // falsch verschachtelt: bis zum passenden Element zurück
      }
      i = lt + m[0].length
      continue
    }
    const nm = /^<([^\s/>]+)/.exec(text.slice(lt, lt + 300))
    if (!nm) break
    const el: El = { name: nm[1], attrs: [], at: lt, parent: stack[stack.length - 1] }
    let p = lt + nm[0].length
    for (;;) {
      attrRe.lastIndex = p
      const a = attrRe.exec(text)
      if (!a) break
      const raw = a[2] ?? a[3] ?? ''
      el.attrs.push({ name: a[1], value: decode(raw), at: a.index + a[0].length - raw.length - 1 })
      p = attrRe.lastIndex
    }
    endRe.lastIndex = p
    const e = endRe.exec(text)
    if (!e) break
    out.push(el)
    if (e[1] !== '/') stack.push(el)
    i = endRe.lastIndex
  }
  return out
}

const attr = (el: El, name: string): Attr | undefined => el.attrs.find(a => a.name === name)

// Namen aus .NET (Enum.GetNames, Colors, FontWeights, FontStyles), abgefragt am 25.10.2026.
const ENUMS = {
  Visibility: ['Visible', 'Hidden', 'Collapsed'],
  HorizontalAlignment: ['Left', 'Center', 'Right', 'Stretch'],
  VerticalAlignment: ['Top', 'Center', 'Bottom', 'Stretch'],
  TextWrapping: ['WrapWithOverflow', 'NoWrap', 'Wrap'],
  TextAlignment: ['Left', 'Right', 'Center', 'Justify'],
  Orientation: ['Horizontal', 'Vertical'],
  Dock: ['Left', 'Top', 'Right', 'Bottom'],
  ScrollBarVisibility: ['Disabled', 'Auto', 'Hidden', 'Visible'],
  ResizeMode: ['NoResize', 'CanMinimize', 'CanResize', 'CanResizeWithGrip'],
  WindowStartupLocation: ['Manual', 'CenterScreen', 'CenterOwner'],
  SizeToContent: ['Manual', 'Width', 'Height', 'WidthAndHeight'],
  WindowState: ['Normal', 'Minimized', 'Maximized'],
  TextTrimming: ['None', 'CharacterEllipsis', 'WordEllipsis'],
  Stretch: ['None', 'Fill', 'Uniform', 'UniformToFill'],
  WindowStyle: ['None', 'SingleBorderWindow', 'ThreeDBorderWindow', 'ToolWindow'],
}
const FONT_WEIGHTS = ['Thin', 'ExtraLight', 'UltraLight', 'Light', 'Normal', 'Regular', 'Medium', 'DemiBold', 'SemiBold', 'Bold', 'ExtraBold', 'UltraBold', 'Black', 'Heavy', 'ExtraBlack', 'UltraBlack']
const FONT_STYLES = ['Normal', 'Oblique', 'Italic']
const COLORS = new Set(
  'AliceBlue,AntiqueWhite,Aqua,Aquamarine,Azure,Beige,Bisque,Black,BlanchedAlmond,Blue,BlueViolet,Brown,BurlyWood,CadetBlue,Chartreuse,Chocolate,Coral,CornflowerBlue,Cornsilk,Crimson,Cyan,DarkBlue,DarkCyan,DarkGoldenrod,DarkGray,DarkGreen,DarkKhaki,DarkMagenta,DarkOliveGreen,DarkOrange,DarkOrchid,DarkRed,DarkSalmon,DarkSeaGreen,DarkSlateBlue,DarkSlateGray,DarkTurquoise,DarkViolet,DeepPink,DeepSkyBlue,DimGray,DodgerBlue,Firebrick,FloralWhite,ForestGreen,Fuchsia,Gainsboro,GhostWhite,Gold,Goldenrod,Gray,Green,GreenYellow,Honeydew,HotPink,IndianRed,Indigo,Ivory,Khaki,Lavender,LavenderBlush,LawnGreen,LemonChiffon,LightBlue,LightCoral,LightCyan,LightGoldenrodYellow,LightGray,LightGreen,LightPink,LightSalmon,LightSeaGreen,LightSkyBlue,LightSlateGray,LightSteelBlue,LightYellow,Lime,LimeGreen,Linen,Magenta,Maroon,MediumAquamarine,MediumBlue,MediumOrchid,MediumPurple,MediumSeaGreen,MediumSlateBlue,MediumSpringGreen,MediumTurquoise,MediumVioletRed,MidnightBlue,MintCream,MistyRose,Moccasin,NavajoWhite,Navy,OldLace,Olive,OliveDrab,Orange,OrangeRed,Orchid,PaleGoldenrod,PaleGreen,PaleTurquoise,PaleVioletRed,PapayaWhip,PeachPuff,Peru,Pink,Plum,PowderBlue,Purple,Red,RosyBrown,RoyalBlue,SaddleBrown,Salmon,SandyBrown,SeaGreen,SeaShell,Sienna,Silver,SkyBlue,SlateBlue,SlateGray,Snow,SpringGreen,SteelBlue,Tan,Teal,Thistle,Tomato,Transparent,Turquoise,Violet,Wheat,White,WhiteSmoke,Yellow,YellowGreen'
    .toLowerCase()
    .split(','),
)

type Check =
  | 'size' | 'min' | 'max' | 'fontsize' | 'coord' | 'double' | 'thickness' | 'corner' | 'uint' | 'span' | 'int' | 'gridlen' | 'brush' | 'bool' | 'nbool'
  | 'weight' | 'fstyle' | { names: readonly string[] }

const BRUSH_PROPS = ['Background', 'Foreground', 'BorderBrush', 'Fill', 'Stroke', 'CaretBrush', 'SelectionBrush', 'OpacityMask']
const BOOL_PROPS = [
  'IsEnabled', 'IsReadOnly', 'Focusable', 'IsTabStop', 'IsDefault', 'IsCancel', 'Topmost', 'ShowInTaskbar', 'AcceptsReturn', 'AcceptsTab',
  'ClipToBounds', 'SnapsToDevicePixels', 'UseLayoutRounding', 'IsHitTestVisible', 'AllowDrop', 'IsThreeState', 'IsEditable', 'ShowGridLines',
  'IsIndeterminate', 'StaysOpen', 'IsTextSearchEnabled',
]

const PROPS: Record<string, Check> = {
  Width: 'size',
  Height: 'size',
  MinWidth: 'min',
  MinHeight: 'min',
  MaxWidth: 'max',
  MaxHeight: 'max',
  FontSize: 'fontsize',
  StrokeThickness: 'coord',
  Opacity: 'double',
  Margin: 'thickness',
  Padding: 'thickness',
  BorderThickness: 'thickness',
  CornerRadius: 'corner',
  TabIndex: 'int',
  MaxLength: 'uint',
  FontWeight: 'weight',
  FontStyle: 'fstyle',
  Visibility: { names: ENUMS.Visibility },
  HorizontalAlignment: { names: ENUMS.HorizontalAlignment },
  HorizontalContentAlignment: { names: ENUMS.HorizontalAlignment },
  VerticalAlignment: { names: ENUMS.VerticalAlignment },
  VerticalContentAlignment: { names: ENUMS.VerticalAlignment },
  TextWrapping: { names: ENUMS.TextWrapping },
  TextAlignment: { names: ENUMS.TextAlignment },
  Orientation: { names: ENUMS.Orientation },
  HorizontalScrollBarVisibility: { names: ENUMS.ScrollBarVisibility },
  VerticalScrollBarVisibility: { names: ENUMS.ScrollBarVisibility },
  ResizeMode: { names: ENUMS.ResizeMode },
  WindowStartupLocation: { names: ENUMS.WindowStartupLocation },
  SizeToContent: { names: ENUMS.SizeToContent },
  WindowState: { names: ENUMS.WindowState },
  TextTrimming: { names: ENUMS.TextTrimming },
  Stretch: { names: ENUMS.Stretch },
  WindowStyle: { names: ENUMS.WindowStyle },
  IsChecked: 'nbool',
  ...Object.fromEntries(BRUSH_PROPS.map(p => [p, 'brush' as Check])),
  ...Object.fromEntries(BOOL_PROPS.map(p => [p, 'bool' as Check])),
}

// Angehängte Eigenschaften (Besitzer.Name)
const ATTACHED: Record<string, Check> = {
  'Grid.Row': 'uint',
  'Grid.Column': 'uint',
  'Grid.RowSpan': 'span',
  'Grid.ColumnSpan': 'span',
  'Panel.ZIndex': 'int',
  'Canvas.Left': 'coord',
  'Canvas.Top': 'coord',
  'Canvas.Right': 'coord',
  'Canvas.Bottom': 'coord',
  'DockPanel.Dock': { names: ENUMS.Dock },
  'ScrollViewer.HorizontalScrollBarVisibility': { names: ENUMS.ScrollBarVisibility },
  'ScrollViewer.VerticalScrollBarVisibility': { names: ENUMS.ScrollBarVisibility },
  'TextElement.FontSize': 'fontsize',
  'TextElement.FontWeight': 'weight',
  'TextElement.FontStyle': 'fstyle',
  'TextElement.Foreground': 'brush',
  'TextBlock.FontSize': 'fontsize',
  'TextBlock.FontWeight': 'weight',
  'TextBlock.Foreground': 'brush',
}

const SIZE_PROPS = new Set(['Width', 'Height', 'MinWidth', 'MinHeight', 'MaxWidth', 'MaxHeight'])

// Welche Prüfung gilt für die Eigenschaft prop an einem Element namens owner ('' = unbekannt)?
function checkFor(owner: string, prop: string): Check | undefined {
  if ((owner === 'RowDefinition' && prop === 'Height') || (owner === 'ColumnDefinition' && prop === 'Width')) return 'gridlen'
  // Spalten (DataGridTextColumn, GridViewColumn, TableColumn) haben eigene Breiten wie "SizeToHeader"
  if (SIZE_PROPS.has(prop) && /Column$/.test(owner)) return undefined
  if (prop === 'Color') return ['SolidColorBrush', 'GradientStop', 'DropShadowEffect'].includes(owner) ? 'brush' : undefined
  return PROPS[prop]
}

const NUM = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/

// Länge mit Einheit (px, in, cm, pt); Kommas gelten bei Längen als Tausender-Trenner (gemessen: "1,5" und "12," laufen).
function length(v: string, commas: boolean): number | undefined {
  const m = /^(.*?)\s*(px|in|cm|pt)?$/i.exec(v.trim())
  const n = commas ? (m?.[1] ?? '').replace(/,/g, '') : (m?.[1] ?? '')
  return NUM.test(n) ? Number(n) : undefined
}

function parts(v: string): string[] {
  return v.trim().split(/\s*,\s*|\s+/)
}

function valid(check: Check, raw: string): boolean {
  const v = raw.trim()
  const lower = v.toLowerCase()
  const len = (): number | undefined => length(v, true)
  switch (check) {
    case 'size': {
      if (v === '' || lower === 'auto' || v === 'NaN') return true
      const n = len()
      return n !== undefined && n >= 0
    }
    case 'min':
    case 'max': {
      // Gemessen: MaxWidth="Infinity" läuft, MinWidth="Infinity" stürzt ab
      if (v === '' || (check === 'max' && v === 'Infinity')) return true
      const n = len()
      return n !== undefined && n >= 0
    }
    case 'fontsize': {
      const n = len()
      return n !== undefined && n > 0
    }
    case 'coord':
      return v === '' || lower === 'auto' || v === 'NaN' || len() !== undefined
    case 'double':
      return NUM.test(v) || ['NaN', 'Infinity', '-Infinity'].includes(v)
    case 'thickness': {
      const p = parts(v)
      return v !== '' && [1, 2, 4].includes(p.length) && p.every(x => x !== '' && length(x, false) !== undefined)
    }
    case 'corner': {
      // Gemessen: Einheiten wie "1px" stürzen hier ab
      const p = parts(v)
      return v !== '' && [1, 4].includes(p.length) && p.every(x => NUM.test(x) && Number(x) >= 0)
    }
    case 'uint':
      return /^\+?\d+$/.test(v) && Number(v) <= 2147483647
    case 'span':
      return /^\+?\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 2147483647
    case 'int':
      return /^[+-]?\d+$/.test(v) && Math.abs(Number(v)) <= 2147483647
    case 'gridlen': {
      if (lower === 'auto' || /^(?:(?:\d+\.?\d*|\.\d+)\s*)?\*$/.test(v)) return true
      const n = length(v, false)
      return n !== undefined && n >= 0
    }
    case 'brush':
      return (
        COLORS.has(lower) ||
        /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(v) ||
        /^sc#/i.test(v)
      )
    case 'bool':
      return lower === 'true' || lower === 'false'
    case 'nbool':
      return v === '' || lower === 'true' || lower === 'false'
    case 'weight':
      // Gemessen: " Bold" mit Leerzeichen stürzt ab, darum hier der Wert ungekürzt
      return FONT_WEIGHTS.some(w => w.toLowerCase() === raw.toLowerCase()) || (/^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 999)
    case 'fstyle':
      // Gemessen: " Italic" mit Leerzeichen stürzt ab
      return FONT_STYLES.some(w => w.toLowerCase() === raw.toLowerCase())
    default:
      // enum: auch Zahlen und mehrere Namen mit Komma (gemessen: "2" und "Visible,Hidden" laufen, leer stürzt ab)
      return v !== '' && v.split(',').every(x => /^[+-]?\d+$/.test(x.trim()) || check.names.some(n => n.toLowerCase() === x.trim().toLowerCase()))
  }
}

function allowedText(check: Check): string {
  switch (check) {
    case 'size':
      return t('eine Zahl ab 0, auch mit px, in, cm, pt, oder Auto', 'a number from 0, also with px, in, cm, pt, or Auto')
    case 'min':
      return t('eine Zahl ab 0 (kein Auto, kein Infinity)', 'a number from 0 (no Auto, no Infinity)')
    case 'max':
      return t('eine Zahl ab 0 oder Infinity (kein Auto)', 'a number from 0 or Infinity (no Auto)')
    case 'fontsize':
      return t('eine Zahl grösser als 0', 'a number above 0')
    case 'coord':
      return t('eine Zahl', 'a number')
    case 'double':
      return t('eine Zahl mit Punkt, ohne Einheit und ohne %', 'a number with a dot, no unit and no %')
    case 'thickness':
      return t('1, 2 oder 4 Zahlen', '1, 2 or 4 numbers')
    case 'corner':
      return t('1 oder 4 Zahlen ab 0, ohne Einheit', '1 or 4 numbers from 0, no unit')
    case 'uint':
      return t('eine ganze Zahl ab 0', 'a whole number from 0')
    case 'span':
      return t('eine ganze Zahl ab 1', 'a whole number from 1')
    case 'int':
      return t('eine ganze Zahl', 'a whole number')
    case 'gridlen':
      return t('Auto, *, 2* oder eine Zahl ab 0', 'Auto, *, 2* or a number from 0')
    case 'brush':
      return t('ein englischer Farbname wie Red oder #RGB, #RRGGBB, #AARRGGBB', 'an English colour name like Red or #RGB, #RRGGBB, #AARRGGBB')
    case 'bool':
    case 'nbool':
      return 'True / False'
    case 'weight':
      return t('Normal, Bold, SemiBold … oder 1 bis 999', 'Normal, Bold, SemiBold … or 1 to 999')
    case 'fstyle':
      return FONT_STYLES.join(', ')
    default:
      return check.names.join(', ')
  }
}

// Schlüssel der Ressourcen eines Projekts: x:Key aus allen XAML-Dateien (mit dem Element, das ihn trägt) und Schlüssel, die der
// Code anlegt (Resources["…"] = …, Resources.Add("…", …)). external: Ressourcen kommen auch von ausserhalb (fremde Bibliothek,
// im Code geladenes Wörterbuch); dann wird ein fehlender Schlüssel nicht gemeldet.
export type ResourceIndex = { keys: Map<string, Set<string>>; external: boolean }

export function resourceIndex(assembly: string, xaml: { text: string }[], cs: { text: string }[]): ResourceIndex {
  const keys = new Map<string, Set<string>>()
  const put = (k: string, tag: string): void => {
    if (!keys.has(k)) keys.set(k, new Set())
    keys.get(k)?.add(tag)
  }
  let external = false
  for (const x of xaml) {
    for (const el of elements(x.text)) {
      const k = attr(el, 'x:Key')
      if (k) put(k.value, el.name)
      const src = el.name === 'ResourceDictionary' ? attr(el, 'Source')?.value : undefined
      const asm = src ? /([^/;,]+);component\//i.exec(src)?.[1] : undefined
      if (asm && asm.toLowerCase() !== assembly.toLowerCase()) external = true
      if (src && /^https?:/i.test(src)) external = true
      if (el.name.includes(':') && el.parent?.name.endsWith('.MergedDictionaries')) external = true
    }
  }
  for (const c of cs) {
    const { kept } = stripComments(c.text)
    for (const m of kept.matchAll(/Resources\s*\[\s*"([^"]+)"\s*\]\s*=(?!=)/g)) put(m[1], 'code')
    for (const m of kept.matchAll(/Resources\s*\.\s*Add\s*\(\s*"([^"]+)"/g)) put(m[1], 'code')
    // Wörterbuch im Code geladen oder Schlüssel aus einer Variablen: welche Namen es gibt, ist dann nicht lesbar
    if (/MergedDictionaries\s*\.\s*Add\s*\(|\bResources\s*(?:\[\s*[^"\s\]]|\.\s*Add\s*\(\s*[^"\s)])/.test(kept)) external = true
  }
  return { keys, external }
}

const NOT_BRUSH = new Set(['Style', 'ControlTemplate', 'DataTemplate', 'HierarchicalDataTemplate', 'ItemsPanelTemplate'])

export function isWpfXaml(text: string): boolean {
  const root = elements(text.slice(0, 20000))[0]
  return !!root && attr(root, 'xmlns')?.value === WPF_NS
}

// Fehler in einer WPF-XAML-Datei. index: Ressourcen des Projekts (ohne: keine Prüfung der StaticResource-Namen).
export function xamlErrors(text: string, file: string, index?: ResourceIndex): WinFinding[] {
  if (!isWpfXaml(text)) return []
  const starts = lineStarts(text)
  const lines = text.split('\n')
  const els = elements(text)
  const local = resourceIndex('', [{ text }], [])
  const errors: WinFinding[] = []
  const add = (index0: number, code: string, msg: string): void => {
    const line = lineOf(starts, index0)
    if (allowed(lines, line, code)) return
    errors.push({ file, line, col: index0 - starts[line - 1] + 1, code, text: msg })
  }

  // Ein Wert an einer Eigenschaft: falscher Wert oder Stil statt Farbe.
  const value = (owner: string, prop: string, full: string, a: Attr, shown: string): void => {
    // Besitzer.Name, das nicht angehängt ist (FrameworkElement.Width, Control.Background), gilt wie Name allein
    const check = ATTACHED[full] ?? (full.includes('.') && !/^[A-Z]\w*\.[A-Z]\w*$/.test(full) ? undefined : checkFor(owner, prop))
    if (!check) return
    const v = a.value
    if (v.trimStart().startsWith('{')) {
      const res = /^\s*\{StaticResource\s+(?:ResourceKey\s*=\s*)?([^\s{},]+)\s*\}\s*$/.exec(v)
      if (res && check === 'brush') {
        const tags = local.keys.get(res[1]) ?? index?.keys.get(res[1])
        const tag = tags ? [...tags].find(x => NOT_BRUSH.has(x)) : undefined
        if (tag && [...(tags ?? [])].every(x => NOT_BRUSH.has(x))) {
          add(
            a.at,
            'CW-XAML-STIL',
            t(
              `${shown} bekommt mit StaticResource ${q(res[1])} einen ${tag}, keine Farbe – das Fenster stürzt beim Öffnen ab. Ein gleich heissender Schlüssel in den Resources des Fensters verdeckt die Farbe in App.xaml`,
              `${shown} gets a ${tag} from StaticResource ${q(res[1])}, not a colour – the window crashes when it opens. A key of the same name in the window's Resources hides the colour in App.xaml`,
            ),
          )
        }
      }
      return
    }
    if (valid(check, v)) return
    add(
      a.at,
      'CW-XAML-WERT',
      t(
        `${shown}=${q(v)} ist kein gültiger Wert (erlaubt: ${allowedText(check)}) – WPF übersetzt das ohne Meldung, das Fenster stürzt aber beim Öffnen ab`,
        `${shown}=${q(v)} is not a valid value (allowed: ${allowedText(check)}) – WPF builds it without a message, but the window crashes when it opens`,
      ),
    )
  }

  for (const el of els) {
    // Eigene Steuerelemente (local:…) und Eigenschafts-Elemente (Button.Background) haben eigene Typen: nicht prüfen
    const custom = el.name.includes(':') || el.name.includes('.')
    if (el.name === 'Setter') {
      const p = attr(el, 'Property')
      const v = attr(el, 'Value')
      if (p && v) {
        const full = p.value.trim()
        let owner = ''
        let prop = full
        if (full.includes('.')) {
          owner = full.slice(0, full.lastIndexOf('.'))
          prop = full.slice(full.lastIndexOf('.') + 1)
        } else {
          for (let x = el.parent; x; x = x.parent) {
            const tt = attr(x, 'TargetType')
            if (tt) {
              owner = tt.value.replace(/^\s*\{x:Type\s+([^}\s]+)\s*\}\s*$/, '$1').trim()
              break
            }
          }
        }
        const unknownTarget = attr(el, 'TargetName') !== undefined
        if (!owner.includes(':') && !(unknownTarget && SIZE_PROPS.has(prop))) value(unknownTarget ? '' : owner, prop, full, v, `Setter ${full}`)
        else if (ATTACHED[full]) value('', prop, full, v, `Setter ${full}`)
      }
    }
    if (!custom) {
      for (const a of el.attrs) {
        if (a.name.includes(':') || a.name === 'xmlns') continue
        const prop = a.name.slice(a.name.lastIndexOf('.') + 1)
        value(el.name, prop, a.name, a, a.name)
      }
    }
    // Fehlender StaticResource-Name: in jedem Wert, auch verschachtelt ({Binding Converter={StaticResource X}})
    if (index && !index.external) {
      const keyAttr = el.name === 'StaticResource' ? attr(el, 'ResourceKey') : undefined
      const found: { key: string; at: number }[] = keyAttr ? [{ key: keyAttr.value.trim(), at: keyAttr.at }] : []
      for (const a of el.attrs) {
        for (const m of a.value.matchAll(/\{StaticResource\s+(?:ResourceKey\s*=\s*)?([^\s{},]+)\s*\}/g)) found.push({ key: m[1], at: a.at })
      }
      for (const f of found) {
        if (local.keys.has(f.key) || index.keys.has(f.key)) continue
        add(
          f.at,
          'CW-XAML-RESSOURCE',
          t(
            `StaticResource ${q(f.key)} gibt es nirgends im Projekt (kein x:Key in einer XAML-Datei, nicht im Code angelegt) – das Fenster stürzt beim Öffnen ab. Namen prüfen (Gross- und Kleinschreibung zählt)`,
            `StaticResource ${q(f.key)} exists nowhere in the project (no x:Key in any XAML file, not created in code) – the window crashes when it opens. Check the name (case matters)`,
          ),
        )
      }
    }
  }
  return errors.sort((a, b) => a.line - b.line)
}

export const windowsChecks = { csCrashErrors, xamlErrors, resourceIndex, isWpfXaml }
