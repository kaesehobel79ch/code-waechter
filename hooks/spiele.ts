// Regeln für Spiel-Engines, die ohne die Engine selbst prüfbar sind.
// Unity: Vorschläge für C#-Skripte (teure Aufrufe, die jedes Bild laufen; CompareTag; leere Unity-Methoden).
// Unreal: die Regeln von Unreals Header-Werkzeug (UHT), an denen der Bau sonst erst spät scheitert, und Zeiger ohne UPROPERTY.
//
// Engine rules that can be checked without the engine itself (Unity C# performance hints, Unreal Header Tool rules).

import { t } from './i18n'

export type GameFinding = { file: string; line: number; col: number; code: string; text: string }

// Zeilen, die länger sind, bekommen keine Muster-Vorschläge (verkleinerter oder erzeugter Code); gezählt wird trotzdem alles.
const MAX_RULE_LINE = 4000
const MAX_HINTS = 50

// Kommentare entfernen, in einem Durchgang Zeichen für Zeichen (die Zeit wächst nur mit der Dateigröße).
// kept: Kommentare durch Leerzeichen ersetzt, Texte bleiben (für Muster wie tag == "Player").
// bare: zusätzlich der Inhalt von Texten und Zeichen ersetzt (zum Zählen von Klammern).
// Zeilenumbrüche bleiben überall stehen, damit die Zeilennummern stimmen. Kennt C#-Texte mit @ (ohne Backslash, "" als Anführungszeichen).
export function stripComments(text: string): { kept: string; bare: string } {
  const kept: string[] = []
  const bare: string[] = []
  const n = text.length
  const blank = (c: string): string => (c === '\n' || c === '\r' ? c : ' ')
  let i = 0
  while (i < n) {
    const c = text[i]
    const d = text[i + 1]
    if (c === '/' && d === '/') {
      while (i < n && text[i] !== '\n') {
        kept.push(blank(text[i]))
        bare.push(blank(text[i]))
        i++
      }
      continue
    }
    if (c === '/' && d === '*') {
      const end = text.indexOf('*/', i + 2)
      const stop = end < 0 ? n : end + 2
      for (; i < stop; i++) {
        kept.push(blank(text[i]))
        bare.push(blank(text[i]))
      }
      continue
    }
    if (c === '"' || c === "'") {
      const verbatim = c === '"' && (text[i - 1] === '@' || (text[i - 1] === '$' && text[i - 2] === '@') || (text[i - 1] === '@' && text[i - 2] === '$'))
      kept.push(c)
      bare.push(c)
      i++
      while (i < n) {
        const x = text[i]
        if (x === '\n' && !verbatim) break // Text ohne Ende: an der Zeile hört er auf
        if (!verbatim && x === '\\') {
          kept.push(x)
          bare.push(' ')
          if (i + 1 < n) {
            kept.push(text[i + 1])
            bare.push(blank(text[i + 1]))
          }
          i += 2
          continue
        }
        if (x === c) {
          if (verbatim && text[i + 1] === '"') {
            kept.push('""')
            bare.push('  ')
            i += 2
            continue
          }
          kept.push(x)
          bare.push(x)
          i++
          break
        }
        kept.push(x)
        bare.push(blank(x))
        i++
      }
      continue
    }
    kept.push(c)
    bare.push(c)
    i++
  }
  return { kept: kept.join(''), bare: bare.join('') }
}

// Zeilennummer zu einer Stelle: einmal die Zeilenanfänge sammeln, dann binär suchen. Auch von windows.ts benutzt.
export function lineStarts(text: string): number[] {
  const out = [0]
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) out.push(i + 1)
  return out
}

export function lineOf(starts: number[], index: number): number {
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (starts[mid] <= index) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}

// ---- Unity
const UPDATE_METHOD = /\bvoid\s+(Update|FixedUpdate|LateUpdate|OnGUI)\s*\(\s*\)/

type Rule = { re: RegExp; text: (method: string) => string }

// Teuer, wenn es in jedem Bild läuft (in Update, FixedUpdate, LateUpdate, OnGUI).
const PER_FRAME: Rule[] = [
  {
    re: /\bGetComponents?(?:InChildren|InParent)?\s*[<(]/,
    text: m => t(`GetComponent in ${m}() läuft jedes Bild; einmal in Awake/Start holen und in einem Feld merken`, `GetComponent in ${m}() runs every frame; fetch it once in Awake/Start and keep it in a field`),
  },
  {
    re: /\bGameObject\.Find(?:WithTag|GameObjectsWithTag)?\s*\(|\bFind(?:ObjectOfType|ObjectsOfType|FirstObjectByType|AnyObjectByType|ObjectsByType)\s*[<(]/,
    text: m => t(`Suche nach Objekten in ${m}() läuft jedes Bild und ist langsam; einmal suchen und merken`, `searching for objects in ${m}() runs every frame and is slow; search once and keep the result`),
  },
  {
    re: /\bDebug\.Log\w*\s*\(/,
    text: m => t(`Debug.Log in ${m}() kostet jedes Bild Leistung und füllt das Log`, `Debug.Log in ${m}() costs performance every frame and floods the log`),
  },
  {
    re: /\bnew\s+(?:List|Dictionary|HashSet|Queue|Stack)\s*</,
    text: m => t(`neue Sammlung in ${m}() erzeugt jedes Bild Speichermüll (Ruckler); einmal anlegen und leeren`, `new collection in ${m}() creates garbage every frame (stutter); create it once and clear it`),
  },
]

const ANYWHERE: { re: RegExp; text: () => string }[] = [
  {
    re: /(?:\.|\b)tag\s*[!=]=\s*"|"\s*[!=]=\s*(?:[\w.]*\.)?tag\b/,
    text: () => t('Tag-Vergleich mit == erzeugt Speichermüll; CompareTag("…") verwenden', 'comparing tags with == creates garbage; use CompareTag("…")'),
  },
  {
    re: /\b(?:SendMessage|BroadcastMessage|SendMessageUpwards)\s*\(/,
    text: () => t('SendMessage ist langsam und findet Tippfehler erst zur Laufzeit; Methode direkt aufrufen', 'SendMessage is slow and only finds typos at runtime; call the method directly'),
  },
]

function unityCsHints(text: string, file: string): GameFinding[] {
  if (!/\busing\s+UnityEngine\b/.test(text)) return []
  const out: GameFinding[] = []
  const { kept, bare } = stripComments(text)
  const lines = kept.split('\n')
  const bareLines = bare.split('\n')
  let method = ''
  let depth = 0
  let methodDepth = -1
  for (let i = 0; i < lines.length && out.length < MAX_HINTS; i++) {
    const line = lines[i]
    if (line.length <= MAX_RULE_LINE) {
      const start = UPDATE_METHOD.exec(line)
      if (start && methodDepth < 0) {
        method = start[1]
        methodDepth = depth
      }
      if (methodDepth >= 0) {
        for (const rule of PER_FRAME) {
          const m = rule.re.exec(line)
          if (m) {
            out.push({ file, line: i + 1, col: m.index + 1, code: 'UNITY', text: rule.text(method) })
            break
          }
        }
      }
      for (const rule of ANYWHERE) {
        const m = rule.re.exec(line)
        if (m) out.push({ file, line: i + 1, col: m.index + 1, code: 'UNITY', text: rule.text() })
      }
    }
    for (const c of bareLines[i] ?? '') {
      if (c === '{') depth++
      else if (c === '}') {
        depth--
        if (methodDepth >= 0 && depth <= methodDepth) {
          methodDepth = -1
          method = ''
        }
      }
    }
  }
  // Leere Unity-Methoden: Unity ruft sie trotzdem jedes Mal auf.
  const starts = lineStarts(bare)
  const empty = /\bvoid\s+(Update|FixedUpdate|LateUpdate|OnGUI|Start|Awake)\s*\(\s*\)\s*\{\s*\}/g
  for (let m = empty.exec(bare); m !== null && out.length < MAX_HINTS; m = empty.exec(bare)) {
    out.push({
      file,
      line: lineOf(starts, m.index),
      col: 1,
      code: 'UNITY',
      text: t(`leere ${m[1]}()-Methode: Unity ruft sie trotzdem auf; löschen`, `empty ${m[1]}() method: Unity still calls it; delete it`),
    })
  }
  return out
}

// ---- Unreal
const REFLECT = /^\s*(UCLASS|USTRUCT|UINTERFACE|UENUM)\s*\(/
// Delegaten mit DYNAMIC brauchen ebenfalls X.generated.h (aber kein GENERATED_BODY).
const DYNAMIC_DELEGATE = /^\s*DECLARE_DYNAMIC_(?:MULTICAST_)?(?:SPARSE_)?DELEGATE\w*\s*\(/
const GENERATED = /\bGENERATED_(?:UCLASS_|USTRUCT_|UINTERFACE_|IINTERFACE_)?BODY\s*\(/g
const INCLUDE = /^\s*#\s*include\s+["<]([^">]+)[">]/
const RAW_UOBJECT_POINTER = /^\s*(?:class\s+)?([UA][A-Z]\w*)\s*\*\s*\w+\s*(?:=\s*nullptr\s*)?;/

// Für jede Zeile: steht ihr Anfang direkt im Körper einer class/struct, und kam seit der letzten Anweisung ein UPROPERTY(...)?
function classMembers(bare: string): { inClass: boolean[]; uproperty: boolean[] } {
  const inClass: boolean[] = [false]
  const uproperty: boolean[] = [false]
  const stack: boolean[] = []
  let pending = ''
  for (let i = 0; i < bare.length; i++) {
    const c = bare[i]
    if (c === '\n') {
      inClass.push(stack.length > 0 && stack[stack.length - 1])
      uproperty.push(/\bUPROPERTY\s*\(/.test(pending))
      pending += ' '
      continue
    }
    if (c === '{') {
      stack.push(/\b(?:class|struct)\b[^()]*$/.test(pending) || /\bclass\s+\w+[\w\s:,<>]*$/.test(pending))
      pending = ''
    } else if (c === '}') {
      stack.pop()
      pending = ''
    } else if (c === ';') pending = ''
    else if (pending.length < 2000) pending += c
  }
  return { inClass, uproperty }
}

function unrealChecks(text: string, file: string): { errors: GameFinding[]; hints: GameFinding[] } {
  const errors: GameFinding[] = []
  const hints: GameFinding[] = []
  const isHeader = /\.(h|hpp)$/i.test(file)
  const { kept, bare } = stripComments(text)
  const lines = kept.split('\n')
  if (!isHeader) {
    // Unreals Header-Werkzeug liest nur Header: UCLASS/USTRUCT in einer .cpp-Datei wird nie verarbeitet.
    const at = lines.findIndex(l => REFLECT.test(l) && !/UENUM/.test(l))
    if (at >= 0) {
      errors.push({
        file,
        line: at + 1,
        col: 1,
        code: 'UHT',
        text: t('UCLASS/USTRUCT gehört in einen Header (.h); in einer .cpp-Datei verarbeitet das Unreal Header Tool es nicht', 'UCLASS/USTRUCT belongs in a header (.h); the Unreal Header Tool does not process it in a .cpp file'),
      })
    }
    return { errors, hints }
  }
  const base = (file.split(/[\\/]/).pop() ?? file).replace(/\.[^.]+$/, '')
  const generated = `${base}.generated.h`
  const members = classMembers(bare)
  let firstReflect = -1
  let needed = 0
  let lastInclude = -1
  let generatedAt = -1
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const r = REFLECT.exec(line)
    if (r) {
      if (firstReflect < 0) firstReflect = i
      if (r[1] === 'UCLASS' || r[1] === 'USTRUCT') needed += 1
      if (r[1] === 'UINTERFACE') needed += 2
    } else if (DYNAMIC_DELEGATE.test(line) && firstReflect < 0) firstReflect = i
    const inc = INCLUDE.exec(line)
    if (inc) {
      lastInclude = i
      if ((inc[1].split('/').pop() ?? '') === generated) generatedAt = i
    }
    const p = line.length <= MAX_RULE_LINE ? RAW_UOBJECT_POINTER.exec(line) : null
    if (p && members.inClass[i] && !members.uproperty[i] && hints.length < MAX_HINTS) {
      hints.push({
        file,
        line: i + 1,
        col: 1,
        code: 'UNREAL',
        text: t(
          `Zeiger auf ${p[1]} ohne UPROPERTY(): der Garbage Collector kann das Objekt freigeben; UPROPERTY() und TObjectPtr verwenden`,
          `pointer to ${p[1]} without UPROPERTY(): the garbage collector may free the object; use UPROPERTY() and TObjectPtr`,
        ),
      })
    }
  }
  if (firstReflect < 0) return { errors, hints }
  if (generatedAt < 0) {
    errors.push({
      file,
      line: lastInclude >= 0 ? lastInclude + 1 : 1,
      col: 1,
      code: 'UHT',
      text: t(`#include "${generated}" fehlt (Unreal Header Tool bricht ab)`, `#include "${generated}" is missing (Unreal Header Tool will fail)`),
    })
  } else if (generatedAt !== lastInclude) {
    errors.push({
      file,
      line: generatedAt + 1,
      col: 1,
      code: 'UHT',
      text: t(`"${generated}" muss die letzte #include-Zeile sein`, `"${generated}" must be the last #include line`),
    })
  }
  const have = (kept.match(GENERATED) ?? []).length
  if (have < needed) {
    errors.push({
      file,
      line: firstReflect + 1,
      col: 1,
      code: 'UHT',
      text: t(
        `GENERATED_BODY() fehlt: ${needed} nötig für die UCLASS/USTRUCT/UINTERFACE dieser Datei, ${have} vorhanden`,
        `GENERATED_BODY() missing: ${needed} needed for the UCLASS/USTRUCT/UINTERFACE in this file, ${have} present`,
      ),
    })
  }
  return { errors, hints }
}

export const gameChecks = { unityCsHints, unrealChecks }
