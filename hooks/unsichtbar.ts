// Unsichtbare Unicode-Zeichen (27.11.2026, Bauplan "Alle drei Stufen"): Zeichen, die im Editor nichts oder etwas anderes zeigen,
// als Übersetzer und KI lesen. Gilt für jede Textdatei (auch .md, .txt, .json, also CLAUDE.md, Skills und Regeldateien) und auch für
// Prüfdateien; eine bewusste Stelle trägt "code-waechter:ok SICHERHEIT" in der Zeile.
//
// Belege (gelesen 27.11.2026):
//   Trojan Source, CVE-2021-42574 (https://trojansource.codes/): Richtungs-Steuerzeichen ordnen Quelltext für das Auge um, der
//     Übersetzer liest ihn in der echten Reihenfolge.
//   Pillar Security, "Rules File Backdoor", 18.03.2025 (https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents):
//     versteckte Anweisungen an KI-Assistenten in Regeldateien über Nullbreite-Zeichen und Richtungszeichen.
//   Microsoft, 03.09.2026 (https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/):
//     ASCII-Smuggling mit Unicode-Tags U+E0000-U+E007F; die Flaggen von England, Schottland und Wales brauchen diese Tags.
//   UTS #51 Abschnitt 1.4.5 und Annex C.1 (https://www.unicode.org/reports/tr51/) und UTS #35 (unicode_subdivision_id = Region
//     alpha{2}|digit{3} plus alphanum{1,4}): eine gültige Flaggen-Folge ist U+1F3F4, 3 bis 7 Tag-Ziffern oder kleine Tag-Buchstaben
//     (U+E0030-U+E0039, U+E0061-U+E007A) und U+E007F. Nur genau diese Folge bleibt still: Tag-Leerzeichen, grosse Tag-Buchstaben oder ein
//     langer Text zwischen U+1F3F4 und U+E007F wären versteckter Text in einer "Flagge".
//
// Text in Zeichenketten und Kommentaren zählt hier mit (anders als bei den übrigen Mustern): genau dort verstecken die Angriffe ihre
// Zeichen. Je Zeile höchstens ein Fund (das erste Zeichen); die Spalte zählt wie bei den übrigen Mustern in Stellen des JavaScript-Texts
// (UTF-16) ab 1. Diese Datei enthält keines der Zeichen selbst, nur Escapes - sonst meldete der Wächter sie.
//
// Gemessen 27.11.2026 über die Projektordner eines Entwicklers und seinen .claude-Ordner (12'249 Textdateien, 417 MB, 1,8 s): 42 Zeilen rot, jede
// mit einem echten unsichtbaren Zeichen, keine böswillig - 14-mal U+FEFF wörtlich in einer BOM-Prüfung, 3-mal wörtlich in einer
// Zeichenklasse, 12-mal in Prüfsätzen, 8-mal in Protokollen und Berichten, die diese Prüfsätze zitieren, 5-mal in fremden Dateien
// (Changelogs fremder Mods, pip). Abhilfe jeweils die Escape-Schreibweise oder die Markierung. 229 Dateien mit U+FEFF am Anfang blieben
// still; Emoji-Folgen mit U+200D und Flaggen kamen in den Ordnern nicht vor (nur durch die Prüfsätze belegt).

import { t } from './i18n'
import { OK_SICHER } from './sicherheit'
import type { SFund } from './sicherheit'

type Art = 'richtung' | 'tag' | 'bom' | 'nullbreite'

// Alle Zeichen der Regel: Richtungs-Steuerzeichen, Nullbreite-Zeichen, unsichtbare Rechenzeichen, U+FEFF und die Unicode-Tags;
// seit 28.11.2026 auch die Richtungsmarken U+200E/U+200F und U+061C (unsichtbar, ändern die Anzeige der Nachbarzeichen; Gegenprüfungen).
const KANDIDAT = /[\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/gu
// Gültige Flaggen-Folge nach UTS #51 Annex C.1 (siehe Kopf).
const FLAGGE = /\u{1F3F4}[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{3,7}\u{E007F}/gu
// Nachbarn, neben denen U+200C/U+200D zu einer Emoji-Folge gehören: Emoji, Hautfarbe (U+1F3FB-U+1F3FF), Variationszeichen.
const EMOJI_NACHBAR = /^(?:\p{Extended_Pictographic}|\p{Emoji_Modifier}|[\uFE0E\uFE0F])$/u

function artVon(cp: number): Art {
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c) return 'richtung'
  if (cp >= 0xe0000) return 'tag'
  if (cp === 0xfeff) return 'bom'
  return 'nullbreite'
}

const hex = (cp: number): string => cp.toString(16).toUpperCase().padStart(4, '0')

// Das Zeichen direkt vor einer Stelle (ein Ersatzpaar zählt als ein Zeichen) und das Zeichen an einer Stelle.
function zeichenVor(text: string, at: number): string {
  if (at <= 0) return ''
  const unten = text.charCodeAt(at - 1)
  if (unten >= 0xdc00 && unten <= 0xdfff && at >= 2) {
    const oben = text.charCodeAt(at - 2)
    if (oben >= 0xd800 && oben <= 0xdbff) return text.slice(at - 2, at)
  }
  return text.slice(at - 1, at)
}

function zeichenAb(text: string, at: number): string {
  const cp = text.codePointAt(at)
  return cp === undefined ? '' : String.fromCodePoint(cp)
}

function meldung(art: Art, cp: number): string {
  const u = `U+${hex(cp)}`
  const esc = cp > 0xffff ? `\\u{${hex(cp)}}` : `\\u${hex(cp)}`
  switch (art) {
    case 'richtung':
      return t(`Richtungs-Steuerzeichen ${u}: der Text wird anders angezeigt, als Übersetzer und KI ihn lesen (Trojan Source) - Zeichen löschen; braucht der Code es, als Escape ${esc} schreiben.`,
        `bidirectional control character ${u}: the text is shown differently from how compilers and AI read it (Trojan Source) - delete the character; if the code needs it, write the escape ${esc}.`)
    case 'tag':
      return t(`unsichtbares Unicode-Tag ${u}: hier steht Text, den eine KI liest, aber kein Mensch sieht (versteckte Anweisung, ASCII-Smuggling) - Zeichen löschen.`,
        `invisible Unicode tag ${u}: this is text an AI reads but no human sees (hidden instruction, ASCII smuggling) - delete the character.`)
    case 'bom':
      return t(`unsichtbares Zeichen ${u} (Byte-Reihenfolge-Marke) mitten im Text: es gehört nur an den Dateianfang und versteckt sonst Text vor dem Auge, z. B. eine Anweisung an eine KI - Zeichen löschen; braucht der Code es, als Escape ${esc} schreiben.`,
        `invisible character ${u} (byte order mark) inside the text: it belongs only at the start of a file and otherwise hides text from the eye, e.g. an instruction to an AI - delete the character; if the code needs it, write the escape ${esc}.`)
    default:
      return t(`unsichtbares Zeichen ${u} ohne Breite: es versteckt Text vor dem Auge oder macht gleich aussehende Namen verschieden, z. B. eine Anweisung an eine KI - Zeichen löschen; braucht der Code es, als Escape ${esc} schreiben.`,
        `invisible zero-width character ${u}: it hides text from the eye or makes names that look the same different, e.g. an instruction to an AI - delete the character; if the code needs it, write the escape ${esc}.`)
  }
}

// _file: die Regel gilt für jede Datei, Prüfdateien eingeschlossen - der Pfad ändert nichts (Schnittstelle wie bei den übrigen Mustern).
export function unsichtbareZeichen(text: string, _file: string): SFund[] {
  const funde: SFund[] = []
  // Stellen der Tags, die zu einer gültigen Flaggen-Folge gehören.
  const flaggenTags = new Set<number>()
  for (const m of text.matchAll(FLAGGE)) {
    const start = m.index ?? 0
    // U+1F3F4 belegt 2 Stellen, jedes Tag ebenfalls 2.
    for (let k = start + 2; k < start + m[0].length; k += 2) flaggenTags.add(k)
  }
  let zeile = 1
  let zeilenStart = 0
  let bisher = 0
  let letzteFundZeile = 0
  for (const m of text.matchAll(KANDIDAT)) {
    const at = m.index ?? 0
    for (let n = text.indexOf('\n', bisher); n !== -1 && n < at; n = text.indexOf('\n', n + 1)) {
      zeile++
      zeilenStart = n + 1
    }
    bisher = at
    if (zeile === letzteFundZeile) continue
    const cp = m[0].codePointAt(0) ?? 0
    if (cp === 0xfeff && at === 0) continue
    if (cp >= 0xe0000 && flaggenTags.has(at)) continue
    if ((cp === 0x200c || cp === 0x200d) && (EMOJI_NACHBAR.test(zeichenVor(text, at)) || EMOJI_NACHBAR.test(zeichenAb(text, at + 1)))) continue
    const ende = text.indexOf('\n', at)
    if (OK_SICHER.test(text.slice(zeilenStart, ende === -1 ? text.length : ende))) {
      letzteFundZeile = zeile
      continue
    }
    letzteFundZeile = zeile
    funde.push({ line: zeile, col: at - zeilenStart + 1, code: 'UNSICHTBAR', schwer: true, scanner: t('Muster', 'pattern'), text: meldung(artVon(cp), cp) })
  }
  return funde
}
