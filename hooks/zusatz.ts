// Zusatzregeln aus Stufe 1 des Bauplans "höchstes Niveau" (27.11.2026: "Alle drei Stufen")
// an EINER Stelle: beim Schreiben (register.tsx, withScanners) und im /scan (scannenOrdner mit extra) laufen dieselben Regeln.
// Die Bausteine holen Hilfen aus sicherheit.ts; darum ruft register.tsx sie über diese Datei auf und nicht sicherheit.ts selbst
// (sonst bänden sich sicherheit.ts und die Bausteine gegenseitig ein).
//   unsichtbar.ts  UNSICHTBAR    unsichtbare Unicode-Zeichen, jede Textdatei (Rules File Backdoor, Trojan Source, ASCII-Smuggling)
//   rechte.ts      RECHTE-AUS    Schalter, mit denen ein KI-Agent jeden Befehl ohne Rückfrage ausführt; RECHTE-DATEI Hinweis
//   cs_muster.ts   CS-SQL, CS-RECHTE, CS-WEBVIEW, CS-DLL, CS-TEMPDATEI, CS-REGEX (C#)
//   js_worker.ts   JS-SSRF, JS-WEITERLEITUNG, JS-CORS, JS-EVAL, JS-XSS, JS-POSTMESSAGE, JS-JWT; WRANGLER-GEHEIMNIS (Cloudflare-Worker)
//   testbetrug.ts  VERGLEICH-IMMER-WAHR (rot), TEST-UMGEBUNG (C#, Python, JS/TS); testBetrug (alt/neu) ruft register.tsx

import { csZusatzMuster } from './cs_muster'
import { WRANGLER_DATEI, jsZusatzMuster, wranglerMuster } from './js_worker'
import { rechteAbschalter } from './rechte'
import { JS } from './sicherheit'
import type { SFund } from './sicherheit'
import { immerWahr } from './testbetrug'
import { unsichtbareZeichen } from './unsichtbar'

const CS = /\.cs$/i

// Text- und Regeldateien ohne eigene Prüfung (CLAUDE.md, Merkdateien, Skills, Notizen): dort zählen nur die unsichtbaren Zeichen.
export const TEXT_DATEI = /\.(?:md|markdown|mdx|txt)$/i

export function zusatzBefunde(text: string, file: string): SFund[] {
  const funde = [...unsichtbareZeichen(text, file), ...rechteAbschalter(text, file), ...immerWahr(text, file)]
  if (CS.test(file)) funde.push(...csZusatzMuster(text, file))
  if (JS.test(file)) funde.push(...jsZusatzMuster(text, file))
  if (WRANGLER_DATEI.test(file)) funde.push(...wranglerMuster(text, file))
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}

// Für Text- und Regeldateien: nur die unsichtbaren Zeichen.
export function textBefunde(text: string, file: string): SFund[] {
  return unsichtbareZeichen(text, file)
}
