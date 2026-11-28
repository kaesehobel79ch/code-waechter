// JavaScript/TypeScript-Zusatzregeln, vor allem für Cloudflare-Worker (27.11.2026, Bauplan "höchstes Niveau",
// Stufe 1 Punkt 6). Eine Such-Anwendung des Entwicklers ist ein Worker
// (such-worker.js).
//
//   JS-SSRF             rot      fetch / new Request / axios / got mit einer Adresse aus der Anfrage
//   JS-WEITERLEITUNG    rot      Response.redirect / res.redirect / res.location / Location-Kopf mit einem Ziel aus der Anfrage
//   JS-CORS             Hinweis  Access-Control-Allow-Origin "*"; rot, wenn dieselbe Datei Access-Control-Allow-Credentials true setzt
//                       rot      Access-Control-Allow-Origin bekommt den Origin der Anfrage ungeprüft zurück
//   JS-EVAL             rot      setTimeout / setInterval / setImmediate mit Text statt Funktion
//   JS-XSS              rot      insertAdjacentHTML, dangerouslySetInnerHTML, srcdoc, createContextualFragment mit nicht festem Text
//   JS-POSTMESSAGE      Hinweis  Empfänger für 'message' am Fenster, der .origin nicht prüft
//   JS-JWT              Hinweis  jwt.decode / decodeJwt in einer Datei ohne verify / jwtVerify
//   WRANGLER-GEHEIMNIS  rot      Geheimnis unter vars in wrangler.toml / wrangler.json / wrangler.jsonc (Wert verborgen)
//
// Prüfdateien (PRUEF_PFAD in sicherheit.ts) bekommen nur Hinweise. Bewusste Stellen: "code-waechter:ok SICHERHEIT" in der Zeile.
// Text in Zeichenketten und Kommentaren zählt nicht als Code (jsBereinigt).
//
// Herkunft wie in jsMuster (sicherheit.ts): direkt oder über eine Variable, die im selben Block daraus gefüllt wurde. Unschädlich:
// Wahl aus einer festen Liste (LISTE[x]), Prüfung LISTE.includes(x) / .has(x) / .indexOf(x), Vergleich mit einem festen Text
// (x === "a"), new URL(x).origin / x.origin / .host / .hostname === "fest", Number/parseInt/parseFloat/Boolean/basename/
// encodeURIComponent um den Wert. Eine Adresse mit festem Anfang "https://rechner/" (oder "https://rechner" + Pfad der eigenen
// Adresse) behält ihren Rechner: Teile aus der Anfrage dahinter sind kein SSRF.
//
// Belege (gelesen 27.11.2026):
//   developers.cloudflare.com/workers/configuration/secrets: "Do not use vars to store sensitive information in your Worker's
//     Wrangler configuration file. Use secrets instead." und "npx wrangler secret put <KEY>"
//   developers.cloudflare.com/workers/runtime-apis/request: request.url "Contains the URL of the request."
//   developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin: "*" nur für Anfragen ohne
//     Anmeldedaten, mit Anmeldedaten "results in an error"
//   developer.mozilla.org/en-US/docs/Web/API/Window/setTimeout: Text als code "strongly discouraged" aus denselben Gründen wie eval
//   developer.mozilla.org/en-US/docs/Web/API/Window/postMessage: "always verify the sender's identity using the origin" (die Seite
//     spricht nur von Fenstern und iframes)
//   github.com/auth0/node-jsonwebtoken: jwt.decode "will not verify whether the signature is valid"
//   github.com/panva/jose (decodeJwt): "without validating its JWS Signature"
//   developers.cloudflare.com/turnstile/get-started: sitekey "a public identifier you place in your HTML"
//   developer.mozilla.org/en-US/docs/Web/API/URL/pathname: bei http(s) "will therefore always have at least one / character"
//   developer.mozilla.org/en-US/docs/Web/API/Element/insertAdjacentHTML: "injection sinks ... cross-site scripting (XSS)"
//   (alle Belege nochmals gelesen 27.11.2026 abends)
//
// Die Hilfen hier (Block, Ende eines Ausdrucks, Wahl aus einer Liste) gleichen denen in jsMuster; dort sind es innere Funktionen,
// die sich ohne Umbau von sicherheit.ts nicht teilen lassen.

import { t } from './i18n'
import { JS, OK_SICHER, PLATZHALTER, PRUEF_PFAD, ausdruckAb, cArgumente, jsBereinigt, teileOben, zeileVon } from './sicherheit'
import type { SFund } from './sicherheit'

type Art = 'voll' | 'eigen'
type Bereich = { name: string; von: number; bis: number }
type Stelle = ReturnType<typeof jsBereinigt>['texte'][number]

// Text aus der Anfrage: Express req.query/params/body/headers, beim Worker request.headers (auch .get(...)) und der Inhalt
// (await request.json() / formData() / text()).
const QUELLE = /\b(?:req|request)\s*\.\s*(?:query|params|body|headers)\b|\b(?:req|request)\s*\.\s*(?:json|formData|text)\s*\(/g
// request.url ist die Adresse, unter der der Worker selbst aufgerufen wurde ("Contains the URL of the request", Rechner aus der
// Route): fetch(request.url) oder Response.redirect(new URL('/x', request.url)) bleiben beim eigenen Ursprung. Fremd sind ihre Teile
// (Pfad, Suche, searchParams.get(...), split/slice ...). Darum sind request.url und Adress-Variablen daraus "Träger": fremd wird
// erst, was hinter .pathname, .searchParams, [ ... ] usw. steht; .origin/.host/.hostname/.protocol/.port/.href/.toString() bleiben eigen.
// Heisst die Anfrage req (export default { async fetch(req) ... }), zählt req.url nur in new URL(req.url ...) als Träger: bei Express
// ist req.url allein nur der Pfad und kann "//fremd.ch" sein (Probe 27.11.2026: new URL(req.url).searchParams.get('u') blieb sonst still).
const TRAEGER_ODER_NAME = /\brequest\s*\.\s*url\b|(?<=\bnew\s+URL\s*\(\s*)req\s*\.\s*url\b|(?<![\w$.])([A-Za-z_$][\w$]*)/g
const EIGENER_TEIL = /^\s*(?:\?\s*)?\.\s*(?:(?:origin|host|hostname|protocol|port|href)\b(?!\s*\()|toString\s*\(\s*\))/
const EIGENER_NAME = /^(?:origin|host|hostname|protocol|port|href)$/
const HARMLOS_VOR = /\b(?:Number|parseInt|parseFloat|Boolean|basename|encodeURIComponent)\s*$/
// Eine Adresse, deren fester Anfang Rechner und Pfadbeginn festlegt (https://rechner/ ...) oder ein eigener Pfad (/x, ?, #, ./):
// was danach aus der Anfrage kommt, ändert den Rechner nicht. "https://rechner" ohne / reicht nicht (".fremd.ch" oder "@fremd.ch"
// dahinter wechselt den Rechner), "/" allein auch nicht ("//fremd.ch").
const SICHERER_ANFANG = /^(?:[a-z][a-z\d+.-]*:\/\/[^/?#\\\s]+[/?#\\]|\/[^/\\]|[?#]|\.\.?\/)/i
// HTML aus diesen Aufrufen enthält kein fremdes Skript mehr (bereinigt, maskiert oder eine Zahl).
const HTML_HARMLOS = /^(?:[\w$]+\s*\.\s*)*(?:sanitize\w*|escape\w*|Number|parseInt|parseFloat)\s*\(/i

const SSRF_AUFRUF = /(?<![\w$.])fetch\s*\(|\b(?:window|globalThis|self)\s*\.\s*fetch\s*\(|\bnew\s+Request\s*\(|(?<![\w$.])axios\s*(?:\.\s*(?:get|post|put|patch|delete|head|options|request)\s*)?\(|(?<![\w$.])got\s*(?:\.\s*(?:get|post|put|patch|delete|head|stream)\s*)?\(/g
const WEITER_AUFRUF = /\b(?:Response|res(?:ponse)?)\s*\.\s*redirect\s*\(|\bres(?:ponse)?\s*\.\s*location\s*\(/g
const ZEIT_AUFRUF = /(?:(?<![\w$.])|\b(?:window|globalThis|self)\s*\.\s*)(setTimeout|setInterval|setImmediate)\s*\(/g
const JWT_DECODE = /\b(?:jwt|jsonwebtoken)\s*\.\s*decode\s*\(|(?<![\w$])decodeJwt\s*\(/g
const JWT_PRUEFT = /\b(?:verify|jwtVerify)\b/
// Zuweisungen: const/let/var x = ..., Zerlegung { a, b: c } = ..., x = ... / x += ..., und adresse.hostname = ...
const ZUWEISUNG = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])|\b(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=;\n]+)?=(?![=>])|(?<![\w$.])([A-Za-z_$][\w$]*)\s*\+?=(?![=>])|(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:href|host|hostname|protocol)\s*=(?![=>])/g

export function jsZusatzMuster(text: string, file: string): SFund[] {
  if (!JS.test(file)) return []
  const pruef = PRUEF_PFAD.test(file)
  const { bare, texte } = jsBereinigt(text)
  const roh = text.split(/\r?\n/)
  const n = bare.length
  const beiStart = new Map<number, Stelle>(texte.map(s => [s.start, s]))

  // Block jeder Stelle: die innerste offene { davor und ihre schliessende }.
  const innen = new Int32Array(n + 1).fill(-1)
  const schluss = new Map<number, number>()
  const stapel: number[] = []
  for (let k = 0; k <= n; k++) {
    innen[k] = stapel.length > 0 ? (stapel[stapel.length - 1] ?? -1) : -1
    if (bare[k] === '{') stapel.push(k)
    else if (bare[k] === '}') {
      const o = stapel.pop()
      if (o !== undefined) schluss.set(o, k)
    }
  }
  const blockEnde = (at: number): number => {
    const o = innen[Math.min(Math.max(at, 0), n)] ?? -1
    return o < 0 ? n : (schluss.get(o) ?? n)
  }
  const trimmt = (von: number, bis: number): [number, number] => {
    let a = von
    let b = bis
    while (a < b && /\s/.test(bare[a] ?? '')) a++
    while (b > a && /\s/.test(bare[b - 1] ?? '')) b--
    return [a, b]
  }
  const klammerEnde = (offen: number): number => {
    let d = 0
    for (let k = offen; k < n; k++) {
      const s = k > offen ? beiStart.get(k) : undefined
      if (s) {
        k = s.ende - 1
        continue
      }
      const c = bare[k]
      if (c === '(' || c === '[' || c === '{') d++
      else if (c === ')' || c === ']' || c === '}') {
        d--
        if (d === 0) return k
      }
    }
    return -1
  }
  const argumente = (offen: number): { text: string; at: number }[] => {
    let at = offen + 1
    return cArgumente(bare, offen).map(x => {
      const r = { text: x, at }
      at += x.length + 1
      return r
    })
  }
  // Ende eines Ausdrucks ohne Semikolon: Zeilenende auf Tiefe 0, ausser die Zeile endet mit einem Operator oder die nächste beginnt mit
  // einem (wie in jsMuster).
  const rechteSeite = (von: number): string => {
    let d = 0
    for (let k = von; k < n; k++) {
      const c = bare[k]
      if (c === '(' || c === '[' || c === '{') d++
      else if (c === ')' || c === ']' || c === '}') {
        if (d === 0) return bare.slice(von, k)
        d--
      } else if (c === ';' && d === 0) return bare.slice(von, k)
      else if (c === '\n' && d === 0) {
        const vorher = bare.slice(von, k).trimEnd()
        const nachher = bare.slice(k + 1).trimStart()
        if (!/[+\-*/=,(?:&|]$/.test(vorher) && !/^[.+?:&|]/.test(nachher)) return bare.slice(von, k)
      }
    }
    return bare.slice(von)
  }
  // In Number(...) & Co., als Wahl aus einer Liste (LISTE[...]) oder in den Einstellungen von new Request(adresse, ...) bzw.
  // fetch(adresse, ...) trägt eine Stelle keinen fremden Text in eine Adresse (gemessen 27.11.2026 an minipass-fetch: new
  // Request(locationURL, { headers: new Headers(request.headers) }) galt sonst als Abruf einer fremden Adresse).
  const neutral = (pos: number, start: number): boolean => {
    let d = 0
    let komma = false
    for (let k = pos - 1; k >= start; k--) {
      const c = bare[k]
      if (c === ')' || c === ']' || c === '}') d++
      else if (c === ',' && d === 0) komma = true
      else if (c === '(' || c === '[' || c === '{') {
        if (d > 0) {
          d--
          continue
        }
        const davor = bare.slice(Math.max(0, k - 40), k)
        if (c === '(' && HARMLOS_VOR.test(davor)) return true
        if (c === '(' && komma && /(?:\bnew\s+Request|(?<![\w$.])fetch)\s*$/.test(davor)) return true
        if (c === '[' && /[\w$\])]\s*$/.test(davor)) return true
        komma = false
      }
    }
    return false
  }
  // Rechte Seite ist eine Funktion oder Klasse: die Variable hält Code, keinen Text aus der Anfrage (gemessen 27.11.2026 an
  // make-fetch-happen: const getRedirect = (request, ...) => { ... request.headers ... } machte jeden Aufruf "fremd").
  const istFunktion = (von: number): boolean => {
    let k = von
    while (k < n && /\s/.test(bare[k] ?? '')) k++
    const rest = bare.slice(k, k + 200)
    if (/^(?:async\b\s*)?(?:function\b|class\b|[A-Za-z_$][\w$]*\s*=>)/.test(rest)) return true
    const p = /^(?:async\b\s*)?\(/.exec(rest)
    if (!p) return false
    const zu = klammerEnde(k + p[0].length - 1)
    return zu > 0 && /^\s*(?::[^=;{]+)?=>/.test(bare.slice(zu + 1, zu + 200))
  }

  // Feste Texte: const NAME = 'text' (ganze rechte Seite ein Text ohne ${...}).
  const feste = new Map<string, string>()
  for (const m of bare.matchAll(/\bconst\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=(?![=>])\s*/g)) {
    const s = beiStart.get((m.index ?? 0) + m[0].length)
    if (!s || s.teile.length > 0 || !/^\s*(?:as\s+const\b\s*)?(?:[;,)\r\n]|$)/.test(bare.slice(s.ende, s.ende + 30))) continue
    feste.set(m[1] ?? '', text.slice(s.start + 1, s.ende - 1))
  }
  const festerWertBei = (pos: number): boolean => {
    let k = pos
    while (k < n && /\s/.test(bare[k] ?? '')) k++
    const s = beiStart.get(k)
    if (s) return s.teile.length === 0 && s.ende - s.start > 2
    const name = /^[A-Za-z_$][\w$]*/.exec(bare.slice(k, k + 80))?.[0]
    return name !== undefined && feste.has(name)
  }

  // Prüfungen: ab der Stelle gilt die Variable im Block als geprüft.
  const pruefungen: Bereich[] = []
  const geprueft = (name: string, von: number) => pruefungen.push({ name, von, bis: blockEnde(von) })
  for (const m of bare.matchAll(/\.\s*(?:includes|has|indexOf)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) geprueft(m[1] ?? '', m.index ?? 0)
  for (const m of bare.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*(?:origin|host|hostname))?\s*[!=]==?\s*/g)) {
    const at = m.index ?? 0
    if (/\btypeof\s+$/.test(bare.slice(Math.max(0, at - 10), at))) continue
    if (festerWertBei(at + m[0].length)) geprueft(m[1] ?? '', at)
  }
  for (const m of bare.matchAll(/\bnew\s+URL\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.\s*(?:origin|host|hostname)\s*[!=]==?\s*/g)) {
    if (festerWertBei((m.index ?? 0) + m[0].length)) geprueft(m[1] ?? '', m.index ?? 0)
  }
  for (const s of texte) {
    if (s.teile.length > 0 || s.ende - s.start <= 2) continue
    const r = /^\s*[!=]==?\s*([A-Za-z_$][\w$]*)(?:\s*\.\s*(?:origin|host|hostname))?(?!\s*[.\w$([])/.exec(bare.slice(s.ende, s.ende + 120))
    if (r) geprueft(r[1] ?? '', s.start)
  }

  // Herkunft eines Ausdrucks (Stelle at in bare): "voll" = Text aus der Anfrage, "eigen" = die eigene Adresse des Workers.
  const voll: Bereich[] = []
  const eigen: Bereich[] = []
  const gilt = (l: Bereich[], name: string, at: number) => l.some(h => h.name === name && h.von <= at && at < h.bis)
  const art = (ausdruck: string, at: number): Art | undefined => {
    let hatEigen = false
    for (const m of ausdruck.matchAll(QUELLE)) if (!neutral(at + (m.index ?? 0), at)) return 'voll'
    for (const m of ausdruck.matchAll(TRAEGER_ODER_NAME)) {
      const pos = at + (m.index ?? 0)
      const name = m[1]
      if (name !== undefined) {
        if (gilt(voll, name, pos) && !gilt(pruefungen, name, pos) && !neutral(pos, at)) return 'voll'
        if (!gilt(eigen, name, pos)) continue
      }
      // Träger: in new URL(träger[, basis]) eingebettet reicht er bis zur schliessenden Klammer.
      let ende = pos + m[0].length
      const vor = bare.slice(Math.max(at, pos - 40), pos)
      if (/\bnew\s+URL\s*\(\s*$/.test(vor)) {
        const zu = klammerEnde(pos - vor.length + vor.lastIndexOf('('))
        if (zu > 0 && zu < at + ausdruck.length) ende = zu + 1
      }
      const danach = ausdruck.slice(ende - at)
      if (!EIGENER_TEIL.test(danach) && /^\s*(?:\?\s*)?[.[]/.test(danach) && !neutral(pos, at)) return 'voll'
      hatEigen = true
    }
    return hatEigen ? 'eigen' : undefined
  }
  // Pfad der eigenen Adresse (url.pathname, new URL(request.url).pathname, const { pathname } = url): fremd, beginnt aber bei http(s)
  // immer mit "/" (MDN URL.pathname: "path segments, each of which is prefixed by a / character"). Hinter "https://rechner" bleibt der
  // Rechner damit fest - fetch('https://origin.ch' + url.pathname) ist die übliche Weiterleitung eines Workers an den eigenen Ursprung
  // (Probe 27.11.2026: war rot). Allein reicht "/" nicht ("//fremd.ch").
  const pfade: Bereich[] = []
  const zuletzt = (l: Bereich[], name: string, at: number) => l.reduce((b, h) => (h.name === name && h.von <= at && at < h.bis && h.von > b ? h.von : b), -1)
  const istPfad = (w: string, at: number): boolean => {
    if (/^[A-Za-z_$][\w$]*$/.test(w)) {
      // nur, solange die Variable seit der Zuweisung des Pfads nichts anderes aus der Anfrage bekommen hat
      const p = zuletzt(pfade, w, at)
      return p >= 0 && p >= zuletzt(voll, w, at)
    }
    const p = /^(\S[\s\S]*?)\s*\.\s*pathname$/.exec(w)
    return p !== null && art(p[1] ?? '', at) === 'eigen'
  }
  for (const m of bare.matchAll(ZUWEISUNG)) {
    const at = m.index ?? 0
    const rechts = at + m[0].length
    if (istFunktion(rechts)) continue
    const ausdruck = rechteSeite(rechts)
    const a = art(ausdruck, rechts)
    if (a === undefined) continue
    const von = rechts + ausdruck.length
    const bis = blockEnde(at)
    if (m[4] !== undefined) {
      if (a === 'voll') voll.push({ name: m[4], von, bis })
    } else if (m[2] !== undefined) {
      for (const teil of teileOben(m[2])) {
        const [schl, lokal] = teil.trim().replace(/^\.\.\./, '').split('=')[0]?.split(':').map(x => x.trim()) ?? []
        const name = lokal || schl
        if (name && a === 'eigen' && schl === 'pathname') pfade.push({ name, von, bis })
        if (name && (a === 'voll' || !EIGENER_NAME.test(schl ?? ''))) voll.push({ name, von, bis })
      }
    } else {
      const ziel = a === 'voll' ? voll : eigen
      const name = m[1] ?? m[3] ?? ''
      ziel.push({ name, von, bis })
      const rechtsGetrimmt = rechts + ausdruck.length - ausdruck.trimStart().length
      if (a === 'voll' && istPfad(ausdruck.trim(), rechtsGetrimmt)) pfade.push({ name, von, bis })
    }
  }

  // Elemente einer Kette a + b + c auf oberster Ebene (Zeichenketten am Stück).
  const plusTeile = (von: number, bis: number): [number, number][] => {
    const teile: [number, number][] = []
    let d = 0
    let start = von
    for (let k = von; k < bis; k++) {
      const s = beiStart.get(k)
      if (s && s.ende <= bis) {
        k = s.ende - 1
        continue
      }
      const c = bare[k]
      if (c === '(' || c === '[' || c === '{') d++
      else if (c === ')' || c === ']' || c === '}') d--
      else if (c === '+' && d === 0 && bare[k + 1] !== '+' && bare[k + 1] !== '=' && bare[k - 1] !== '+') {
        teile.push([start, k])
        start = k + 1
      }
    }
    teile.push([start, bis])
    return teile
  }
  const literalGenau = (a: number, b: number): Stelle | undefined => {
    const s = beiStart.get(a)
    return s && s.ende === b ? s : undefined
  }
  // Fester Anfang einer Adresse bis zum ersten Teil aus der Anfrage. Ein Teil, der nicht aus der Anfrage stammt (env.BASIS,
  // url.origin), steht als Platzhalter da: am Anfang für "https://rechner", sonst für ein Stück Rechnername.
  const anfang = (von: number, bis: number): string => {
    let a = ''
    const platz = () => (a === '' ? 'https://x' : 'x')
    for (const [x, y] of plusTeile(von, bis)) {
      const [p, q] = trimmt(x, y)
      const s = literalGenau(p, q)
      if (s) {
        let k = s.start + 1
        for (const [ta, tb] of s.teile) {
          a += text.slice(k, ta - 2)
          const [ea, eb] = trimmt(ta, tb)
          const w = bare.slice(ea, eb)
          if (feste.has(w)) a += feste.get(w) ?? ''
          else if (art(w, ea) !== 'voll') a += platz()
          else return istPfad(w, ea) ? `${a}/` : a
          k = tb + 1
        }
        a += text.slice(k, s.ende - 1)
        continue
      }
      const w = bare.slice(p, q)
      if (feste.has(w)) a += feste.get(w) ?? ''
      else if (art(w, p) !== 'voll') a += platz()
      else return istPfad(w, p) ? `${a}/` : a
    }
    return a
  }
  const gefaehrlicheAdresse = (von0: number, bis0: number): boolean => {
    const [von, bis] = trimmt(von0, bis0)
    if (von >= bis) return false
    const nu = /^new\s+URL\s*\(/.exec(bare.slice(von, bis))
    if (nu) {
      const offen = von + nu[0].length - 1
      const zu = klammerEnde(offen)
      if (zu > 0 && /^\s*(?:\.\s*(?:href\b|toString\s*\(\s*\)))?\s*$/.test(bare.slice(zu + 1, bis))) {
        const [p, b] = argumente(offen)
        if (!p) return false
        if (b && art(b.text, b.at) === 'voll') return true
        return gefaehrlicheAdresse(p.at, p.at + p.text.length)
      }
    }
    if (art(bare.slice(von, bis), von) !== 'voll') return false
    return !SICHERER_ANFANG.test(anfang(von, bis))
  }
  // Bedingung ? a : b auf oberster Ebene: die Stellen von a und b.
  const zweige = (von: number, bis: number): [number, number, number, number] | undefined => {
    let d = 0
    let frage = -1
    let offen = 0
    for (let k = von; k < bis; k++) {
      const s = beiStart.get(k)
      if (s && s.ende <= bis) {
        k = s.ende - 1
        continue
      }
      const c = bare[k]
      if (c === '(' || c === '[' || c === '{') d++
      else if (c === ')' || c === ']' || c === '}') d--
      else if (d === 0 && c === '?' && bare[k + 1] !== '.' && bare[k + 1] !== '?' && bare[k - 1] !== '?') {
        if (frage < 0) frage = k
        else offen++
      } else if (d === 0 && c === ':' && frage >= 0) {
        if (offen === 0) return [frage + 1, k, k + 1, bis]
        offen--
      }
    }
    return undefined
  }
  // Fester Text: nur Zeichenketten (auch `...${fest}...`), feste Namen, Zahlen und bereinigende Aufrufe, auch in Klammern und als
  // Bedingung ? a : b.
  const festerText = (von0: number, bis0: number): boolean => {
    const [von, bis] = trimmt(von0, bis0)
    if (von >= bis) return true
    const z = zweige(von, bis)
    if (z) return festerText(z[0], z[1]) && festerText(z[2], z[3])
    return plusTeile(von, bis).every(([x, y]) => {
      const [p, q] = trimmt(x, y)
      if (p >= q) return true
      const s = literalGenau(p, q)
      if (s) return s.teile.every(([ta, tb]) => festerText(ta, tb))
      const w = bare.slice(p, q)
      if (feste.has(w) || /^\d[\d_.]*$/.test(w)) return true
      if (bare[p] === '(' && klammerEnde(p) === q - 1) return festerText(p + 1, q - 1)
      const h = HTML_HARMLOS.exec(w)
      return h !== null && klammerEnde(p + h[0].length - 1) === q - 1
    })
  }

  const funde: SFund[] = []
  const gemeldet = new Set<string>()
  const melden = (at: number, code: string, schwer: boolean, de: string, en: string) => {
    const nr = zeileVon(bare, at)
    if (gemeldet.has(`${code}|${nr}`) || OK_SICHER.test(roh[nr - 1] ?? '')) return
    gemeldet.add(`${code}|${nr}`)
    funde.push({ line: nr, col: at - bare.lastIndexOf('\n', at - 1), code, schwer: schwer && !pruef, scanner: t('Muster', 'pattern'), text: t(de, en) })
  }
  // Aufruf statt Festlegung: nicht "function fetch(", "async fetch(request, env) {" oder "fetch(request: Request)".
  const istDefinition = (at: number, offen: number, erstes: string): boolean => {
    if (/\b(?:function|async)\s*\*?\s*$/.test(bare.slice(Math.max(0, at - 20), at))) return true
    if (/^\s*[A-Za-z_$][\w$]*\s*\??\s*:\s*[A-Za-z_${[(]/.test(erstes)) return true
    const zu = klammerEnde(offen)
    return zu > 0 && /^\s*\{/.test(bare.slice(zu + 1, zu + 20))
  }

  // JS-SSRF
  for (const m of bare.matchAll(SSRF_AUFRUF)) {
    const at = m.index ?? 0
    const offen = at + m[0].length - 1
    const args = argumente(offen)
    const a0 = args[0]
    if (!a0 || istDefinition(at, offen, a0.text)) continue
    let ziel: [number, number] = [a0.at, a0.at + a0.text.length]
    if (/^\s*\{/.test(a0.text) && !/^new\b/.test(m[0])) {
      // axios({ url: x }) / got({ url }) : die Eigenschaft url
      const u = /[{,]\s*url\b\s*(:)?/.exec(a0.text)
      if (!u) continue
      const name = a0.at + (u.index ?? 0) + u[0].indexOf('url')
      const p = a0.at + (u.index ?? 0) + u[0].length
      ziel = u[1] ? [p, p + ausdruckAb(bare, p).length] : [name, name + 3]
    }
    if (gefaehrlicheAdresse(ziel[0], ziel[1])) {
      melden(at, 'JS-SSRF', true,
        'Die Adresse für den Abruf kommt aus der Anfrage (SSRF) - so lässt jemand den Server beliebige Adressen abrufen, auch interne. Adresse fest einbauen oder aus einer festen Liste wählen; Teile wie eine Kennung nur hinter "https://rechner/" und mit encodeURIComponent anhängen.',
        'the address being fetched comes from the request (SSRF) - anyone can make the server fetch any address, including internal ones. Use a fixed address or pick it from a fixed list; append parts like an id only after "https://host/" and with encodeURIComponent.')
    }
  }

  // JS-WEITERLEITUNG
  const weiterleitung = (at: number) =>
    melden(at, 'JS-WEITERLEITUNG', true,
      'Das Ziel der Weiterleitung kommt aus der Anfrage (offene Weiterleitung) - ein Link auf deine Seite führt so zu einer fremden Seite. Nur feste Ziele oder eigene Pfade wie "/start" aus einer festen Liste verwenden.',
      'the redirect target comes from the request (open redirect) - a link to your site then leads to a foreign site. Only use fixed targets or own paths like "/start" from a fixed list.')
  for (const m of bare.matchAll(WEITER_AUFRUF)) {
    const at = m.index ?? 0
    const args = argumente(at + m[0].length - 1)
    // res.redirect(301, ziel): die Zahl ist der Status
    const ziel = args.length >= 2 && /^\s*\d+\s*$/.test(args[0]?.text ?? '') ? args[1] : args[0]
    if (ziel && gefaehrlicheAdresse(ziel.at, ziel.at + ziel.text.length)) weiterleitung(at)
  }

  // Wert eines Kopfes: { 'Name': wert } oder aufruf('Name', wert) bzw. [['Name', wert]]. Gibt die Stelle des Werts zurück.
  const kopfWert = (s: Stelle): [number, number] | undefined => {
    const nach = /^\s*([:,])\s*/.exec(bare.slice(s.ende, s.ende + 40))
    if (!nach) return undefined
    if (nach[1] === ',' && !/[([]\s*$/.test(bare.slice(Math.max(0, s.start - 20), s.start))) return undefined
    const p = s.ende + nach[0].length
    return [p, p + ausdruckAb(bare, p).length]
  }
  const inhalt = (s: Stelle) => text.slice(s.start + 1, s.ende - 1)
  for (const s of texte) {
    if (s.teile.length > 0 || !/^location$/i.test(inhalt(s))) continue
    const w = kopfWert(s)
    if (w && gefaehrlicheAdresse(w[0], w[1])) weiterleitung(s.start)
  }
  for (const m of bare.matchAll(/[{,]\s*Location\s*:\s*/g)) {
    const p = (m.index ?? 0) + m[0].length
    if (gefaehrlicheAdresse(p, p + ausdruckAb(bare, p).length)) weiterleitung(p)
  }

  // JS-CORS
  const cors: { s: Stelle; w: [number, number] }[] = []
  let mitAnmeldung = false
  for (const s of texte) {
    if (s.teile.length > 0) continue
    const name = inhalt(s).toLowerCase()
    if (name !== 'access-control-allow-origin' && name !== 'access-control-allow-credentials') continue
    const w = kopfWert(s)
    if (!w) continue
    if (name === 'access-control-allow-origin') cors.push({ s, w })
    else {
      const [a, b] = trimmt(w[0], w[1])
      const l = literalGenau(a, b)
      if ((l && inhalt(l).trim() === 'true') || bare.slice(a, b) === 'true') mitAnmeldung = true
    }
  }
  for (const { s, w } of cors) {
    const [a, b] = trimmt(w[0], w[1])
    const l = literalGenau(a, b)
    if (l && l.teile.length === 0 && inhalt(l).trim() === '*') {
      if (mitAnmeldung) {
        melden(s.start, 'JS-CORS', true,
          'Access-Control-Allow-Origin "*" und Access-Control-Allow-Credentials true in derselben Datei - Browser lehnen das ab, und der übliche Umbau gibt den Origin ungeprüft zurück. Anmeldedaten nur zusammen mit fest eingetragenen Herkünften erlauben.',
          'Access-Control-Allow-Origin "*" and Access-Control-Allow-Credentials true in the same file - browsers reject it, and the usual fix echoes the origin unchecked. Allow credentials only together with explicitly listed origins.')
      } else {
        melden(s.start, 'JS-CORS', false,
          'Access-Control-Allow-Origin "*" lässt jede Webseite die Antwort lesen - nur für öffentliche Daten; sonst die erlaubte Herkunft fest eintragen.',
          'Access-Control-Allow-Origin "*" lets any website read the response - only for public data; otherwise set the allowed origin explicitly.')
      }
    } else if (art(bare.slice(a, b), a) === 'voll') {
      melden(s.start, 'JS-CORS', true,
        'Access-Control-Allow-Origin gibt den Origin der Anfrage ungeprüft zurück - so darf jede fremde Seite die Antwort lesen, mit Anmeldedaten auch die Daten des Benutzers. Den Origin zuerst mit einer festen Liste vergleichen (LISTE.includes(origin)).',
        'Access-Control-Allow-Origin echoes the request origin unchecked - any foreign site may read the response, with credentials also the user\'s data. Compare the origin with a fixed list first (LIST.includes(origin)).')
    }
  }

  // JS-EVAL: erstes Argument ist Text (Zeichenkette, `...`, fester Name) oder eine Kette mit Text.
  for (const m of bare.matchAll(ZEIT_AUFRUF)) {
    const at = (m.index ?? 0) + m[0].indexOf(m[1] ?? '')
    const offen = (m.index ?? 0) + m[0].length - 1
    const a0 = argumente(offen)[0]
    if (!a0 || /\bfunction\s*$/.test(bare.slice(Math.max(0, (m.index ?? 0) - 12), m.index ?? 0))) continue
    const text0 = plusTeile(a0.at, a0.at + a0.text.length).some(([x, y]) => {
      const [p, q] = trimmt(x, y)
      return literalGenau(p, q) !== undefined || feste.has(bare.slice(p, q))
    })
    if (text0) {
      melden(at, 'JS-EVAL', true,
        `${m[1]}() bekommt Text statt einer Funktion - der Text wird wie eval als Code ausgeführt. Eine Funktion übergeben, z. B. ${m[1]}(() => machWas(), 100).`,
        `${m[1]}() gets text instead of a function - the text is run as code like eval. Pass a function, e.g. ${m[1]}(() => doIt(), 100).`)
    }
  }

  // JS-XSS
  const xss = (at: number, was: string) =>
    melden(at, 'JS-XSS', true,
      `${was} setzt HTML aus nicht festem Text ein - steckt fremder Text darin, läuft fremdes Skript (XSS). Text mit textContent setzen oder das HTML vorher mit DOMPurify.sanitize bereinigen.`,
      `${was} inserts HTML from non-fixed text - if it contains foreign text, foreign script runs (XSS). Set text with textContent or clean the HTML with DOMPurify.sanitize first.`)
  for (const m of bare.matchAll(/\.\s*(insertAdjacentHTML|createContextualFragment)\s*\(/g)) {
    const at = m.index ?? 0
    const args = argumente(at + m[0].length - 1)
    const x = m[1] === 'insertAdjacentHTML' ? args[1] : args[0]
    if (x && !festerText(x.at, x.at + x.text.length)) xss(at + 1, `${m[1]}()`)
  }
  for (const m of bare.matchAll(/\bdangerouslySetInnerHTML\s*(?:=\s*\{\s*|:\s*)\{\s*__html\s*:\s*/g)) {
    const p = (m.index ?? 0) + m[0].length
    if (!festerText(p, p + ausdruckAb(bare, p).length)) xss(m.index ?? 0, 'dangerouslySetInnerHTML')
  }
  for (const m of bare.matchAll(/\.\s*srcdoc\s*=(?![=>])/g)) {
    const p = (m.index ?? 0) + m[0].length
    if (!festerText(p, p + rechteSeite(p).length)) xss((m.index ?? 0) + 1, 'srcdoc')
  }

  // JS-POSTMESSAGE: nur Nachrichten an das Fenster (addEventListener / onmessage ohne Objekt oder an window). WebSocket, Worker und
  // MessagePort (ws.onmessage, worker.onmessage, socket.addEventListener('message')) bekommen keine Nachrichten fremder Fenster.
  const definition = (name: string): string | undefined => {
    const e = name.replace(/\$/g, '\\$')
    const f = new RegExp(String.raw`\bfunction\s*\*?\s*${e}\s*\(`).exec(bare)
    if (f) {
      const zu = klammerEnde((f.index ?? 0) + f[0].length - 1)
      const auf = zu > 0 ? bare.indexOf('{', zu) : -1
      const ende = auf > 0 ? klammerEnde(auf) : -1
      if (ende > 0) return bare.slice(f.index ?? 0, ende + 1)
    }
    const v = new RegExp(String.raw`(?<![\w$])${e}\s*(?::[^=;\n]+)?[:=](?![=>])\s*`).exec(bare)
    if (v) return rechteSeite((v.index ?? 0) + v[0].length)
    const me = new RegExp(String.raw`(?<![\w$.])${e}\s*\([^()]*\)\s*\{`).exec(bare)
    if (me) {
      const auf = (me.index ?? 0) + me[0].length - 1
      const ende = klammerEnde(auf)
      if (ende > 0) return bare.slice(me.index ?? 0, ende + 1)
    }
    return undefined
  }
  const ohneHerkunft = (von: number, bis: number): boolean => {
    const [a, b] = trimmt(von, bis)
    const w = bare.slice(a, b)
    if (/^(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(w)) return !/\borigin\b/.test(w)
    const name = /^(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)(?:\s*\.\s*bind\s*\([^()]*\))?$/.exec(w)?.[1]
    const def = name ? definition(name) : undefined
    return def !== undefined && !/\borigin\b/.test(def)
  }
  const nachricht = (at: number) =>
    melden(at, 'JS-POSTMESSAGE', false,
      'Der Empfänger für Nachrichten (message) prüft die Herkunft nicht - jede fremde Seite kann ihm Nachrichten schicken. Zuerst event.origin mit der erwarteten Herkunft vergleichen.',
      'the message receiver does not check the origin - any foreign page can send it messages. Compare event.origin with the expected origin first.')
  for (const s of texte) {
    if (s.teile.length > 0 || inhalt(s) !== 'message') continue
    const vor = /(?:^|[^\w$.]|\bwindow\s*\.\s*)addEventListener\s*\(\s*$/.exec(bare.slice(Math.max(0, s.start - 60), s.start))
    if (!vor) continue
    const offen = bare.lastIndexOf('(', s.start)
    const h = argumente(offen)[1]
    if (h && ohneHerkunft(h.at, h.at + h.text.length)) nachricht(offen)
  }
  for (const m of bare.matchAll(/(?:\bwindow\s*\.\s*|(?<![\w$.]))onmessage\s*=(?![=>])/g)) {
    const p = (m.index ?? 0) + m[0].length
    if (ohneHerkunft(p, p + rechteSeite(p).length)) nachricht(m.index ?? 0)
  }

  // JS-JWT
  if (!JWT_PRUEFT.test(bare)) {
    for (const m of bare.matchAll(JWT_DECODE)) {
      const was = /decodeJwt/.test(m[0]) ? 'decodeJwt()' : 'jwt.decode()'
      melden(m.index ?? 0, 'JS-JWT', false,
        `${was} liest das Token, ohne die Unterschrift zu prüfen, und die Datei prüft nirgends (verify/jwtVerify) - ein gefälschtes Token gilt so als echt. Vor dem Vertrauen jwt.verify bzw. jwtVerify verwenden.`,
        `${was} reads the token without checking the signature, and the file never verifies (verify/jwtVerify) - a forged token is accepted as real. Use jwt.verify or jwtVerify before trusting it.`)
    }
  }
  return funde.sort((a, b) => a.line - b.line || a.col - b.col)
}

// ---- Wrangler-Einstellungen: Geheimnisse unter vars (Cloudflare: "Do not use vars to store sensitive information in your Worker's
// Wrangler configuration file. Use secrets instead."). Geheim ist ein Name, dessen LETZTER Teil ein Geheimnis-Wort ist (API_KEY,
// GITHUB_TOKEN, DB_PASSWORD, JWT_SECRET, OPENAI_API, apiKey; dazu CODEWORT/KENNWORT - ein Worker des Entwicklers heisst sein Geheimnis
// env.CODEWORT), nicht wenn es nur vorne steht (API_URL, KEY_PREFIX, TOKEN_TTL). Öffentliche Schlüssel (PUBLIC/PUBLISHABLE/SITE im
// Namen, z. B. Turnstile-sitekey "a public identifier you place in your HTML") sind kein Geheimnis. Leere Werte, Wahrheitswerte,
// Tabellen und Platzhalter (wie bei den eingebauten Schlüsseln) zählen nicht.
export const WRANGLER_DATEI = /(?:^|[\\/])wrangler\.(?:toml|jsonc?)$/i
const GEHEIM_ENDE = /(?:token|secret|key|passwor[dt]|passwd|kennwort|codewort)$/i
const OEFFENTLICH = /^(?:public|publishable|site)$/i
type VarEintrag = { name: string; line: number; col: number; wert: string | undefined }

function geheimerName(name: string): boolean {
  const teile = name.replace(/([a-z\d])([A-Z])/g, '$1_$2').split(/[^A-Za-z\d]+/).filter(Boolean)
  const letzter = teile[teile.length - 1] ?? ''
  if (teile.some(x => OEFFENTLICH.test(x))) return false
  return GEHEIM_ENDE.test(letzter) || /^api$/i.test(letzter)
}

// Ein Tabellen- oder Schlüsselname in TOML: Teile an den Punkten ausserhalb von Anführungszeichen, ohne die Anführungszeichen.
function tomlSchluessel(s: string): string[] {
  return [...s.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|([^.\s"']+)/g)].map(m => m[1] ?? m[2] ?? m[3] ?? '')
}

// Zeile ohne # -Kommentar (ausserhalb von Texten); Spalten bleiben gleich.
function tomlOhneKommentar(z: string): string {
  let q = ''
  for (let k = 0; k < z.length; k++) {
    const c = z[k]
    if (q) {
      if (c === '\\' && q === '"') k++
      else if (c === q) q = ''
    } else if (c === '"' || c === "'") q = c
    else if (c === '#') return z.slice(0, k)
  }
  return z
}

// Wert hinter "=": Text (auch """...""" über mehrere Zeilen), Zahl oder Datum als Text; Wahrheitswert, Tabelle und Liste: undefined.
function tomlWert(rest: string, zeilen: string[], i: number): string | undefined {
  const r = rest.trim()
  const drei = /^("""|''')/.exec(r)
  if (drei) {
    const zu = drei[1] ?? '"""'
    let alles = r.slice(3)
    for (let k = i + 1; !alles.includes(zu) && k < zeilen.length && k < i + 200; k++) alles += `\n${zeilen[k] ?? ''}`
    const e = alles.indexOf(zu)
    return e < 0 ? alles : alles.slice(0, e)
  }
  const s = /^"((?:[^"\\]|\\.)*)"|^'([^']*)'/.exec(r)
  if (s) return s[1] ?? s[2] ?? ''
  if (r === '' || /^(?:true|false)\b|^[{[]/.test(r)) return undefined
  return r
}

function tomlVars(text: string): VarEintrag[] {
  const out: VarEintrag[] = []
  const zeilen = text.split(/\r?\n/)
  const istVars = (p: string[]) => (p.length === 1 && p[0] === 'vars') || (p.length === 3 && p[0] === 'env' && p[2] === 'vars')
  let tabelle: string[] = []
  for (let i = 0; i < zeilen.length; i++) {
    const z = tomlOhneKommentar(zeilen[i] ?? '')
    if (/^\s*\[\[/.test(z)) {
      tabelle = ['[['] // Liste von Tabellen ([[kv_namespaces]] ...): keine vars
      continue
    }
    const kopf = /^\s*\[([^[\]]*)\]\s*$/.exec(z)
    if (kopf) {
      tabelle = tomlSchluessel(kopf[1] ?? '')
      continue
    }
    const kv = /^(\s*)((?:"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)(?:\s*\.\s*(?:"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+))*)\s*=(.*)$/.exec(z)
    if (!kv) continue
    const pfad = [...tabelle, ...tomlSchluessel(kv[2] ?? '')]
    const rest = kv[3] ?? ''
    if (pfad.length > 1 && istVars(pfad.slice(0, -1))) {
      out.push({ name: pfad[pfad.length - 1] ?? '', line: i + 1, col: (kv[1] ?? '').length + 1, wert: tomlWert(rest, zeilen, i) })
    } else if (istVars(pfad) && rest.trim().startsWith('{')) {
      // vars = { API_KEY = "...", NAME = "..." } in einer Zeile
      const start = z.length - rest.length
      for (const p of rest.matchAll(/(?:^\s*\{|,)\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^,}]*)/g)) {
        const name = tomlSchluessel(p[1] ?? '')[0] ?? ''
        out.push({ name, line: i + 1, col: start + (p.index ?? 0) + p[0].indexOf(p[1] ?? '') + 1, wert: tomlWert(p[2] ?? '', [], 0) })
      }
    }
  }
  return out
}

// wrangler.json / wrangler.jsonc: "vars" oben oder unter "env": { "<name>": { "vars": ... } }. Kommentare und Kommas am Ende erlaubt.
function jsonVars(text: string): VarEintrag[] {
  const { bare, texte } = jsBereinigt(text)
  const beiStart = new Map<number, Stelle>(texte.map(s => [s.start, s]))
  const n = bare.length
  const out: VarEintrag[] = []
  const istVars = (p: string[]) => (p.length === 1 && p[0] === 'vars') || (p.length === 3 && p[0] === 'env' && p[2] === 'vars')
  let i = 0
  const weiter = (mitKomma: boolean) => {
    while (i < n && (/\s/.test(bare[i] ?? '') || (mitKomma && bare[i] === ','))) i++
  }
  const wert = (pfad: string[], tiefe: number): void => {
    weiter(true)
    const c = bare[i]
    if (c === '{') return objekt(pfad, tiefe)
    if (c === '[') {
      i++
      while (i < n) {
        weiter(true)
        if (bare[i] === ']') {
          i++
          return
        }
        const vor = i
        wert([...pfad, '[]'], tiefe + 1)
        if (i === vor) i++
      }
      return
    }
    const s = beiStart.get(i)
    if (s) {
      i = s.ende
      return
    }
    while (i < n && !/[\s,\]}]/.test(bare[i] ?? '')) i++
  }
  function objekt(pfad: string[], tiefe: number): void {
    i++
    while (i < n) {
      weiter(true)
      if (bare[i] === '}') {
        i++
        return
      }
      const s = beiStart.get(i)
      if (!s || tiefe > 100) {
        i++
        continue
      }
      const name = text.slice(s.start + 1, s.ende - 1)
      i = s.ende
      weiter(false)
      if (bare[i] !== ':') continue
      i++
      weiter(false)
      if (istVars(pfad)) {
        const w = beiStart.get(i)
        const roh = /^[^\s,\]}]*/.exec(bare.slice(i, i + 200))?.[0] ?? ''
        const zahl = /^-?\d/.test(roh) ? roh : undefined
        out.push({ name, line: zeileVon(bare, s.start), col: s.start - bare.lastIndexOf('\n', s.start - 1), wert: w ? text.slice(w.start + 1, w.ende - 1) : zahl })
      }
      wert([...pfad, name], tiefe + 1)
    }
  }
  weiter(true)
  if (bare[i] === '{') objekt([], 0)
  return out
}

export function wranglerMuster(text: string, file: string): SFund[] {
  if (!WRANGLER_DATEI.test(file)) return []
  const pruef = PRUEF_PFAD.test(file)
  const roh = text.split(/\r?\n/)
  const funde: SFund[] = []
  for (const e of /\.toml$/i.test(file) ? tomlVars(text) : jsonVars(text)) {
    const w = e.wert?.trim() ?? ''
    if (!geheimerName(e.name) || w === '' || PLATZHALTER.test(w) || OK_SICHER.test(roh[e.line - 1] ?? '')) continue
    const name = e.name.replace(/[^\w.-]/g, '_').slice(0, 60)
    funde.push({ line: e.line, col: e.col, code: 'WRANGLER-GEHEIMNIS', schwer: !pruef, scanner: t('Muster', 'pattern'), geheim: true,
      text: t(`«${name}» steht unter vars in der Wrangler-Datei (Wert verborgen) - vars sind kein Geheimnis-Speicher (Cloudflare: "Do not use vars to store sensitive information"). Mit "npx wrangler secret put ${name}" als Secret anlegen und hier löschen.`,
        `«${name}» is under vars in the Wrangler file (value hidden) - vars are not a secret store (Cloudflare: "Do not use vars to store sensitive information"). Create it as a secret with "npx wrangler secret put ${name}" and delete it here.`) })
  }
  return funde
}
