import { expect, test } from 'claude-code/testing'
import { WRANGLER_DATEI, jsZusatzMuster, wranglerMuster } from './js_worker'

// Erwartungen aus dem Auftrag vom 27.11.2026 (Bauplan "Höchstes Niveau", Stufe 1 Punkt 6). Fund als Code, "!" = rot, @Zeile.
const art = (text: string, file = 'D:\\w\\worker.js') => jsZusatzMuster(text, file).map(f => `${f.code}${f.schwer ? '!' : ''}@${f.line}`)
const wr = (text: string, file = 'D:\\w\\wrangler.toml') => wranglerMuster(text, file).map(f => `${f.code}${f.schwer ? '!' : ''}@${f.line}`)
const OK = '// code-waechter:ok SICHERHEIT'

test('JS-SSRF: Adresse aus der Anfrage (Worker und Express) ist ein Fehler, auch über Variablen und zusammengesetzt', () => {
  expect(art("export default { async fetch(request) {\n  const url = new URL(request.url)\n  const ziel = url.searchParams.get('u')\n  return fetch(ziel)\n} }")).toEqual(['JS-SSRF!@4'])
  expect(art("async function h(request) {\n  return fetch(new URL(request.url).searchParams.get('u'))\n}")).toEqual(['JS-SSRF!@2'])
  // Proxy über den Pfad: https://worker/https://fremd.ch
  expect(art('async function h(request) {\n  const ziel = new URL(request.url).pathname.slice(1)\n  return fetch(ziel)\n}')).toEqual(['JS-SSRF!@3'])
  expect(art("app.get('/p', async (req, res) => {\n  const r = await axios.get(req.query.url)\n})")).toEqual(['JS-SSRF!@2'])
  expect(art('got(req.body.adresse)')).toEqual(['JS-SSRF!@1'])
  expect(art('axios({ method: "get", url: req.query.u })')).toEqual(['JS-SSRF!@1'])
  expect(art('async function h(request) {\n  const daten = await request.json()\n  return fetch(new Request(daten.ziel))\n}')).toEqual(['JS-SSRF!@3'])
  expect(art('async function h(request) {\n  const { host } = await request.json()\n  return fetch(`https://${host}/api`)\n}')).toEqual(['JS-SSRF!@3'])
  // Fester Anfang ohne / nach dem Rechner: ".fremd.ch" oder "@fremd.ch" dahinter wechselt den Rechner
  expect(art("async function h(request) {\n  const { id } = await request.json()\n  return fetch('https://api.fest.ch' + id)\n}")).toEqual(['JS-SSRF!@3'])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  url.hostname = url.searchParams.get('h')\n  return fetch(url)\n}")).toEqual(['JS-SSRF!@4'])
  expect(art("async function h(request) {\n  return fetch(request.headers.get('X-Ziel'))\n}")).toEqual(['JS-SSRF!@2'])
})

test('JS-SSRF: eigene Adresse, fester Rechner, Liste, Prüfung, Text, Festlegung, fremdes Objekt und Prüfdatei sind kein Fehler', () => {
  expect(art('async function h(request) {\n  return fetch(request.url)\n}')).toEqual([])
  expect(art('async function h(request) {\n  return fetch(request)\n}')).toEqual([])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  url.hostname = 'backend.fest.ch'\n  return fetch(url, request)\n}")).toEqual([])
  expect(art("async function h(request) {\n  const { id } = await request.json()\n  return fetch('https://api.fest.ch/items/' + id)\n}")).toEqual([])
  expect(art("const BASIS = 'https://api.fest.ch/'\nasync function h(request) {\n  const { id } = await request.json()\n  return fetch(BASIS + id)\n}")).toEqual([])
  expect(art("async function h(request, env) {\n  const id = new URL(request.url).searchParams.get('id')\n  return fetch(`${env.BASIS}/x/${encodeURIComponent(id)}`)\n}")).toEqual([])
  expect(art("async function h(request) {\n  const z = new URL(request.url).searchParams.get('z')\n  return fetch(ZIELE[z])\n}")).toEqual([])
  expect(art("async function h(request) {\n  const z = new URL(request.url).searchParams.get('z')\n  if (!ERLAUBT.includes(z)) return new Response('nein', { status: 400 })\n  return fetch(z)\n}")).toEqual([])
  expect(art("async function h(request) {\n  const z = new URL(request.url).searchParams.get('z')\n  if (new URL(z).origin !== 'https://api.fest.ch') return\n  return fetch(z)\n}")).toEqual([])
  expect(art("async function h(request) {\n  const z = new URL(request.url).searchParams.get('z')\n  if (z !== 'https://api.fest.ch/a') return\n  return fetch(z)\n}")).toEqual([])
  expect(art("// fetch(new URL(request.url).searchParams.get('u'))\nconst s = \"fetch(req.query.u)\"")).toEqual([])
  expect(art("export default {\n  async fetch(request, env) {\n    return new Response('ok')\n  },\n}")).toEqual([])
  expect(art('async function h(request, env) {\n  return env.DIENST.fetch(request.headers.get("x"))\n}')).toEqual([])
  // Gemessen 27.11.2026 an make-fetch-happen und minipass-fetch: Funktion in einer Variable, Einstellungen von new Request(...)
  expect(art("const weiter = (request) => {\n  request.headers.delete('cookie')\n  return {}\n}\nconst r = weiter(request)\nfetch(r.request, r.options)")).toEqual([])
  expect(art('const opts = { headers: new Headers(request.headers) }\nfetch(new Request(ziel, opts))')).toEqual([])
  expect(art(`fetch(req.query.u) ${OK}`)).toEqual([])
  // Prüfdatei: nur ein Hinweis
  expect(art("async function h(request) {\n  return fetch(new URL(request.url).searchParams.get('u'))\n}", 'D:\\w\\worker.test.js')).toEqual(['JS-SSRF@2'])
  expect(art('got(req.body.adresse)', 'D:\\w\\Tests\\a.ts')).toEqual(['JS-SSRF@1'])
})

test('JS-SSRF: eine echte Gedächtnis-Suche (Worker) bleibt ohne Fund', () => {
  const worker = [
    'export default {',
    '  async fetch(request, env) {',
    '    if (request.method !== "POST") return antwort({ fehler: "nur POST" }, 405);',
    '    if (!env.CODEWORT || !gleich(request.headers.get("X-Codewort") ?? "", env.CODEWORT)) {',
    '      return antwort({ fehler: "kein Zugang" }, 403);',
    '    }',
    '    let koerper;',
    '    try {',
    '      koerper = await request.json();',
    '    } catch {',
    '      return antwort({ fehler: "kein JSON" }, 400);',
    '    }',
    '    const weg = new URL(request.url).pathname;',
    '    if (weg === "/suche") return await suche(env, koerper);',
    '    return antwort({ fehler: "unbekannter Weg" }, 404);',
    '  },',
    '};',
  ].join('\n')
  expect(jsZusatzMuster(worker, 'D:\\p\\such-worker\\worker.js')).toEqual([])
})

test('JS-SSRF: weitere Quellen aus dem Auftrag (req.headers, formData, text, axios(x), Worker-Anfrage namens req)', () => {
  expect(art("fetch(req.headers['x-ziel'])")).toEqual(['JS-SSRF!@1'])
  expect(art("async function h(request) {\n  const fd = await request.formData()\n  return fetch(fd.get('u'))\n}")).toEqual(['JS-SSRF!@3'])
  expect(art('async function h(request) {\n  const t = await request.text()\n  return fetch(t)\n}')).toEqual(['JS-SSRF!@3'])
  expect(art('axios(req.query.u)')).toEqual(['JS-SSRF!@1'])
  expect(art("export default { async fetch(req) {\n  return fetch(new URL(req.url).searchParams.get('u'))\n} }")).toEqual(['JS-SSRF!@2'])
  // Nicht: die eigene Adresse unter dem Namen req
  expect(art('export default { async fetch(req) {\n  return fetch(new URL(req.url))\n} }')).toEqual([])
})

// Ein Pfad (URL.pathname) beginnt bei http(s) immer mit "/": hinter "https://rechner" ändert er den Rechner nicht, allein kann er
// "//fremd.ch" sein.
test('JS-SSRF: Pfad der eigenen Adresse hinter festem Rechner ist kein Fehler; allein, gekürzt, in new URL(pfad, basis) oder nach fremder Zuweisung schon', () => {
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  return fetch('https://o.fest.ch' + url.pathname + url.search, request)\n}")).toEqual([])
  expect(art('async function h(request) {\n  const url = new URL(request.url)\n  return fetch(`https://o.fest.ch${url.pathname}`)\n}')).toEqual([])
  expect(art("async function h(request) {\n  const { pathname } = new URL(request.url)\n  return fetch('https://o.fest.ch' + pathname)\n}")).toEqual([])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  const p = url.pathname\n  return fetch('https://o.fest.ch' + p)\n}")).toEqual([])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  let p = url.pathname\n  p = url.searchParams.get('z')\n  return fetch('https://o.fest.ch' + p)\n}")).toEqual(['JS-SSRF!@5'])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  return fetch(new URL(url.pathname, 'https://o.fest.ch'))\n}")).toEqual(['JS-SSRF!@3'])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  return fetch('https://o.fest.ch' + url.pathname.slice(1))\n}")).toEqual(['JS-SSRF!@3'])
  expect(art("async function h(request) {\n  const { ziel } = await request.json()\n  return fetch('https://o.fest.ch' + new URL(ziel).pathname)\n}")).toEqual(['JS-SSRF!@3'])
  expect(art('async function h(request) {\n  const url = new URL(request.url)\n  return Response.redirect(url.pathname)\n}')).toEqual(['JS-WEITERLEITUNG!@3'])
})

test('JS-WEITERLEITUNG: Ziel aus der Anfrage ist ein Fehler (Response.redirect, res.redirect, Location)', () => {
  expect(art("export default { async fetch(request) {\n  const next = new URL(request.url).searchParams.get('next')\n  return Response.redirect(next, 302)\n} }")).toEqual(['JS-WEITERLEITUNG!@3'])
  expect(art("app.get('/l', (req, res) => {\n  res.redirect(req.query.to)\n})")).toEqual(['JS-WEITERLEITUNG!@2'])
  expect(art("app.get('/l', (req, res) => {\n  res.redirect(301, req.query.to)\n})")).toEqual(['JS-WEITERLEITUNG!@2'])
  expect(art('async function h(request) {\n  const { to } = await request.json()\n  return new Response(null, { status: 302, headers: { Location: to } })\n}')).toEqual(['JS-WEITERLEITUNG!@3'])
  expect(art("async function h(request) {\n  const to = new URL(request.url).searchParams.get('to')\n  return new Response(null, { status: 302, headers: { 'Location': to } })\n}")).toEqual(['JS-WEITERLEITUNG!@3'])
  expect(art("res.setHeader('Location', req.query.z)")).toEqual(['JS-WEITERLEITUNG!@1'])
  expect(art('res.location(req.query.z)')).toEqual(['JS-WEITERLEITUNG!@1'])
  // "/" allein: "//fremd.ch" ist eine fremde Seite
  expect(art("res.redirect('/' + req.query.z)")).toEqual(['JS-WEITERLEITUNG!@1'])
})

test('JS-WEITERLEITUNG: eigene Adresse, eigener Pfad, Liste, Antwort eines Abrufs, Text, Markierung und Prüfdatei sind kein Fehler', () => {
  expect(art("async function h(request) {\n  return Response.redirect(new URL('/start', request.url), 301)\n}")).toEqual([])
  expect(art("app.get('/l', (req, res) => {\n  res.redirect('/start?x=' + req.query.to)\n})")).toEqual([])
  expect(art("async function h(request) {\n  const url = new URL(request.url)\n  return Response.redirect(url.origin + '/login')\n}")).toEqual([])
  expect(art('res.redirect(ZIELE[req.query.z])')).toEqual([])
  expect(art("async function h(request) {\n  const antwort = await fetch('https://a.ch/x')\n  return Response.redirect(antwort.headers.get('Location'))\n}")).toEqual([])
  expect(art("// res.redirect(req.query.to)\nconst s = 'res.redirect(req.query.to)'")).toEqual([])
  expect(art(`res.redirect(req.query.to) ${OK}`)).toEqual([])
  expect(art('res.redirect(req.query.to)', 'D:\\w\\Tests\\a.js')).toEqual(['JS-WEITERLEITUNG@1'])
})

test('JS-CORS: "*" ist ein Hinweis; mit Allow-Credentials true oder mit dem ungeprüften Origin der Anfrage ein Fehler', () => {
  expect(art("const h = { 'Access-Control-Allow-Origin': '*' }")).toEqual(['JS-CORS@1'])
  expect(art("headers.set('Access-Control-Allow-Origin', '*')")).toEqual(['JS-CORS@1'])
  expect(art("const h = {\n  'Access-Control-Allow-Origin': '*',\n  'Access-Control-Allow-Credentials': 'true',\n}")).toEqual(['JS-CORS!@2'])
  expect(art("res.setHeader('Access-Control-Allow-Origin', '*')\nres.setHeader('Access-Control-Allow-Credentials', true)")).toEqual(['JS-CORS!@1'])
  expect(art("async function h(request) {\n  return new Response('x', { headers: { 'Access-Control-Allow-Origin': request.headers.get('Origin') } })\n}")).toEqual(['JS-CORS!@2'])
  expect(art("res.header('Access-Control-Allow-Origin', req.headers.origin)")).toEqual(['JS-CORS!@1'])
  expect(art("async function h(request) {\n  const o = request.headers.get('Origin')\n  return new Response('x', { headers: { 'Access-Control-Allow-Origin': o } })\n}")).toEqual(['JS-CORS!@3'])
})

test('JS-CORS: feste oder geprüfte Herkunft, Lesen des Kopfes, Credentials false, Text, Markierung und Prüfdatei sind kein Fehler', () => {
  expect(art("const h = { 'Access-Control-Allow-Origin': 'https://a.ch' }")).toEqual([])
  expect(art("async function h(request) {\n  const o = request.headers.get('Origin')\n  const erlaubt = ERLAUBT.includes(o) ? o : ERLAUBT[0]\n  return new Response('x', { headers: { 'Access-Control-Allow-Origin': erlaubt } })\n}")).toEqual([])
  expect(art("async function h(request) {\n  const o = request.headers.get('Origin')\n  if (o !== 'https://a.ch') return\n  return new Response('x', { headers: { 'Access-Control-Allow-Origin': o } })\n}")).toEqual([])
  expect(art("const a = antwort.headers.get('Access-Control-Allow-Origin')")).toEqual([])
  expect(art("const h = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'false' }")).toEqual(['JS-CORS@1'])
  expect(art("// 'Access-Control-Allow-Origin': '*'\nconst s = \"'Access-Control-Allow-Origin': '*'\"")).toEqual([])
  expect(art(`const h = { 'Access-Control-Allow-Origin': '*' } ${OK}`)).toEqual([])
  expect(art("const h = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }", 'D:\\w\\cors.test.ts')).toEqual(['JS-CORS@1'])
})

test('JS-EVAL: setTimeout/setInterval/setImmediate mit Text ist ein Fehler, mit einer Funktion nicht', () => {
  expect(art("setTimeout('tick()', 100)")).toEqual(['JS-EVAL!@1'])
  expect(art('setInterval("pruefe()", 5000)')).toEqual(['JS-EVAL!@1'])
  expect(art('window.setTimeout(`zeige(${nr})`, 1)')).toEqual(['JS-EVAL!@1'])
  expect(art("setTimeout(code + ';', 0)")).toEqual(['JS-EVAL!@1'])
  expect(art("setImmediate('weiter()')")).toEqual(['JS-EVAL!@1'])
  expect(art("const CODE = 'tick()'\nsetTimeout(CODE, 5)")).toEqual(['JS-EVAL!@2'])
  // Nicht: Funktion, Pfeilfunktion, gebundene Funktion mit Text-Argument, fremde Methode, eigene Festlegung, Text, Kommentar
  expect(art("setTimeout(() => tick(), 100)\nsetTimeout(tick, 100)\nsetTimeout(function () { a('x') }, 5)\nsetTimeout(fn.bind(null, 'x'), 1)")).toEqual([])
  expect(art("uhr.setTimeout('x', 1)\nfunction setTimeout(code) { return code }")).toEqual([])
  expect(art("// setTimeout('tick()', 100)\nconst s = \"setTimeout('tick()', 100)\"")).toEqual([])
  expect(art(`setTimeout('tick()', 100) ${OK}`)).toEqual([])
  expect(art("setTimeout('tick()', 100)", 'D:\\w\\uhr.test.js')).toEqual(['JS-EVAL@1'])
})

test('JS-XSS: HTML aus nicht festem Text ist ein Fehler (insertAdjacentHTML, dangerouslySetInnerHTML, srcdoc, createContextualFragment)', () => {
  expect(art("el.insertAdjacentHTML('beforeend', html)")).toEqual(['JS-XSS!@1'])
  expect(art("el.insertAdjacentHTML('afterbegin', `<li>${name}</li>`)")).toEqual(['JS-XSS!@1'])
  expect(art('const A = () => <div dangerouslySetInnerHTML={{ __html: text }} />', 'D:\\w\\a.tsx')).toEqual(['JS-XSS!@1'])
  expect(art("React.createElement('div', { dangerouslySetInnerHTML: { __html: text } })")).toEqual(['JS-XSS!@1'])
  expect(art('frame.srcdoc = inhalt')).toEqual(['JS-XSS!@1'])
  expect(art("const f = range.createContextualFragment('<p>' + name + '</p>')")).toEqual(['JS-XSS!@1'])
})

test('JS-XSS: fester Text, bereinigtes HTML, Bedingung mit festen Texten, Text, Markierung und Prüfdatei sind kein Fehler', () => {
  expect(art("el.insertAdjacentHTML('beforeend', '<b>fest</b>')\nel.insertAdjacentHTML('beforeend', `<hr>`)")).toEqual([])
  expect(art("el.insertAdjacentHTML('beforeend', DOMPurify.sanitize(html))\nel.insertAdjacentHTML('beforeend', `<li>${escapeHtml(name)}</li>`)")).toEqual([])
  expect(art("el.insertAdjacentHTML('beforeend', aktiv ? '<b>an</b>' : '')\nconst ZEILE = '<tr></tr>'\nel.insertAdjacentHTML('beforeend', ZEILE)")).toEqual([])
  expect(art("frame.srcdoc = ''\nel.insertAdjacentHTML('beforeend', `<td>${Number(n)}</td>`)")).toEqual([])
  expect(art('const B = () => <div dangerouslySetInnerHTML={{ __html: \'<b>x</b>\' }} />', 'D:\\w\\b.tsx')).toEqual([])
  expect(art("// el.insertAdjacentHTML('beforeend', html)\nconst s = 'frame.srcdoc = inhalt'")).toEqual([])
  expect(art(`frame.srcdoc = inhalt ${OK}`)).toEqual([])
  expect(art('frame.srcdoc = inhalt', 'D:\\w\\Pruefung\\a.js')).toEqual(['JS-XSS@1'])
})

test('JS-POSTMESSAGE: Empfänger am Fenster ohne Prüfung von origin ist ein Hinweis', () => {
  expect(art("window.addEventListener('message', (e) => {\n  machWas(e.data)\n})")).toEqual(['JS-POSTMESSAGE@1'])
  expect(art('addEventListener("message", function (e) { machWas(e.data) })')).toEqual(['JS-POSTMESSAGE@1'])
  expect(art("function empfang(e) {\n  machWas(e.data)\n}\nwindow.addEventListener('message', empfang)")).toEqual(['JS-POSTMESSAGE@4'])
  expect(art('window.onmessage = (e) => {\n  machWas(e.data)\n}')).toEqual(['JS-POSTMESSAGE@1'])
  expect(art('onmessage = function (e) { machWas(e.data) }')).toEqual(['JS-POSTMESSAGE@1'])
  // Nicht: mit Prüfung (auch im benannten Empfänger), WebSocket/Worker/MessagePort, unbekannter Empfänger, anderes Ereignis, Text
  expect(art("window.addEventListener('message', (e) => {\n  if (e.origin !== 'https://a.ch') return\n  machWas(e.data)\n})")).toEqual([])
  expect(art("const empfang = (e) => {\n  if (e.origin !== ERLAUBT) return\n}\nwindow.addEventListener('message', empfang)")).toEqual([])
  expect(art("ws.addEventListener('message', (e) => machWas(e.data))\nworker.onmessage = (e) => machWas(e.data)\nport.onmessage = (e) => machWas(e.data)")).toEqual([])
  expect(art("import { empfang } from './empfang'\nwindow.addEventListener('message', empfang)")).toEqual([])
  expect(art("window.addEventListener('click', (e) => machWas(e))")).toEqual([])
  expect(art("// window.addEventListener('message', (e) => machWas(e.data))\nconst s = \"onmessage = (e) => machWas(e.data)\"")).toEqual([])
  expect(art(`window.addEventListener('message', (e) => machWas(e.data)) ${OK}`)).toEqual([])
})

test('JS-JWT: jwt.decode / decodeJwt ohne verify / jwtVerify in der Datei ist ein Hinweis', () => {
  expect(art('const daten = jwt.decode(token)')).toEqual(['JS-JWT@1'])
  expect(art("import { decodeJwt } from 'jose'\nconst daten = decodeJwt(token)")).toEqual(['JS-JWT@2'])
  expect(art('const daten = jsonwebtoken.decode(token)')).toEqual(['JS-JWT@1'])
  expect(art('const kopf = jose.decodeJwt(token)')).toEqual(['JS-JWT@1'])
  // Nicht: die Datei prüft auch, Text, Kommentar, Markierung
  expect(art('const daten = jwt.decode(token)\njwt.verify(token, schluessel)')).toEqual([])
  expect(art("import { decodeJwt, jwtVerify } from 'jose'\nconst kopf = decodeJwt(token)\nawait jwtVerify(token, schluessel)")).toEqual([])
  expect(art("// jwt.decode(token)\nconst s = 'decodeJwt(token)'")).toEqual([])
  expect(art(`const daten = jwt.decode(token) ${OK}`)).toEqual([])
})

// Werte aus Teilen, damit die Prüfdatei selbst keinen Schlüssel enthält.
const W1 = ['abc', '123', 'def', '456'].join('')
const W2 = ['xyz', '789', 'uvw'].join('')

test('WRANGLER-GEHEIMNIS: Geheimnis unter vars (toml, json, jsonc) ist ein Fehler, Wert verborgen', () => {
  const toml = [
    'name = "w"',
    '[vars]',
    `API_KEY = "${W1}"`,
    'API_URL = "https://api.fest.ch"',
    '[env.production.vars]',
    `GITHUB_TOKEN = '${W2}'`,
    `apiKey = "${W2}"`,
    '[env.production]',
    `vars = { DB_PASSWORD = "${W1}", MODUS = "a" }`,
  ].join('\n')
  expect(wr(toml)).toEqual(['WRANGLER-GEHEIMNIS!@3', 'WRANGLER-GEHEIMNIS!@6', 'WRANGLER-GEHEIMNIS!@7', 'WRANGLER-GEHEIMNIS!@9'])
  expect(wr(`vars.JWT_SECRET = "${W1}"\n[vars]\nOPENAI_API = "${W2}"\nADMIN_PASSWORT = """\n${W1}\n"""\nCODEWORT = "${W2}"`)).toEqual(['WRANGLER-GEHEIMNIS!@1', 'WRANGLER-GEHEIMNIS!@3', 'WRANGLER-GEHEIMNIS!@4', 'WRANGLER-GEHEIMNIS!@7'])
  const jsonc = `{\n  // Kommentar\n  "name": "w",\n  "vars": {\n    "API_KEY": "${W1}",\n    "API_URL": "https://x.ch",\n  },\n  "env": { "staging": { "vars": { "JWT_SECRET": "${W2}" } } }\n}`
  expect(wr(jsonc, 'D:\\w\\wrangler.jsonc')).toEqual(['WRANGLER-GEHEIMNIS!@5', 'WRANGLER-GEHEIMNIS!@8'])
  expect(wr(`{ "vars": { "SECRET": "${W1}" } }`, 'D:\\w\\wrangler.json')).toEqual(['WRANGLER-GEHEIMNIS!@1'])
  const f = wranglerMuster(`[vars]\nAPI_KEY = "${W1}"`, 'D:\\w\\wrangler.toml')[0]
  expect(f?.geheim).toBe(true)
  expect(f?.text.includes(W1)).toBe(false)
  expect(f?.text.includes('API_KEY')).toBe(true)
})

test('WRANGLER-GEHEIMNIS: harmlose Namen, öffentliche Schlüssel, leer, Platzhalter, ausserhalb von vars, Kommentar, Markierung, Prüfdatei', () => {
  expect(wr(`[vars]\nAPI_URL = "https://a.ch"\nKEY_PREFIX = "${W1}"\nTOKEN_TTL = 3600\nPUBLIC_KEY = "${W1}"\nTURNSTILE_SITE_KEY = "${W2}"`)).toEqual([])
  expect(wr('[vars]\nAPI_KEY = ""\nGITHUB_TOKEN = "dein-token-hier"\nUSE_TOKEN = true\nSECRET = { a = 1 }')).toEqual([])
  expect(wr(`[[kv_namespaces]]\nAPI_KEY = "${W1}"\n[env.production]\nAPI_KEY = "${W1}"`)).toEqual([])
  expect(wr(`[vars]\n# API_KEY = "${W1}"\nMODUS = "a" # API_KEY = "${W1}"`)).toEqual([])
  expect(wr(`[vars]\nAPI_KEY = "${W1}" # code-waechter:ok SICHERHEIT`)).toEqual([])
  expect(wr(`{ "durable_objects": { "vars": { "API_KEY": "${W1}" } }, "API_KEY": "${W1}" }`, 'D:\\w\\wrangler.json')).toEqual([])
  expect(wr(`[vars]\nAPI_KEY = "${W1}"`, 'D:\\w\\Tests\\wrangler.toml')).toEqual(['WRANGLER-GEHEIMNIS@2'])
  expect(wr(`[vars]\nAPI_KEY = "${W1}"`, 'D:\\w\\config.toml')).toEqual([])
  expect(['wrangler.toml', 'wrangler.json', 'wrangler.jsonc', 'wrangler.toml.bak', 'mywrangler.toml'].map(n => WRANGLER_DATEI.test(`D:\\w\\${n}`))).toEqual([true, true, true, false, false])
})
