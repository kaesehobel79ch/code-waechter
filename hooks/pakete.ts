// Regel "neue Pakete prüfen" (27.11.2026, Bauplan "Alle drei Stufen"): steht in einer Paketliste ein Paket, das es vorher
// nicht gab, fragt der Wächter die offizielle Paketquelle, ob es das Paket gibt. Geschickt wird NUR der Paketname, nie ein Dateiinhalt
// (keine Projektdaten an fremde Server).
//
// Anlass und Belege (an der Quelle gelesen 27.11.2026):
//   Spracklen u. a., "We Have a Package for You!", USENIX Security 2025 (arxiv.org/abs/2406.10279): bei 576'000 erzeugten
//     Codebeispielen waren im Mittel mindestens 5,2 % (kommerzielle Modelle) bzw. 21,7 % (offene Modelle) der genannten Pakete erfunden.
//     Angreifer legen solche Namen als Schadpaket an ("Slopsquatting").
//   Endor Labs, 13.07.2026 (endorlabs.com/learn/when-ai-imports-vulnerable-dependencies-securing-ai-generated-code): "49% of
//     dependency versions imported by AI coding agents had known vulnerabilities".
//   OpenSSF, "Security-Focused Guide for AI Code Assistant Instructions", 01.08.2025 (best.openssf.org): "Do not add dependencies
//     that may be malicious or hallucinated" und "Specify version ranges or exact versions".
//
// Paketlisten: .csproj/.vbproj/.fsproj (PackageReference), Directory.Packages.props (PackageVersion, GlobalPackageReference),
// packages.config, requirements*.txt, pyproject.toml ([project], [project.optional-dependencies], [tool.poetry.dependencies]),
// package.json (dependencies, devDependencies, peerDependencies, optionalDependencies).
//
// Abfragen (je mit curl.exe, -s -o NUL -w "%{http_code}" --max-time 10; 200 = gibt es, 404 = gibt es nicht, alles andere = Lücke):
//   NuGet  zuerst der eigene Paketordner (<nugetOrdner>\<name klein>), sonst https://api.nuget.org/v3-flatcontainer/<name klein>/index.json
//          (learn.microsoft.com/nuget/api/package-base-address-resource: "If the package source has no versions of the provided
//          package ID, a 404 status code is returned"; LOWER_ID = ToLowerInvariant)
//   PyPI   https://pypi.org/pypi/<name>/json (docs.pypi.org/api/json: "GET /pypi/<project>/json"); der Name nach
//          packaging.python.org/specifications/name-normalization (re.sub(r"[-_.]+", "-", name).lower())
//   npm    https://registry.npmjs.org/<name> (github.com/npm/registry/blob/main/docs/responses/package-metadata.md, mit der dort
//          genannten Kurzfassung "application/vnd.npm.install-v1+json"); @scope/name als @scope%2fname wie npm selbst
//          (escapedName in github.com/npm/npm-package-arg)
//
// Nur Namen nach den Regeln der Quelle gehen in eine Adresse (sonst Hinweis PAKET-NAME):
//   NuGet  ^\w+([.-]\w+)*$ und höchstens 100 Zeichen (NuGet.Client, PackageIdValidator.cs); hier nur ASCII
//   PyPI   ^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$ ohne Gross/Klein (packaging.python.org, name-normalization)
//   npm    höchstens 214 Zeichen, nicht mit . oder _ am Anfang, nur Zeichen, die in einer Adresse nichts bedeuten, nicht
//          node_modules/favicon.ico (github.com/npm/validate-npm-package-name)

import { t } from './i18n'
import { daten } from './sicherheit'
import type { SFund, Umgebung } from './sicherheit'

export type Oekosystem = 'nuget' | 'pypi' | 'npm'

// version: wie in der Datei ('' = keine Fassung angegeben). zeile: ab 1. datei: wo das Paket steht (für die zentrale
// Fassungsverwaltung von NuGet). zentral: die Projektdatei schaltet ManagePackageVersionsCentrally selbst ein (true) oder aus (false).
// eigeneQuelle: die Datei nennt eine eigene Paketquelle (pip -i/--extra-index-url/-f/--no-index, pyproject [tool.*.source|index]).
export type Paket = {
  oekosystem: Oekosystem
  name: string
  version: string
  zeile: number
  datei: string
  zentral?: boolean
  eigeneQuelle?: boolean
}

export type PaketUmgebung = {
  run: Umgebung['run']
  // %NUGET_PACKAGES% oder %USERPROFILE%\.nuget\packages (learn.microsoft.com/nuget/consume-packages/managing-the-global-packages-and-cache-folders)
  nugetOrdner: string
  exists: (p: string) => Promise<boolean>
}

export const CURL = 'C:\\Windows\\System32\\curl.exe'
export const MAX_ABFRAGEN = 20
const CURL_ZEIT_S = '10'
// curl bricht nach 10 s selbst ab; 5 s Reserve für den Start des Programms.
const LAUF_MS = 15000

const PROJEKT = /\.(?:cs|vb|fs)proj$/i
const ZENTRAL_DATEI = /(?:^|[\\/])Directory\.Packages\.props$/i
const PACKAGES_CONFIG = /(?:^|[\\/])packages\.config$/i
const REQUIREMENTS = /(?:^|[\\/])requirements[^\\/]*\.txt$/i
const PYPROJECT = /(?:^|[\\/])pyproject\.toml$/i
const PACKAGE_JSON = /(?:^|[\\/])package\.json$/i

// Ob eine Datei eine Paketliste ist (der Einbau liest nur dann den alten Inhalt vor dem Schreiben).
export function istPaketDatei(file: string): boolean {
  return [PROJEKT, ZENTRAL_DATEI, PACKAGES_CONFIG, REQUIREMENTS, PYPROJECT, PACKAGE_JSON].some(re => re.test(file))
}

// ---- Namensregeln und Schreibweise in der Adresse
export function pep503(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase()
}

export function nameGueltig(o: Oekosystem, name: string): boolean {
  if (o === 'nuget') return name.length <= 100 && /^[A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*$/.test(name)
  if (o === 'pypi') return /^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$/.test(name)
  return name.length <= 214 && /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/.test(name) && !/^(?:node_modules|favicon\.ico)$/i.test(name)
}

// Schlüssel eines Pakets: gleiche Schreibweise wie die Quelle (NuGet ohne Gross/Klein, PyPI normalisiert, npm genau).
const nameSchluessel = (o: Oekosystem, name: string): string => (o === 'nuget' ? name.toLowerCase() : o === 'pypi' ? pep503(name) : name)

export function adresse(o: Oekosystem, name: string): string {
  if (o === 'nuget') return `https://api.nuget.org/v3-flatcontainer/${name.toLowerCase()}/index.json`
  if (o === 'pypi') return `https://pypi.org/pypi/${pep503(name)}/json`
  return `https://registry.npmjs.org/${name.replace('/', '%2f')}`
}

const QUELLE: Record<Oekosystem, string> = { nuget: 'nuget.org', pypi: 'PyPI', npm: 'npm' }

// ---- Hilfen für die Zeilennummer
const zeileVon = (text: string, at: number): number => {
  let n = 1
  for (let k = 0; k < at && k < text.length; k++) if (text.charCodeAt(k) === 10) n++
  return n
}

// ---- XML (MSBuild-Projekte, Directory.Packages.props, packages.config)
// Kommentare werden Leerzeichen (Zeilen bleiben), damit <!-- <PackageReference ... /> --> nicht zählt.
function ohneXmlKommentare(text: string): string {
  return text.replace(/<!--[\s\S]*?(?:-->|$)/g, m => m.replace(/[^\r\n]/g, ' '))
}

// Zeichen aus einer Nummer; eine Nummer ausserhalb von Unicode (&#99999999;) wird nichts statt einer Ausnahme.
const zeichen = (cp: number): string => (Number.isInteger(cp) && cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '')

const xmlText = (s: string): string =>
  s.replace(/&(?:#(\d+)|#x([0-9a-fA-F]+)|(amp|lt|gt|quot|apos));/g, (_m, d: string | undefined, h: string | undefined, n: string | undefined) =>
    d ? zeichen(Number(d)) : h ? zeichen(parseInt(h, 16)) : ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" } as Record<string, string>)[n ?? ''] ?? '')

function attribute(roh: string): Map<string, string> {
  const m = new Map<string, string>()
  for (const a of roh.matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) m.set((a[1] ?? '').toLowerCase(), xmlText(a[2] ?? a[3] ?? '').trim())
  return m
}

// Start-Tag mit Attributen (Werte in Anführungszeichen dürfen > enthalten, z. B. in Condition).
const tagMuster = (namen: string): RegExp => new RegExp(`<(${namen})((?:\\s+[\\w:.-]+\\s*=\\s*(?:"[^"]*"|'[^']*'))*)\\s*(/?)>`, 'gi')

function xmlPakete(text: string, file: string): Paket[] {
  const code = ohneXmlKommentare(text)
  const out: Paket[] = []
  if (PACKAGES_CONFIG.test(file)) {
    for (const m of code.matchAll(tagMuster('package'))) {
      const a = attribute(m[2] ?? '')
      const id = a.get('id') ?? ''
      if (id !== '') out.push({ oekosystem: 'nuget', name: id, version: a.get('version') ?? '', zeile: zeileVon(code, m.index ?? 0), datei: file })
    }
    return out
  }
  const zentralDatei = ZENTRAL_DATEI.test(file)
  const schalter = /<ManagePackageVersionsCentrally(?:\s[^>]*)?>\s*(true|false)\s*<\/ManagePackageVersionsCentrally>/i.exec(code)?.[1]?.toLowerCase()
  const zentral = schalter === 'true' ? true : schalter === 'false' ? false : undefined
  for (const m of code.matchAll(tagMuster(zentralDatei ? 'PackageVersion|GlobalPackageReference' : 'PackageReference'))) {
    const a = attribute(m[2] ?? '')
    const start = m.index ?? 0
    // Fassung als Attribut oder als Kind-Element bis zum schliessenden Tag (<PackageReference Include="x"><Version>1.0</Version>...).
    let version = a.get('versionoverride') ?? a.get('version')
    if (version === undefined && m[3] !== '/') {
      const nach = start + m[0].length
      const ende = code.slice(nach).search(new RegExp(`</${m[1]}\\s*>`, 'i'))
      const innen = code.slice(nach, ende < 0 ? code.length : nach + ende)
      const kind = /<(VersionOverride|Version)\s*>([^<]*)<\/\1\s*>/i.exec(innen)
      if (kind) version = xmlText(kind[2] ?? '').trim()
    }
    const include = a.get('include')
    // Update ohne Fassung ändert nur Angaben eines vorhandenen Eintrags (PrivateAssets ...), es kommt kein Paket dazu.
    const namen = include ?? (version !== undefined ? a.get('update') : undefined) ?? ''
    for (const n of namen.split(';').map(x => x.trim()).filter(Boolean)) {
      out.push({ oekosystem: 'nuget', name: n, version: version ?? '', zeile: zeileVon(code, start), datei: file, ...(zentral !== undefined && !zentralDatei ? { zentral } : {}) })
    }
  }
  return out
}

// ---- pip: eine Anforderung nach PEP 508 (Name, Zusätze in [], Fassung, Marker nach ;). undefined: kein Paket aus der Paketquelle
// (Adresse, Pfad, Archiv, "name @ adresse") oder nicht lesbar (Umgebungsvariable ${...} im Namen).
export function pep508(roh: string): { name: string; version: string } | undefined {
  // Angaben je Anforderung (--hash=..., --config-settings=...) stehen nach Leerraum am Ende.
  const s = roh.replace(/\s--[A-Za-z][\s\S]*$/, '').trim()
  if (s === '' || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(s) || /^(?:\.{1,2}(?:[\\/]|$)|[\\/~]|[A-Za-z]:[\\/])/.test(s)) return undefined
  const m = /^([^\s[\]()<>=!~;@,]+)\s*(\[[^\]]*\])?\s*([\s\S]*)$/.exec(s)
  if (!m) return undefined
  const name = m[1] ?? ''
  if (name.includes('${') || /[\\/]/.test(name) || /\.(?:whl|zip|tar\.gz|tgz|tar\.bz2|tar\.xz)$/i.test(name)) return undefined
  const rest = m[3] ?? ''
  if (rest.startsWith('@')) return undefined
  const version = (rest.split(';')[0] ?? '').trim().replace(/^\(\s*([\s\S]*?)\s*\)$/, '$1')
  return { name, version }
}

// requirements*.txt (pip.pypa.io/en/stable/reference/requirements-file-format): \ am Zeilenende verbindet, # am Anfang oder nach
// Leerraum ist ein Kommentar, Zeilen mit - sind Einstellungen (-r/-c andere Datei, -e Ordner oder Adresse); -i, --index-url,
// --extra-index-url, --no-index, -f, --find-links nennen eine eigene Paketquelle.
function requirementsPakete(text: string, file: string): Paket[] {
  const roh = text.replace(/^\ufeff/, '').split(/\r?\n/)
  const logisch: { nr: number; text: string }[] = []
  for (let i = 0; i < roh.length; i++) {
    const nr = i + 1
    let z = roh[i] ?? ''
    while (/(?:^|[^\\])\\$/.test(z) && i + 1 < roh.length) z = z.slice(0, -1) + (roh[++i] ?? '')
    logisch.push({ nr, text: z.replace(/(?:^|\s)#.*$/, '').trim() })
  }
  const eigene = logisch.some(z => /^(?:-i\b|--index-url\b|--extra-index-url\b|--no-index\b|-f\b|--find-links\b)/.test(z.text))
  const out: Paket[] = []
  for (const z of logisch) {
    if (z.text === '' || z.text.startsWith('-')) continue
    const p = pep508(z.text)
    if (p) out.push({ oekosystem: 'pypi', name: p.name, version: p.version, zeile: z.nr, datei: file, ...(eigene ? { eigeneQuelle: true } : {}) })
  }
  return out
}

// ---- pyproject.toml: kleiner Leser für die Teile von TOML 1.0 (toml.io/en/v1.0.0), die Paketlisten brauchen: Tabellen [a.b] und
// [[a.b]], Schlüssel (auch "..." und a.b), Texte "..." '...' """...""" '''...''', Listen über mehrere Zeilen, Tabellen in { }.
// Ein Schreibfehler beendet das Lesen still: die Datei prüft der Wächter ohnehin mit dem TOML-Prüfer.
type TWert = { art: 'text'; wert: string; at: number } | { art: 'liste'; werte: TWert[] } | { art: 'tabelle'; felder: [string[], TWert][] } | { art: 'sonst' }

function tomlLesen(text: string): { pfad: string[]; wert: TWert }[] {
  const out: { pfad: string[]; wert: TWert }[] = []
  let i = 0
  const n = text.length
  const leer = (zeilen: boolean) => {
    for (;;) {
      while (i < n && (text[i] === ' ' || text[i] === '\t' || (zeilen && (text[i] === '\n' || text[i] === '\r')))) i++
      if (i < n && text[i] === '#') {
        while (i < n && text[i] !== '\n') i++
        continue
      }
      return
    }
  }
  const textLesen = (): string | undefined => {
    const q = text[i]
    if (q !== '"' && q !== "'") return undefined
    const drei = text.startsWith(q.repeat(3), i)
    const zu = drei ? q.repeat(3) : q
    i += zu.length
    if (drei && text[i] === '\r') i++
    if (drei && text[i] === '\n') i++
    let s = ''
    while (i < n && !text.startsWith(zu, i)) {
      if (!drei && text[i] === '\n') return undefined
      if (q === '"' && text[i] === '\\') {
        const e = text[i + 1] ?? ''
        const ersatz: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', b: '\b', f: '\f' }
        if (e === 'u' || e === 'U') {
          const len = e === 'u' ? 4 : 8
          s += zeichen(parseInt(text.slice(i + 2, i + 2 + len), 16))
          i += 2 + len
        } else if (e === '\n' || e === '\r' || e === ' ' || e === '\t') {
          i++
          while (i < n && /\s/.test(text[i] ?? '')) i++
        } else {
          s += ersatz[e] ?? e
          i += 2
        }
      } else s += text[i++]
    }
    if (i >= n) return undefined
    i += zu.length
    return s
  }
  const schluessel = (): string[] | undefined => {
    const teile: string[] = []
    for (;;) {
      leer(false)
      const q = textLesen()
      if (q !== undefined) teile.push(q)
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 200))
        if (!m) return undefined
        teile.push(m[0])
        i += m[0].length
      }
      leer(false)
      if (text[i] !== '.') return teile
      i++
    }
  }
  const wert = (tiefe: number): TWert | undefined => {
    if (tiefe > 20) return undefined
    leer(false)
    const at = i
    const c = text[i]
    if (c === '"' || c === "'") {
      const s = textLesen()
      return s === undefined ? undefined : { art: 'text', wert: s, at }
    }
    if (c === '[') {
      i++
      const werte: TWert[] = []
      for (;;) {
        leer(true)
        if (i >= n) return undefined
        if (text[i] === ']') {
          i++
          return { art: 'liste', werte }
        }
        const w = wert(tiefe + 1)
        if (!w) return undefined
        werte.push(w)
        leer(true)
        if (text[i] === ',') i++
        else if (text[i] !== ']') return undefined
      }
    }
    if (c === '{') {
      i++
      const felder: [string[], TWert][] = []
      for (;;) {
        leer(true)
        if (i >= n) return undefined
        if (text[i] === '}') {
          i++
          return { art: 'tabelle', felder }
        }
        const k = schluessel()
        if (!k || text[i] !== '=') return undefined
        i++
        const w = wert(tiefe + 1)
        if (!w) return undefined
        felder.push([k, w])
        leer(true)
        if (text[i] === ',') i++
        else if (text[i] !== '}') return undefined
      }
    }
    // Zahl, Wahrheitswert, Datum: bis zum Ende des Werts
    const m = /^[^,\]}\r\n#]+/.exec(text.slice(i, i + 200))
    if (!m || m[0].trim() === '') return undefined
    i += m[0].length
    return { art: 'sonst' }
  }
  let tabelle: string[] = []
  while (i < n) {
    leer(true)
    if (i >= n) break
    if (text[i] === '[') {
      const doppelt = text[i + 1] === '['
      i += doppelt ? 2 : 1
      const k = schluessel()
      if (!k) break
      leer(false)
      if (!text.startsWith(doppelt ? ']]' : ']', i)) break
      i += doppelt ? 2 : 1
      tabelle = k
      out.push({ pfad: k, wert: { art: 'tabelle', felder: [] } })
      continue
    }
    const k = schluessel()
    if (!k || text[i] !== '=') break
    i++
    const w = wert(0)
    if (!w) break
    out.push({ pfad: [...tabelle, ...k], wert: w })
  }
  return out
}

function pyprojectPakete(text: string, file: string): Paket[] {
  const eintraege = tomlLesen(text.replace(/^\ufeff/, ' '))
  // Tabellen in { } flach machen: project.optional-dependencies = { dev = [...] } wie [project.optional-dependencies] dev = [...]
  const flach: { pfad: string[]; wert: TWert }[] = []
  const besuche = (pfad: string[], w: TWert) => {
    flach.push({ pfad, wert: w })
    if (w.art === 'tabelle' && !(pfad[0] === 'tool' && pfad[1] === 'poetry' && pfad[2] === 'dependencies' && pfad.length === 4)) for (const [k, v] of w.felder) besuche([...pfad, ...k], v)
  }
  for (const e of eintraege) besuche(e.pfad, e.wert)
  const eigene = flach.some(e => e.pfad[0] === 'tool' && ['source', 'sources', 'index'].includes(e.pfad[2] ?? ''))
  const out: Paket[] = []
  const neu = (spez: string, at: number, extra: Partial<Paket> = {}) => {
    const p = pep508(spez)
    if (p) out.push({ oekosystem: 'pypi', name: p.name, version: p.version, zeile: zeileVon(text, at), datei: file, ...(eigene ? { eigeneQuelle: true } : {}), ...extra })
  }
  const liste = (w: TWert) => {
    if (w.art === 'liste') for (const x of w.werte) if (x.art === 'text') neu(x.wert, x.at)
  }
  // Poetry: name = "^1.2", name = { version = "^1.2", ... }, eine Liste solcher Tabellen oder eine eigene Tabelle
  // [tool.poetry.dependencies.name] mit version = ...; path/git/url/file sind keine Pakete der Paketquelle.
  const poetry = new Map<string, { at: number; wert?: TWert; felder: [string, TWert][] }>()
  for (const e of flach) {
    const p = e.pfad
    if (p.length === 2 && p[0] === 'project' && p[1] === 'dependencies') liste(e.wert)
    else if (p.length === 3 && p[0] === 'project' && p[1] === 'optional-dependencies') liste(e.wert)
    else if ((p.length === 4 || p.length === 5) && p[0] === 'tool' && p[1] === 'poetry' && p[2] === 'dependencies' && p[3]?.toLowerCase() !== 'python') {
      const name = p[3] ?? ''
      const eintrag = poetry.get(name) ?? { at: Math.max(0, text.indexOf(name)), felder: [] }
      if (p.length === 4) eintrag.wert = e.wert
      else eintrag.felder.push([p[4] ?? '', e.wert])
      poetry.set(name, eintrag)
    }
  }
  for (const [name, e] of poetry) {
    const w = e.wert?.art === 'liste' ? e.wert.werte[0] : e.wert
    if (w?.art === 'text') {
      neu(name, w.at, { version: w.wert })
      continue
    }
    const felder = [...(w?.art === 'tabelle' ? w.felder.filter(([k]) => k.length === 1).map(([k, v]): [string, TWert] => [k[0] ?? '', v]) : []), ...e.felder]
    const feld = (k: string) => felder.find(([kk]) => kk === k)?.[1]
    if (feld('path') || feld('git') || feld('url') || feld('file')) continue
    const v = feld('version')
    neu(name, v?.art === 'text' ? v.at : e.at, { version: v?.art === 'text' ? v.wert : '', ...(feld('source') ? { eigeneQuelle: true } : {}) })
  }
  return out
}

// ---- package.json (docs.npmjs.com/cli/configuring-npm/package-json). Unity-Pakete haben dieselbe Form, ihre Abhängigkeiten kommen
// aber aus Unitys eigener Quelle (Name in umgekehrter Domain-Schreibweise, docs.unity.com ... upm-manifest-pkg): dann kein npm.
const NPM_FELDER = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
// Angaben, die nicht aus der Paketquelle kommen: Datei, Ordner, Arbeitsbereich, Git, GitHub-Kurzform, Adresse.
const NPM_NICHT_QUELLE = /^(?:file:|link:|workspace:|portal:|patch:|exec:|git:|git\+|github:|gitlab:|bitbucket:|gist:|https?:|\.{0,2}[\\/]|~[\\/]|[A-Za-z]:[\\/])|^[^@\s/]+\/[^\s]+$/i

function packageJsonPakete(text: string, file: string): Paket[] {
  let j: unknown
  try {
    j = JSON.parse(text.replace(/^\ufeff/, ''))
  } catch {
    // Kaputtes JSON meldet die JSON-Prüfung des Wächters als Fehler; Pakete daraus sind nicht lesbar.
    return []
  }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return []
  const o = j as Record<string, unknown>
  if (typeof o.unity === 'string' || (typeof o.name === 'string' && /^[a-z0-9-]+(?:\.[a-z0-9_-]+){2,}$/.test(o.name))) return []
  const out: Paket[] = []
  for (const feld of NPM_FELDER) {
    const d = o[feld]
    if (!d || typeof d !== 'object' || Array.isArray(d)) continue
    const feldAt = text.search(new RegExp(`"${feld}"\\s*:`))
    for (const [schl, spez0] of Object.entries(d as Record<string, unknown>)) {
      const spez = typeof spez0 === 'string' ? spez0.trim() : ''
      if (NPM_NICHT_QUELLE.test(spez)) continue
      // Decknamen: "foo": "npm:bar@^1.0" holt das Paket bar.
      let name = schl
      let version = spez
      const alias = /^npm:((?:@[^@/]+\/)?[^@]+)(?:@(.*))?$/.exec(spez)
      if (alias) {
        name = alias[1] ?? schl
        version = alias[2] ?? ''
      }
      const keyAt = text.indexOf(JSON.stringify(schl), Math.max(0, feldAt))
      out.push({ oekosystem: 'npm', name, version, zeile: zeileVon(text, keyAt >= 0 ? keyAt : Math.max(0, feldAt)), datei: file })
    }
  }
  return out
}

// ---- Alle Pakete einer Paketliste
export function allePakete(text: string, file: string): Paket[] {
  if (PROJEKT.test(file) || ZENTRAL_DATEI.test(file) || PACKAGES_CONFIG.test(file)) return xmlPakete(text, file)
  if (REQUIREMENTS.test(file)) return requirementsPakete(text, file)
  if (PYPROJECT.test(file)) return pyprojectPakete(text, file)
  if (PACKAGE_JSON.test(file)) return packageJsonPakete(text, file)
  return []
}

// Pakete, die im neuen Inhalt stehen und im alten nicht (gleicher Name mit anderer Fassung zählt als neu); alt undefined: alle.
// Jedes Paket nur einmal (die erste Zeile).
export function neuePakete(alt: string | undefined, neu: string, file: string): Paket[] {
  const schl = (p: Paket) => `${p.oekosystem}|${nameSchluessel(p.oekosystem, p.name)}|${p.version}`
  const vorher = new Set(alt === undefined ? [] : allePakete(alt, file).map(schl))
  const gesehen = new Set<string>()
  const out: Paket[] = []
  for (const p of allePakete(neu, file)) {
    const k = schl(p)
    if (vorher.has(k) || gesehen.has(k)) continue
    gesehen.add(k)
    out.push(p)
  }
  return out
}

// ---- Fassung bei NuGet (learn.microsoft.com/nuget/concepts/package-versioning): * nimmt die höchste passende Fassung ("Will resolve
// to the highest acceptable stable version"); ohne Fassung nimmt NuGet die niedrigste vorhandene und fragt jedes Mal neu (NU1604);
// ein Bereich mit Klammern ohne Obergrenze ([1.0,) oder (1.0,)) lässt jede höhere zu. Die einfache Schreibweise "1.0" ist die übliche
// Mindestfassung und zählt nicht. In Projekten mit Directory.Packages.props fehlt die Fassung in der .csproj absichtlich
// (learn.microsoft.com/nuget/consume-packages/central-package-management: die nächste Datei im Projektordner oder darüber).
function fassungsHinweis(p: Paket, zentral: boolean): string | undefined {
  const v = p.version.trim()
  if (v.includes('*')) {
    return t(`Fassung ${daten(v, 40)} mit * - NuGet nimmt bei jeder Wiederherstellung die höchste passende Fassung, auch eine eben erst veröffentlichte (verseuchte). Feste Fassung angeben.`,
      `version ${daten(v, 40)} with * - NuGet takes the highest matching version on every restore, even one just published (malicious). Give a fixed version.`)
  }
  if (v === '' && !(PROJEKT.test(p.datei) && zentral)) {
    return t('keine Fassung angegeben - NuGet nimmt die niedrigste vorhandene und fragt bei jeder Wiederherstellung neu (NU1604). Feste Fassung angeben.',
      'no version given - NuGet takes the lowest available one and asks again on every restore (NU1604). Give a fixed version.')
  }
  if (/^[[(][^,\])]*,\s*\)$/.test(v)) {
    return t(`Fassungsbereich ${daten(v, 40)} ohne Obergrenze - lässt jede höhere Fassung zu; fehlt die kleinste in der Quelle, nimmt NuGet eine höhere (NU1603). Genau eine Fassung: [1.2.3].`,
      `version range ${daten(v, 40)} without upper bound - allows any higher version; if the lowest is missing in the source, NuGet takes a higher one (NU1603). Exactly one version: [1.2.3].`)
  }
  return undefined
}

const ordnerVon = (p: string): string => {
  const x = p.replace(/\//g, '\\')
  const k = x.lastIndexOf('\\')
  return k > 0 ? x.slice(0, k) : ''
}

// ---- Prüfen: Fassung (ohne Netz), Name nach den Regeln der Quelle, dann ob es das Paket gibt (eigener NuGet-Ordner, sonst die Quelle).
export async function paketePruefen(u: PaketUmgebung, pakete: Paket[]): Promise<{ funde: SFund[]; luecken: string[] }> {
  const funde: SFund[] = []
  const luecken: string[] = []
  const scanner = t('Pakete', 'packages')
  const fund = (p: Paket, code: string, schwer: boolean, text: string) => funde.push({ line: p.zeile, col: 0, code, text, schwer, scanner })

  // Zentrale Fassungen: Directory.Packages.props im Ordner der Datei oder darüber (je Ordner einmal nachgesehen).
  const zentralBei = new Map<string, boolean>()
  const zentralFuer = async (datei: string): Promise<boolean> => {
    const start = ordnerVon(datei)
    if (zentralBei.has(start)) return zentralBei.get(start) ?? false
    let dir = start
    let ja = false
    for (let k = 0; k < 64 && dir !== ''; k++) {
      try {
        if (await u.exists(`${dir}\\Directory.Packages.props`)) {
          ja = true
          break
        }
      } catch {
        // nicht lesbar: weiter oben suchen
      }
      const oben = ordnerVon(dir)
      if (oben === dir || !/\\/.test(dir)) break
      dir = oben
    }
    zentralBei.set(start, ja)
    return ja
  }

  const zuPruefen: Paket[] = []
  for (const p of pakete) {
    if (p.oekosystem === 'nuget') {
      const zentral = p.zentral ?? (p.version.trim() === '' && PROJEKT.test(p.datei) ? await zentralFuer(p.datei) : false)
      const h = fassungsHinweis(p, zentral)
      if (h) fund(p, 'PAKET-VERSION', false, h)
    }
    if (/[$@%]\(/.test(p.name)) {
      luecken.push(t(`Paketname aus einer MSBuild-Angabe ${daten(p.name, 80)} (Zeile ${p.zeile}) nicht geprüft`, `package name from an MSBuild expression ${daten(p.name, 80)} (line ${p.zeile}) not checked`))
      continue
    }
    if (!nameGueltig(p.oekosystem, p.name)) {
      fund(p, 'PAKET-NAME', false, t(`${daten(p.name, 80)} ist kein zulässiger Paketname für ${QUELLE[p.oekosystem]} - nicht abgefragt. Namen prüfen.`,
        `${daten(p.name, 80)} is not a valid package name for ${QUELLE[p.oekosystem]} - not looked up. Check the name.`))
      continue
    }
    zuPruefen.push(p)
  }

  // Ergebnis je Name (gleiches Paket in mehreren Zeilen: eine Abfrage).
  type Antwort = 'da' | 'fehlt' | 'offen'
  const antwort = new Map<string, Antwort>()
  const nichtErreichbar = new Map<Oekosystem, { grund: string; anzahl: number }>()
  let abfragen = 0
  let zuViele = 0
  for (const p of zuPruefen) {
    const k = `${p.oekosystem}|${nameSchluessel(p.oekosystem, p.name)}`
    let a = antwort.get(k)
    if (a === undefined && p.oekosystem === 'nuget') {
      try {
        if (u.nugetOrdner !== '' && (await u.exists(`${u.nugetOrdner}\\${p.name.toLowerCase()}`))) a = 'da'
      } catch {
        // Ordner nicht lesbar: dann fragt der Wächter die Quelle
      }
    }
    if (a === undefined) {
      const kaputt = nichtErreichbar.get(p.oekosystem)
      if (kaputt) {
        kaputt.anzahl++
        a = 'offen'
      } else if (abfragen >= MAX_ABFRAGEN) {
        zuViele++
        a = 'offen'
      } else {
        abfragen++
        const argv = [CURL, '-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', CURL_ZEIT_S,
          ...(p.oekosystem === 'npm' ? ['-H', 'Accept: application/vnd.npm.install-v1+json'] : []), adresse(p.oekosystem, p.name)]
        let grund = ''
        try {
          const r = await u.run(argv, { timeoutMs: LAUF_MS })
          const code = r.ok ? r.stdout.trim() : ''
          if (r.ok && r.exitCode === 0 && code === '200') a = 'da'
          else if (r.ok && r.exitCode === 0 && code === '404') a = 'fehlt'
          else grund = r.ok ? t(`curl-Code ${r.exitCode}, HTTP ${daten(code || '-', 20)}`, `curl code ${r.exitCode}, HTTP ${daten(code || '-', 20)}`) : daten(r.reason, 120)
        } catch (err) {
          grund = daten(String((err as { message?: string })?.message ?? err), 120)
        }
        if (a === undefined) {
          nichtErreichbar.set(p.oekosystem, { grund, anzahl: 1 })
          a = 'offen'
        }
      }
    }
    antwort.set(k, a)
    if (a === 'fehlt') {
      fund(p, 'PAKET-UNBEKANNT', !p.eigeneQuelle, p.eigeneQuelle
        ? t(`Paket ${daten(p.name, 80)} gibt es auf ${QUELLE[p.oekosystem]} nicht - die Datei nennt eine eigene Paketquelle; gibt es das Paket dort, ist es gewollt. Sonst ein erfundener Name: Angreifer registrieren solche Namen. Namen prüfen.`,
          `package ${daten(p.name, 80)} does not exist on ${QUELLE[p.oekosystem]} - the file names its own package source; if the package is there, it is intended. Otherwise an invented name: attackers register such names. Check the name.`)
        : t(`Paket ${daten(p.name, 80)} gibt es in der Paketquelle ${QUELLE[p.oekosystem]} nicht - erfundener Name? Angreifer registrieren solche Namen. Namen prüfen.`,
          `package ${daten(p.name, 80)} does not exist in the package source ${QUELLE[p.oekosystem]} - invented name? Attackers register such names. Check the name.`))
    }
  }
  for (const [o, x] of nichtErreichbar) {
    luecken.push(t(`Paketquelle ${QUELLE[o]} nicht erreichbar (${x.grund}) - ${x.anzahl} Paket(e) nicht geprüft`, `package source ${QUELLE[o]} not reachable (${x.grund}) - ${x.anzahl} package(s) not checked`))
  }
  if (zuViele > 0) {
    luecken.push(t(`zu viele neue Pakete, nur die ersten ${MAX_ABFRAGEN} geprüft (${zuViele} weitere nicht)`, `too many new packages, only the first ${MAX_ABFRAGEN} checked (${zuViele} more not)`))
  }
  funde.sort((a, b) => a.line - b.line)
  return { funde, luecken }
}
