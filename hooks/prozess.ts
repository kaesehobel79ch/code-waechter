// Programme nur mit vollem Pfad starten.
// Ohne Pfad sucht Windows ein Programm zuerst im aktuellen Ordner (Microsoft-Doku zu CreateProcess: "The current directory for
// the parent process", vor dem Suchpfad). Eine untergeschobene py.exe oder node.exe in einem fremden Projekt würde sonst gestartet.
// Darum sucht die Mod selbst: cmd und PowerShell im Windows-Ordner, alles andere nur in den Ordnern des Suchpfads, die einen
// vollen Pfad haben (nie ".", nie relative Einträge).
//
// Start programs by full path only: Windows searches the current directory before PATH, so a planted py.exe in a cloned
// project would run. cmd and PowerShell come from the Windows folder, everything else from absolute PATH entries only.

const exeCache = new Map<string, string>()

const norm = (p: string): string => p.replace(/\//g, '\\')

export const isAbsolute = (p: string): boolean => /^[A-Za-z]:\\/.test(norm(p)) || norm(p).startsWith('\\\\')

// Die Mod-Schnittstelle verlangt bei $.env.get einen festen Namen (damit sichtbar ist, welche Variablen eine Mod liest).
const text = (v: unknown): string | undefined => (v === undefined || v === null ? undefined : String(v))

export async function envPath($: any): Promise<string | undefined> {
  try {
    return text(await $.env.get('PATH'))
  } catch {
    return undefined
  }
}

async function envSystemRoot($: any): Promise<string | undefined> {
  try {
    return text(await $.env.get('SystemRoot'))
  } catch {
    return undefined
  }
}

export async function resolveExe($: any, name: string): Promise<string | undefined> {
  if (isAbsolute(name)) return name
  if (name.length === 0 || /[\\/]/.test(name)) return undefined // relative Pfade werden nie gestartet
  const key = name.toLowerCase()
  const hit = exeCache.get(key)
  if (hit !== undefined) return hit
  const root = ((await envSystemRoot($)) ?? 'C:\\Windows').replace(/\\+$/, '')
  const system: Record<string, string> = {
    cmd: `${root}\\System32\\cmd.exe`,
    powershell: `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`,
  }
  const path = await envPath($)
  // Ohne lesbaren Suchpfad (nur in der Testumgebung der Mod) bleibt der Name; der Host der App liefert ihn immer.
  if (path === undefined) return system[key] ?? name
  const candidates = system[key] ? [system[key]] : []
  const exts = /\.[a-z0-9]{2,4}$/i.test(name) ? [''] : ['.exe', '.com']
  for (const dir of (path ?? '').split(';').map(d => d.trim().replace(/^"|"$/g, '').replace(/\\+$/, ''))) {
    if (!isAbsolute(dir)) continue
    for (const ext of exts) candidates.push(`${dir}\\${name}${ext}`)
  }
  for (const c of candidates) {
    try {
      if (await $.fs.exists(c)) {
        exeCache.set(key, c)
        return c
      }
    } catch {
      // nicht lesbar: nächster Ort
    }
  }
  // Windows-App-Verknüpfungen (z. B. py.exe in ...\Microsoft\WindowsApps) gelten für "exists" nicht als vorhanden, weil ihr Ziel
  // nicht lesbar ist (gemessen 22.10.2026); die Ordnerliste zeigt sie aber, und Windows startet sie. Darum zweiter Weg über die Liste.
  const wanted = new Set(exts.map(ext => `${name}${ext}`.toLowerCase()))
  for (const dir of new Set(candidates.map(c => c.slice(0, c.lastIndexOf('\\'))))) {
    try {
      const hit = ((await $.fs.list(dir)) as { name: string; kind: string }[]).find(x => wanted.has(x.name.toLowerCase()) && x.kind !== 'dir')
      if (hit) {
        const found = `${dir}\\${hit.name}`
        exeCache.set(key, found)
        return found
      }
    } catch {
      // Ordner nicht lesbar: nächster
    }
  }
  return undefined
}

export function clearExeCache(): void {
  exeCache.clear()
}
