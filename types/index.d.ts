// Ein Eintrag je Datei (der letzte Stand). at: Zeitpunkt in Millisekunden; älter als 48 Stunden fällt aus dem Log.
// group: Überschrift in der Seitenleiste (Python, PHP, Unity ...). fixed: der Fehler dieser Datei ist behoben.
export type WaechterEntry = {
  id: string
  file: string
  path: string
  group: string
  kind: string
  status: 'ok' | 'fehler' | 'ungeprueft'
  detail: string
  ms: number
  at: number
  fixed?: boolean
  hints?: number // Zahl der Verbesserungsvorschläge bei ✔
}

export type WaechterRunning = { id: string; file: string; kind: string }

declare module 'claude-code' {
  interface PluginState {
    'code-waechter': {
      log: WaechterEntry[]
      running: WaechterRunning[]
      frame: number
    }
  }
}
