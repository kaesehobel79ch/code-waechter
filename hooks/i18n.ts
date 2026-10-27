// Sprache der Meldungen: Deutsch oder Englisch. "auto" richtet sich nach der Anzeigesprache von Windows (beim Sitzungsstart
// gelesen); bis dahin und wenn sie sich nicht lesen lässt, gilt Deutsch.
//
// Message language: German or English. "auto" follows the Windows display language (read when the session starts);
// until then, and when it cannot be read, German is used.

export type Lang = 'de' | 'en'

let lang: Lang = 'de'

export function setLang(value: Lang): void {
  lang = value
}

export function getLang(): Lang {
  return lang
}

// t('Deutscher Text', 'English text'): der Text in der eingestellten Sprache.
export function t(de: string, en: string): string {
  return lang === 'en' ? en : de
}
