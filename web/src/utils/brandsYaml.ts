// Reads brand names and their official domains from backend/app/data/brands.yaml (the backend's
// own brand list) at build time. Only the two fields the website needs are parsed, so no YAML
// library is added: "- name: …" starts a brand, "official_domains: [a, b]" lists its domains.

export type OfficialDomains = Record<string, string[]>

const NAME = /^\s*-\s*name:\s*(.+?)\s*$/
const DOMAINS = /^\s*official_domains:\s*\[(.*)\]\s*$/

const unquote = (value: string) => value.trim().replace(/^(["'])(.*)\1$/, '$2')

export function parseOfficialDomains(yaml: string): OfficialDomains {
  const result: OfficialDomains = {}
  let current: string | null = null
  for (const line of yaml.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue
    const name = NAME.exec(line)
    if (name?.[1]) {
      current = unquote(name[1])
      continue
    }
    const domains = DOMAINS.exec(line)
    if (domains && current) {
      const list = (domains[1] ?? '')
        .split(',')
        .map(unquote)
        .filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))
      if (list.length) result[current] = list
      current = null
    }
  }
  return result
}
