import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parseOfficialDomains } from './brandsYaml'

describe('parseOfficialDomains', () => {
  it('reads names and official domains, skipping comments and other fields', () => {
    const yaml = [
      '# official_domains: a comment, not a brand',
      'brands:',
      '  - name: Example Bank',
      '    keywords: [example, exbank]',
      '    official_domains: [example.com, "example.bank.in"]',
      "  - name: 'No Domains'",
      '    official_domains: []',
    ].join('\n')
    expect(parseOfficialDomains(yaml)).toEqual({ 'Example Bank': ['example.com', 'example.bank.in'] })
  })

  it("parses the backend's real brand list", () => {
    const yaml = readFileSync(resolve(__dirname, '../../../backend/app/data/brands.yaml'), 'utf8')
    const domains = parseOfficialDomains(yaml)
    expect(domains['State Bank of India']).toContain('sbi.co.in')
    expect(domains['HDFC Bank']).toContain('hdfcbank.com')
    expect(Object.keys(domains).length).toBeGreaterThan(10)
  })
})
