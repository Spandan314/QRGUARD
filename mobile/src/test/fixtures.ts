import type { AnalysisResult } from '../types/api'

// Shapes copied from real backend responses (docs/api-spec.md). DEMO / TEST DATA.
export const maliciousUrl: AnalysisResult = {
  request_id: 'req123',
  input_type: 'url',
  risk_score: 73,
  risk_level: 'MALICIOUS',
  confidence: 'HIGH',
  verification: {
    status: 'UNVERIFIED',
    source: null,
    message: 'There is insufficient evidence to establish trust.',
  },
  summary: 'Strong warning signs: this link is very likely malicious.',
  categories: [
    { id: 'phishing', label: 'Phishing' },
    { id: 'impersonation', label: 'Impersonation scam' },
  ],
  indicators: [
    {
      id: 'URL_NO_HTTPS',
      severity: 'low',
      title: 'No secure connection',
      message: 'The link uses http.',
      evidence: 'http://',
      weight: 8,
      score_contribution: 8,
      module: 'url_qr',
      source: 'link',
    },
    {
      id: 'OFFICIAL_DOMAIN_IN_SUBDOMAIN',
      severity: 'critical',
      title: 'Real brand address used as a disguise',
      message: 'A genuine brand address appears at the start of this link.',
      evidence: '<img src=x onerror=alert(1)>',
      weight: 40,
      score_contribution: 40,
      module: 'url_qr',
      source: 'link',
    },
  ],
  recommendation: 'Do not open this link. In India, report financial fraud at 1930.',
  score_breakdown: { final_score: 73, floor_applied: null },
  threat_intel: {
    checked: true,
    providers: [
      { provider: 'local_feed', status: 'not_listed', limited_coverage: true },
      { provider: 'urlhaus', status: 'disabled' },
      { provider: 'virustotal', status: 'unavailable', detail: 'timeout' },
    ],
    note: "Only QRGUARD's small demo blocklist could be checked.",
  },
  analysis: {
    normalized_url: 'http://sbi.co.in.kyc-verify.xyz/login',
    redirects: { checked: false },
  },
  disclaimer: 'This is an automated security assessment, not a guarantee.',
  engine_version: '0.1.0',
}

export const safeUnverified: AnalysisResult = {
  ...maliciousUrl,
  request_id: 'req-safe',
  risk_score: 0,
  risk_level: 'SAFE',
  confidence: 'LOW',
  summary: 'No significant warning signs were found.',
  categories: [],
  indicators: [],
}

export const tiListed: AnalysisResult = {
  ...maliciousUrl,
  request_id: 'req-ti',
  risk_score: 90,
  verification: {
    status: 'VERIFIED',
    source: 'threat_intelligence',
    message: 'A threat-intelligence source lists this as known malicious.',
  },
  indicators: [
    {
      id: 'TI_LISTED',
      severity: 'critical',
      title: 'Listed as malicious by a threat-intelligence source',
      message: 'Listed.',
      evidence: 'Listed by: local_feed',
      weight: 100,
      score_contribution: 90,
      module: 'threat_intel',
      source: 'threat_intelligence',
    },
  ],
  threat_intel: {
    checked: true,
    providers: [{ provider: 'local_feed', status: 'listed', threat_type: 'blocklist', limited_coverage: true }],
    note: 'Not being listed in a threat database does not mean a link is safe.',
  },
}

export const screenshotResult: AnalysisResult = {
  ...maliciousUrl,
  request_id: 'req-shot',
  input_type: 'screenshot',
  risk_score: 65,
  indicators: [
    {
      id: 'MSG_ACCOUNT_THREAT',
      severity: 'high',
      title: 'Threat to block your account',
      message: 'The message threatens to block your account.',
      evidence: 'will be BLOCKED',
      weight: 15,
      score_contribution: 15,
      module: 'message',
      source: 'message',
    },
  ],
  analysis: {
    links: [{ url: 'http://sbi-kyc-update.xyz/login', risk_level: 'SUSPICIOUS', scored: true }],
    ocr: {
      engine: 'tesseract',
      extracted_text: 'Dear customer, your SBI account will be BLOCKED today.',
      confidence: 93.8,
      quality: 'good',
      word_count: 9,
      truncated: false,
    },
    image: { format: 'PNG', width: 1100, height: 210, size_bytes: 22347 },
  },
}

export const qrResult: AnalysisResult = {
  ...maliciousUrl,
  request_id: 'req-qr',
  input_type: 'qr',
  risk_score: 40,
  risk_level: 'SUSPICIOUS',
  indicators: [
    {
      id: 'QR_UPI_NAME_MISMATCH',
      severity: 'medium',
      title: 'Payee name does not match the UPI ID',
      message: 'The name claims a bank.',
      evidence: "name mentions 'sbi'",
      weight: 15,
      score_contribution: 15,
      module: 'url_qr',
      source: 'qr',
    },
  ],
  analysis: {
    qr: {
      source: 'image',
      codes_found: 2,
      decoded_content: 'upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999',
      content_type: 'upi',
      parsed: { payee_vpa: 'refund.desk9912@okdemo', amount: '4999', valid_vpa: true, note: null },
    },
    qr_codes: [
      { index: 1, content_type: 'url', decoded_content: 'https://www.wikipedia.org/', risk_level: 'SAFE', scored: false },
      { index: 2, content_type: 'upi', decoded_content: 'upi://pay?pa=refund.desk9912@okdemo', risk_level: 'SUSPICIOUS', scored: true },
    ],
  },
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
