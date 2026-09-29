// Mirrors docs/api-spec.md. The web app contains no security logic: every verdict comes from
// the backend, and these types only describe what it returns.

export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH'
export type InputType = 'url' | 'message' | 'screenshot' | 'qr'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type EvidenceSource = 'message' | 'link' | 'qr' | 'threat_intelligence' | 'combination' | 'ocr'
export type TIStatus = 'listed' | 'partial' | 'not_listed' | 'unavailable' | 'disabled' | 'error'

export interface Verification {
  status: 'VERIFIED' | 'UNVERIFIED'
  source: 'trusted_domain_list' | 'threat_intelligence' | null
  message: string
}

export interface Indicator {
  id: string
  severity: Severity
  title: string
  message: string
  evidence?: string | null
  weight: number
  score_contribution: number
  module: string
  source?: EvidenceSource
}

export interface Category {
  id: string
  label: string
}

export interface ProviderResult {
  provider: string
  status: TIStatus
  threat_type?: string
  detail?: string
  limited_coverage?: boolean
  cached?: boolean
}

export interface ThreatIntelBlock {
  checked: boolean
  providers: ProviderResult[]
  note: string
}

export interface ScoreBreakdown {
  final_score: number
  weighted_score?: number
  rule_used?: string
  floor_applied?: { indicator: string; minimum_score: number; points_added: number } | null
  sources?: { source: EvidenceSource; points: number; indicator_ids: string[] }[]
  modules?: {
    module: string
    applicable: boolean
    module_score: number | null
    weight: number
    effective_weight: number
  }[]
}

export interface LinkRow {
  url: string
  risk_score?: number
  risk_level?: RiskLevel
  scored?: boolean
  found_in?: string
  error?: string
}

export interface OcrBlock {
  engine: string
  extracted_text: string
  confidence: number | null
  quality: 'good' | 'fair' | 'poor' | 'none'
  word_count: number
  truncated: boolean
}

export interface QrBlock {
  source: string
  codes_found: number
  decoded_content: string
  content_type: string
  parsed: Record<string, unknown>
}

export interface QrCodeRow {
  index: number
  content_type: string
  decoded_content: string
  risk_score?: number
  risk_level?: RiskLevel
  scored?: boolean
  used_as?: string
}

export interface AnalysisDetails {
  input_url?: string
  normalized_url?: string
  host?: string | null
  redirects?: { checked: boolean; status?: string; final_url?: string | null; chain?: string[] }
  links?: LinkRow[]
  matched_phrases?: string[]
  low_confidence_reasons?: string[]
  ocr?: OcrBlock
  image?: { format: string; width: number; height: number; size_bytes: number }
  qr?: QrBlock
  qr_codes?: QrCodeRow[]
  [key: string]: unknown
}

export interface AnalysisResult {
  request_id: string
  input_type: InputType
  risk_score: number
  risk_level: RiskLevel
  confidence: Confidence
  verification: Verification
  summary: string
  categories: Category[]
  indicators: Indicator[]
  recommendation: string
  score_breakdown: ScoreBreakdown
  threat_intel: ThreatIntelBlock
  analysis: AnalysisDetails
  disclaimer: string
  engine_version?: string
}

export interface ApiErrorBody {
  error: { code: string; message: string; request_id?: string; details?: unknown }
}

export interface HealthResponse {
  status: string
  engine_version: string
  components: {
    api: string
    ocr_engine?: string
    threat_intel?: {
      enabled: boolean
      providers: { provider: string; enabled: boolean; external: boolean }[]
    }
    [key: string]: unknown
  }
}
