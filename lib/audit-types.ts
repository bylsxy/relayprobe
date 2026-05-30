export const DEFAULT_TARGET_MODEL = "gpt-5.5"
export const DEFAULT_AUDITOR_MODEL = "gpt-5.5"

export const TEST_PROFILE_KEYS = [
  "schemaLock",
  "canaryLeak",
  "injectionLure",
  "crossRequest",
] as const

export type TestProfileKey = (typeof TEST_PROFILE_KEYS)[number]

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type AuditStatus = "idle" | "running" | "completed" | "failed"

export type AuditorMode = "ai" | "heuristic"

export type CaseStatus = "passed" | "warning" | "failed" | "error"

export type TestProfiles = Record<TestProfileKey, boolean>

export interface AuditRequestPayload {
  endpoint: string
  relayApiKey: string
  targetModel: string
  auditorModel: string
  includeBaseline: boolean
  captureFullResponses: boolean
  profiles: TestProfiles
  customInstruction?: string
}

export interface AuditFinding {
  id: string
  severity: Severity
  confidence: number
  category:
    | "canary"
    | "schema"
    | "cross-request"
    | "protocol"
    | "baseline"
    | "auditor"
  title: string
  evidence: string
  recommendation: string
  caseIds: string[]
}

export interface AuditCaseResult {
  id: string
  name: string
  status: CaseStatus
  durationMs: number
  requestPreview: string
  responsePreview: string
  baselinePreview?: string
  canaries: string[]
  observations: string[]
  httpStatus?: number
  error?: string
}

export interface AuditReport {
  runId: string
  status: AuditStatus
  startedAt: string
  completedAt: string
  endpointHost: string
  targetModel: string
  auditorModel: string
  auditorMode: AuditorMode
  riskScore: number
  topSeverity: Severity
  summary: string
  findings: AuditFinding[]
  cases: AuditCaseResult[]
  jsonPreview: string
}

export const defaultProfiles: TestProfiles = {
  schemaLock: true,
  canaryLeak: true,
  injectionLure: true,
  crossRequest: true,
}

export function severityRank(severity: Severity) {
  return {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  }[severity]
}

export function severityLabel(score: number): Severity {
  if (score >= 85) return "critical"
  if (score >= 65) return "high"
  if (score >= 35) return "medium"
  if (score >= 15) return "low"
  return "info"
}

