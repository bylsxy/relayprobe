import {
  DEFAULT_AUDITOR_MODEL,
  DEFAULT_TARGET_MODEL,
  type AuditReport,
} from "@/lib/audit-types"

export const sampleReport: AuditReport = {
  runId: "demo-run",
  status: "idle",
  startedAt: new Date("2026-05-31T00:00:00.000Z").toISOString(),
  completedAt: new Date("2026-05-31T00:00:00.000Z").toISOString(),
  endpointHost: "relay.example.com",
  targetModel: DEFAULT_TARGET_MODEL,
  auditorModel: DEFAULT_AUDITOR_MODEL,
  auditorMode: "heuristic",
  riskScore: 0,
  topSeverity: "info",
  summary:
    "No live run yet. Configure a relay endpoint and run a safe canary audit.",
  findings: [
    {
      id: "demo-scope",
      severity: "info",
      confidence: 100,
      category: "auditor",
      title: "Evidence-based audit scope",
      evidence:
        "RelayProbe reports observable anomalies only. It does not prove that a relay is safe or malicious.",
      recommendation:
        "Use fake secrets and canaries. Do not test with real credentials or private prompts.",
      caseIds: [],
    },
  ],
  cases: [
    {
      id: "schema-lock",
      name: "Schema lock",
      status: "passed",
      durationMs: 0,
      requestPreview: '{"ok":true,"case":"schema_lock"}',
      responsePreview: '{"ok":true,"case":"schema_lock"}',
      canaries: ["rp-canary-demo"],
      observations: ["Strict JSON checks are ready."],
    },
    {
      id: "canary-seal",
      name: "Canary seal",
      status: "passed",
      durationMs: 0,
      requestPreview: "Fake credential canary is injected into a harmless task.",
      responsePreview: "No live response captured yet.",
      canaries: ["sk-canary-demo"],
      observations: ["Canary leakage checks are ready."],
    },
  ],
  jsonPreview: "{}",
}

