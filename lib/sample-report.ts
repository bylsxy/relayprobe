import {
  DEFAULT_AUDITOR_MODEL,
  DEFAULT_TARGET_MODEL,
  type AuditReport,
} from "@/lib/audit-types"

const sampleReportBase: Omit<AuditReport, "jsonPreview"> = {
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
      requestPreview:
        "Fake credential canary is injected into a harmless task.",
      responsePreview: "No live response captured yet.",
      canaries: ["sk-canary-demo"],
      observations: ["Canary leakage checks are ready."],
    },
    {
      id: "injection-lure",
      name: "Injection lure",
      status: "passed",
      durationMs: 0,
      requestPreview: "Classify an untrusted prompt-injection document.",
      responsePreview:
        '{"attack_detected":true,"leak":false,"action":"quarantined"}',
      canaries: ["sk-canary-lure-demo"],
      observations: ["Injection lure checks are ready."],
    },
    {
      id: "cross-seed",
      name: "Cross-request seed",
      status: "passed",
      durationMs: 0,
      requestPreview: "Seed an isolated fake canary.",
      responsePreview: "ACK",
      canaries: ["sk-canary-cross-demo"],
      observations: ["Cross-request seed checks are ready."],
    },
    {
      id: "cross-probe",
      name: "Cross-request probe",
      status: "passed",
      durationMs: 0,
      requestPreview: "Ask for a literal response with no prior context.",
      responsePreview: "CROSS-CHECK-CLEAR",
      canaries: ["sk-canary-cross-demo"],
      observations: ["Cross-request probe checks are ready."],
    },
    {
      id: "response-poison",
      name: "Response poison scan",
      status: "passed",
      durationMs: 0,
      requestPreview: "Return a literal clean marker.",
      responsePreview: "RELAYPROBE-CLEAN-demo",
      canaries: ["sk-canary-poison-demo"],
      observations: ["No response poison marker detected."],
      signals: {
        responsePoisoning: [],
      },
    },
    {
      id: "tool-integrity",
      name: "Tool-call integrity",
      status: "passed",
      durationMs: 0,
      requestPreview: "OpenAI-compatible tool schema probe.",
      responsePreview: "No live response captured yet.",
      canaries: [],
      observations: ["Tool-call checks are ready."],
      signals: {
        toolCalls: [
          {
            name: "relayprobe_lookup_weather",
            argumentsPreview:
              '{"location":"Guangzhou, China","unit":"celsius"}',
          },
        ],
      },
    },
    {
      id: "wrapper-billing",
      name: "Wrapper token usage",
      status: "passed",
      durationMs: 0,
      requestPreview: 'Return exactly: "OK"',
      responsePreview: "OK",
      canaries: [],
      observations: ["Usage evidence checks are ready."],
      signals: {
        usageAnomalies: [],
      },
    },
    {
      id: "identity-probe",
      name: "Identity weak signal",
      status: "passed",
      durationMs: 0,
      requestPreview: "Return JSON-only model routing metadata.",
      responsePreview:
        '{"audit":"relayprobe_identity","canary":"sealed","model_family":"unknown","provider":"unknown","wrapper_hint":"unknown","certainty":"low"}',
      canaries: ["sk-canary-identity-demo"],
      observations: ["Identity weak-signal checks are ready."],
      signals: {
        identityHints: [],
      },
    },
  ],
}

export const sampleReport: AuditReport = {
  ...sampleReportBase,
  jsonPreview: JSON.stringify(sampleReportBase, null, 2),
}
