"use client"

import * as React from "react"
import {
  ActivityIcon,
  BrainIcon,
  CopyIcon,
  DownloadIcon,
  FileJsonIcon,
  FingerprintIcon,
  InfoIcon,
  KeyRoundIcon,
  PlayIcon,
  RefreshCwIcon,
  SearchCheckIcon,
  ServerIcon,
  ShieldCheckIcon,
  TriangleAlertIcon,
} from "lucide-react"
import { toast } from "sonner"

import {
  DEFAULT_AUDITOR_MODEL,
  DEFAULT_TARGET_MODEL,
  defaultProfiles,
  severityRank,
  type AuditFinding,
  type AuditReport,
  type AuditRequestPayload,
  type Severity,
  type TestProfileKey,
} from "@/lib/audit-types"
import { sampleReport } from "@/lib/sample-report"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
  InputGroupTextarea,
} from "@/components/ui/input-group"
import { Progress } from "@/components/ui/progress"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

type FormState = AuditRequestPayload

const profileMeta: Array<{
  key: TestProfileKey
  title: string
  description: string
}> = [
  {
    key: "schemaLock",
    title: "Schema lock",
    description: "Exact JSON contract.",
  },
  {
    key: "canaryLeak",
    title: "Canary seal",
    description: "Fake credential containment.",
  },
  {
    key: "injectionLure",
    title: "Injection lure",
    description: "Untrusted text trap.",
  },
  {
    key: "crossRequest",
    title: "Cross-request",
    description: "Isolation check.",
  },
  {
    key: "responsePoisoning",
    title: "Poison scan",
    description: "MITM payload markers.",
  },
  {
    key: "toolIntegrity",
    title: "Tool integrity",
    description: "OpenAI tool_calls path.",
  },
  {
    key: "wrapperBilling",
    title: "Wrapper tokens",
    description: "Hidden usage evidence.",
  },
  {
    key: "identityProbe",
    title: "Identity hints",
    description: "Weak model routing signal.",
  },
]

export function RelayProbeConsole() {
  const [form, setForm] = React.useState<FormState>({
    endpoint: "https://relay.example.com/v1",
    relayApiKey: "",
    targetModel: DEFAULT_TARGET_MODEL,
    auditorModel: DEFAULT_AUDITOR_MODEL,
    includeBaseline: false,
    captureFullResponses: false,
    profiles: defaultProfiles,
    customInstruction: "",
  })
  const [report, setReport] = React.useState<AuditReport>(sampleReport)
  const [isRunning, setIsRunning] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const activeCase = report.cases[0]
  const severeCount = report.findings.filter((finding) =>
    ["critical", "high"].includes(finding.severity)
  ).length

  async function runAudit() {
    setError(null)

    if (!form.endpoint.trim() || !form.relayApiKey.trim()) {
      setError("Endpoint and relay key are required.")
      return
    }

    setIsRunning(true)

    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(form),
      })
      const body = await response.json()

      if (!response.ok) {
        throw new Error(body.error ?? "Audit failed.")
      }

      setReport(body as AuditReport)
      toast.success("Audit completed")
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Audit request failed."
      setError(message)
      toast.error(message)
    } finally {
      setIsRunning(false)
    }
  }

  function resetDemo() {
    setReport(sampleReport)
    setError(null)
  }

  function updateForm<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }))
  }

  function updateProfile(key: TestProfileKey, checked: boolean) {
    setForm((current) => ({
      ...current,
      profiles: {
        ...current.profiles,
        [key]: checked,
      },
    }))
  }

  return (
    <div className="@container/main flex flex-1 flex-col gap-4 p-4 lg:gap-6 lg:p-6">
      <section className="grid grid-cols-1 gap-4 @4xl/main:grid-cols-4">
        <MetricCard
          title="Risk score"
          value={`${report.riskScore}`}
          suffix="/100"
          description={report.topSeverity}
          icon={<TriangleAlertIcon />}
          severity={report.topSeverity}
        />
        <MetricCard
          title="Cases run"
          value={`${report.cases.length}`}
          suffix="cases"
          description={isRunning ? "running" : report.status}
          icon={<ActivityIcon />}
          severity={isRunning ? "low" : "info"}
        />
        <MetricCard
          title="Severe findings"
          value={`${severeCount}`}
          suffix="flagged"
          description={`${report.findings.length} total`}
          icon={<SearchCheckIcon />}
          severity={severeCount ? "high" : "info"}
        />
        <MetricCard
          title="Auditor mode"
          value={report.auditorMode === "ai" ? "AI" : "Heuristic"}
          suffix={report.auditorModel}
          description="ready"
          icon={<BrainIcon />}
          severity={report.auditorMode === "ai" ? "low" : "info"}
        />
      </section>

      <section className="grid grid-cols-1 gap-4 2xl:grid-cols-[420px_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Audit configuration</CardTitle>
            <CardDescription>
              GPT-5.5 relay MITM evidence probes
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="endpoint">Endpoint</FieldLabel>
                <InputGroup>
                  <InputGroupAddon>
                    <ServerIcon />
                  </InputGroupAddon>
                  <InputGroupInput
                    id="endpoint"
                    value={form.endpoint}
                    onChange={(event) =>
                      updateForm("endpoint", event.target.value)
                    }
                    placeholder="https://relay.example.com/v1"
                    autoComplete="off"
                  />
                </InputGroup>
              </Field>

              <Field>
                <FieldLabel htmlFor="relay-key">Relay key</FieldLabel>
                <InputGroup>
                  <InputGroupAddon>
                    <KeyRoundIcon />
                  </InputGroupAddon>
                  <InputGroupInput
                    id="relay-key"
                    type="password"
                    value={form.relayApiKey}
                    onChange={(event) =>
                      updateForm("relayApiKey", event.target.value)
                    }
                    placeholder="sk-relay-..."
                    autoComplete="off"
                  />
                </InputGroup>
              </Field>

              <div className="grid grid-cols-1 gap-3 @md/main:grid-cols-2">
                <Field>
                  <FieldLabel htmlFor="target-model">Target model</FieldLabel>
                  <Select
                    value={form.targetModel}
                    onValueChange={(value) => updateForm("targetModel", value)}
                  >
                    <SelectTrigger id="target-model" className="w-full">
                      <SelectValue placeholder={DEFAULT_TARGET_MODEL} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="gpt-5.5">gpt-5.5</SelectItem>
                        <SelectItem value="gpt-5.4">gpt-5.4</SelectItem>
                        <SelectItem value="gpt-5.4-mini">
                          gpt-5.4-mini
                        </SelectItem>
                        <SelectItem value="gpt-4.1">gpt-4.1</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>

                <Field>
                  <FieldLabel htmlFor="auditor-model">Auditor model</FieldLabel>
                  <Select
                    value={form.auditorModel}
                    onValueChange={(value) => updateForm("auditorModel", value)}
                  >
                    <SelectTrigger id="auditor-model" className="w-full">
                      <SelectValue placeholder={DEFAULT_AUDITOR_MODEL} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="gpt-5.5">gpt-5.5</SelectItem>
                        <SelectItem value="gpt-5.4">gpt-5.4</SelectItem>
                        <SelectItem value="gpt-5.4-mini">
                          gpt-5.4-mini
                        </SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>
              </div>

              <Field>
                <FieldLabel htmlFor="custom-instruction">
                  Local policy
                </FieldLabel>
                <InputGroup>
                  <InputGroupTextarea
                    id="custom-instruction"
                    value={form.customInstruction}
                    onChange={(event) =>
                      updateForm("customInstruction", event.target.value)
                    }
                    placeholder="Optional local policy for this run"
                    rows={3}
                  />
                </InputGroup>
              </Field>

              <FieldGroup data-slot="checkbox-group" className="gap-3">
                {profileMeta.map((profile) => (
                  <Field key={profile.key} orientation="horizontal">
                    <Checkbox
                      id={profile.key}
                      checked={form.profiles[profile.key]}
                      onCheckedChange={(checked) =>
                        updateProfile(profile.key, checked === true)
                      }
                    />
                    <FieldContent>
                      <FieldLabel htmlFor={profile.key}>
                        {profile.title}
                      </FieldLabel>
                      <FieldDescription>{profile.description}</FieldDescription>
                    </FieldContent>
                  </Field>
                ))}
              </FieldGroup>

              <Separator />

              <FieldGroup data-slot="checkbox-group" className="gap-3">
                <Field orientation="horizontal">
                  <Checkbox
                    id="include-baseline"
                    checked={form.includeBaseline}
                    onCheckedChange={(checked) =>
                      updateForm("includeBaseline", checked === true)
                    }
                  />
                  <FieldContent>
                    <FieldLabel htmlFor="include-baseline">
                      Official baseline
                    </FieldLabel>
                    <FieldDescription>
                      Requires server OPENAI_API_KEY.
                    </FieldDescription>
                  </FieldContent>
                </Field>
                <Field orientation="horizontal">
                  <Checkbox
                    id="capture-full"
                    checked={form.captureFullResponses}
                    onCheckedChange={(checked) =>
                      updateForm("captureFullResponses", checked === true)
                    }
                  />
                  <FieldContent>
                    <FieldLabel htmlFor="capture-full">
                      Capture longer evidence
                    </FieldLabel>
                    <FieldDescription>
                      Keep report snippets expanded.
                    </FieldDescription>
                  </FieldContent>
                </Field>
              </FieldGroup>

              {error ? (
                <Alert variant="destructive">
                  <TriangleAlertIcon />
                  <AlertTitle>Audit failed</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              ) : null}

              <div className="grid grid-cols-[1fr_auto] gap-2">
                <Button onClick={runAudit} disabled={isRunning}>
                  {isRunning ? (
                    <RefreshCwIcon data-icon="inline-start" />
                  ) : (
                    <PlayIcon data-icon="inline-start" />
                  )}
                  {isRunning ? "Running" : "Run audit"}
                </Button>
                <Button variant="outline" size="icon" onClick={resetDemo}>
                  <RefreshCwIcon />
                  <span className="sr-only">Reset demo</span>
                </Button>
              </div>
            </FieldGroup>
          </CardContent>
        </Card>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Results overview</CardTitle>
              <CardDescription>{report.summary}</CardDescription>
              <CardAction>
                <SeverityBadge severity={report.topSeverity} />
              </CardAction>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid grid-cols-1 gap-3 @3xl/main:grid-cols-[220px_1fr]">
                <div className="flex flex-col gap-2 rounded-lg border p-3">
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span className="text-muted-foreground">Risk score</span>
                    <span className="font-medium tabular-nums">
                      {report.riskScore}/100
                    </span>
                  </div>
                  <Progress value={report.riskScore} />
                  <div className="text-xs text-muted-foreground">
                    {report.auditorMode === "ai"
                      ? `Reviewed by ${report.auditorModel}`
                      : "Deterministic checks only"}
                  </div>
                </div>
                <FindingTable findings={report.findings} />
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-4 @5xl/main:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Test matrix</CardTitle>
                <CardDescription>{report.endpointHost}</CardDescription>
              </CardHeader>
              <CardContent>
                <CaseMatrix report={report} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Evidence preview</CardTitle>
                <CardDescription>
                  {activeCase ? activeCase.name : "No case selected"}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="response" className="flex flex-col gap-3">
                  <TabsList>
                    <TabsTrigger value="response">Response</TabsTrigger>
                    <TabsTrigger value="request">Request</TabsTrigger>
                    <TabsTrigger value="json">JSON</TabsTrigger>
                  </TabsList>
                  <TabsContent value="response">
                    <CodePanel
                      value={
                        activeCase?.responsePreview ??
                        "No response captured yet."
                      }
                    />
                  </TabsContent>
                  <TabsContent value="request">
                    <CodePanel
                      value={
                        activeCase?.requestPreview ?? "No request captured yet."
                      }
                    />
                  </TabsContent>
                  <TabsContent value="json">
                    <CodePanel value={report.jsonPreview} />
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 2xl:grid-cols-[1fr_420px]">
        <Card>
          <CardHeader>
            <CardTitle>Methodology</CardTitle>
            <CardDescription>
              Canary, active lure, tool, usage, evidence
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-3 @3xl/main:grid-cols-3 @6xl/main:grid-cols-6">
              <MethodStep
                icon={<FingerprintIcon />}
                title="Canary"
                body="Unique fake secrets are generated per run."
              />
              <MethodStep
                icon={<ShieldCheckIcon />}
                title="Containment"
                body="Responses are scanned for exact token leakage."
              />
              <MethodStep
                icon={<FileJsonIcon />}
                title="Structure"
                body="Strict JSON and literal contracts are checked."
              />
              <MethodStep
                icon={<InfoIcon />}
                title="Attribution"
                body="Findings stay at observable evidence level."
              />
              <MethodStep
                icon={<TriangleAlertIcon />}
                title="Poison"
                body="Operator-facing payload markers are scanned."
              />
              <MethodStep
                icon={<SearchCheckIcon />}
                title="Tools"
                body="Tool-call stripping and mutation are checked."
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Run output</CardTitle>
            <CardDescription>Portable JSON report</CardDescription>
            <CardAction className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyReport(report)}
              >
                <CopyIcon data-icon="inline-start" />
                Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => downloadReport(report)}
              >
                <DownloadIcon data-icon="inline-start" />
                JSON
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <CodePanel value={report.jsonPreview} minHeight="min-h-60" />
          </CardContent>
        </Card>
      </section>
    </div>
  )
}

function MetricCard({
  title,
  value,
  suffix,
  description,
  icon,
  severity,
}: {
  title: string
  value: string
  suffix: string
  description: string
  icon: React.ReactNode
  severity: Severity
}) {
  return (
    <Card className="@container/card">
      <CardHeader>
        <CardDescription className="flex items-center gap-2">
          {React.cloneElement(
            icon as React.ReactElement<{ className?: string }>,
            {
              className: "text-muted-foreground",
            }
          )}
          {title}
        </CardDescription>
        <CardTitle className="flex items-end gap-2 text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
          <span
            className={severityRank(severity) >= 4 ? "text-destructive" : ""}
          >
            {value}
          </span>
          <span className="pb-1 text-sm font-normal text-muted-foreground">
            {suffix}
          </span>
        </CardTitle>
        <CardAction>
          <SeverityBadge severity={severity} label={description} />
        </CardAction>
      </CardHeader>
    </Card>
  )
}

function FindingTable({ findings }: { findings: AuditFinding[] }) {
  const sorted = [...findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity)
  )

  return (
    <div className="overflow-hidden rounded-lg border">
      {sorted.length ? (
        <div className="flex flex-col divide-y">
          {sorted.map((finding) => (
            <div
              key={finding.id}
              className="grid grid-cols-[auto_1fr_auto] gap-3 p-3"
            >
              <SeverityBadge severity={finding.severity} />
              <div className="flex min-w-0 flex-col gap-1">
                <span className="font-medium break-words">{finding.title}</span>
                <span className="text-sm break-words text-muted-foreground">
                  {finding.evidence}
                </span>
              </div>
              <div className="text-right text-sm text-muted-foreground tabular-nums">
                {finding.confidence}%
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="p-6 text-center text-sm text-muted-foreground">
          No findings.
        </div>
      )}
    </div>
  )
}

function CaseMatrix({ report }: { report: AuditReport }) {
  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="flex flex-col divide-y">
        {report.cases.map((item) => (
          <div key={item.id} className="grid grid-cols-[1fr_auto] gap-3 p-3">
            <div className="flex min-w-0 flex-col gap-1">
              <span className="font-medium break-words">{item.name}</span>
              <span className="text-xs break-words text-muted-foreground">
                {item.observations[0] ?? "No observation"}
              </span>
              <span className="text-xs text-muted-foreground">
                HTTP {item.httpStatus ?? "-"} - {item.durationMs}ms
              </span>
            </div>
            <Badge
              variant={
                item.status === "failed" || item.status === "error"
                  ? "destructive"
                  : item.status === "warning"
                    ? "outline"
                    : "secondary"
              }
            >
              {item.status}
            </Badge>
          </div>
        ))}
      </div>
    </div>
  )
}

function SeverityBadge({
  severity,
  label,
}: {
  severity: Severity
  label?: string
}) {
  const variant =
    severity === "critical" || severity === "high"
      ? "destructive"
      : severity === "medium"
        ? "outline"
        : "secondary"

  return <Badge variant={variant}>{label ?? severity}</Badge>
}

function CodePanel({
  value,
  minHeight = "min-h-44",
}: {
  value: string
  minHeight?: string
}) {
  return (
    <ScrollArea
      className={`${minHeight} max-h-96 rounded-lg border bg-muted/30`}
    >
      <pre className="p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">
        {value}
      </pre>
    </ScrollArea>
  )
}

function MethodStep({
  icon,
  title,
  body,
}: {
  icon: React.ReactNode
  title: string
  body: string
}) {
  return (
    <div className="flex min-h-28 flex-col gap-3 rounded-lg border p-3">
      <div className="flex items-center gap-2 font-medium">
        {React.cloneElement(
          icon as React.ReactElement<{ className?: string }>,
          {
            className: "text-muted-foreground",
          }
        )}
        <span>{title}</span>
      </div>
      <p className="text-sm text-muted-foreground">{body}</p>
    </div>
  )
}

async function copyReport(report: AuditReport) {
  await navigator.clipboard.writeText(report.jsonPreview)
  toast.success("Report copied")
}

function downloadReport(report: AuditReport) {
  const blob = new Blob([report.jsonPreview], {
    type: "application/json",
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = `relayprobe-${report.runId}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}
