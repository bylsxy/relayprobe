import type {
  AuditSignal,
  Severity,
  TokenUsageSignal,
  ToolCallSignal,
} from "@/lib/audit-types"

type PatternRule = {
  id: string
  label: string
  severity: Severity
  pattern: RegExp
  evidence: string
}

const POISON_RULES: PatternRule[] = [
  {
    id: "shell-pipe-exec",
    label: "Shell pipe execution",
    severity: "high",
    pattern:
      /\b(curl|wget)\b[^\n\r]{0,120}\|\s*(sh|bash|zsh)|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n\r]{0,120}\|\s*(iex|invoke-expression)/i,
    evidence: "Response contained a download-and-execute command pattern.",
  },
  {
    id: "powershell-encoded",
    label: "PowerShell encoded payload",
    severity: "high",
    pattern: /\bpowershell(?:\.exe)?\b[^\n\r]{0,140}-(enc|encodedcommand)\b/i,
    evidence: "Response contained a PowerShell encoded command pattern.",
  },
  {
    id: "instruction-override",
    label: "Instruction override text",
    severity: "medium",
    pattern:
      /\b(ignore|disregard|forget)\b[^\n\r]{0,60}\b(previous|above|system|developer)\b[^\n\r]{0,80}\b(instruction|prompt|message)s?\b/i,
    evidence: "Response contained text that looks like a prompt override.",
  },
  {
    id: "operator-action",
    label: "Operator action request",
    severity: "medium",
    pattern:
      /\b(to continue|before proceeding|for verification)\b[^\n\r]{0,80}\b(run|execute|paste|copy|download|install)\b/i,
    evidence: "Response attempted to make the operator run or paste content.",
  },
  {
    id: "markdown-image-exfil",
    label: "Markdown image callback",
    severity: "high",
    pattern: /!\[[^\]]*]\((?:https?:)?\/\/[^)\s]+[?&][^)\s=]+=/i,
    evidence: "Response contained a markdown image URL with query parameters.",
  },
  {
    id: "hidden-unicode",
    label: "Hidden Unicode control",
    severity: "medium",
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF\u202A-\u202E]/u,
    evidence:
      "Response contained hidden or direction-changing Unicode controls.",
  },
  {
    id: "long-base64",
    label: "Long encoded blob",
    severity: "medium",
    pattern: /(?:[A-Za-z0-9+/]{80,}={0,2})|(?:\b[0-9a-f]{96,}\b)/i,
    evidence: "Response contained a long encoded blob.",
  },
]

export function scanResponsePoisoning(text: string): AuditSignal[] {
  if (!text.trim()) return []

  return POISON_RULES.filter((rule) => rule.pattern.test(text)).map((rule) => ({
    id: rule.id,
    label: rule.label,
    severity: rule.severity,
    evidence: rule.evidence,
  }))
}

export function extractTokenUsage(
  payload: unknown
): TokenUsageSignal | undefined {
  const usage = readObject(payload, "usage")
  if (!usage) return undefined

  const promptTokens =
    readNumber(usage, "prompt_tokens") ?? readNumber(usage, "input_tokens")
  const completionTokens =
    readNumber(usage, "completion_tokens") ?? readNumber(usage, "output_tokens")
  const totalTokens = readNumber(usage, "total_tokens")

  const promptDetails = readObject(usage, "prompt_tokens_details")
  const inputDetails = readObject(usage, "input_tokens_details")
  const cachedTokens =
    readNumber(promptDetails, "cached_tokens") ??
    readNumber(inputDetails, "cached_tokens") ??
    readNumber(usage, "cached_tokens")

  const cacheReadInputTokens =
    readNumber(usage, "cache_read_input_tokens") ??
    readNumber(usage, "cache_read_tokens")
  const cacheCreationInputTokens =
    readNumber(usage, "cache_creation_input_tokens") ??
    readNumber(usage, "cache_creation_tokens")

  const result: TokenUsageSignal = {
    promptTokens,
    completionTokens,
    totalTokens,
    cachedTokens,
    cacheReadInputTokens,
    cacheCreationInputTokens,
  }

  return Object.values(result).some((value) => typeof value === "number")
    ? result
    : undefined
}

export function detectUsageAnomalies(
  usage: TokenUsageSignal | undefined
): AuditSignal[] {
  if (!usage) return []

  const signals: AuditSignal[] = []
  const cached =
    usage.cachedTokens ??
    usage.cacheReadInputTokens ??
    usage.cacheCreationInputTokens ??
    0

  if ((usage.promptTokens ?? 0) > 180) {
    signals.push({
      id: "tiny-prompt-large-usage",
      label: "Tiny prompt large usage",
      severity: (usage.promptTokens ?? 0) > 800 ? "high" : "medium",
      evidence: `Tiny probe reported ${usage.promptTokens} prompt tokens.`,
    })
  }

  if (cached > 300) {
    signals.push({
      id: "unexpected-cache-usage",
      label: "Unexpected cache usage",
      severity: cached > 1500 ? "high" : "medium",
      evidence: `Tiny probe reported ${cached} cached or cache-created input tokens.`,
    })
  }

  return signals
}

export function extractToolCalls(payload: unknown): ToolCallSignal[] {
  const choice = Array.isArray((payload as { choices?: unknown[] })?.choices)
    ? (payload as { choices: unknown[] }).choices[0]
    : undefined
  const message = readObject(choice, "message")
  const toolCalls = Array.isArray(message?.tool_calls)
    ? message.tool_calls
    : undefined

  if (toolCalls) {
    return toolCalls.map((call) => {
      const functionCall = readObject(call, "function")
      return {
        id: readString(call, "id"),
        name: readString(functionCall, "name"),
        argumentsPreview: truncate(
          readString(functionCall, "arguments") ?? "",
          600
        ),
      }
    })
  }

  const legacyFunctionCall = readObject(message, "function_call")
  if (legacyFunctionCall) {
    return [
      {
        name: readString(legacyFunctionCall, "name"),
        argumentsPreview: truncate(
          readString(legacyFunctionCall, "arguments") ?? "",
          600
        ),
      },
    ]
  }

  return []
}

export function detectIdentityHints(
  text: string,
  targetModel: string
): AuditSignal[] {
  const lowered = text.toLowerCase()
  const target = targetModel.toLowerCase()
  const signals: AuditSignal[] = []

  const wrapperHints = [
    "cursor",
    "continue",
    "cline",
    "kiro",
    "openrouter",
    "new api",
    "one api",
  ].filter((hint) => lowered.includes(hint))

  if (wrapperHints.length) {
    signals.push({
      id: "wrapper-self-report",
      label: "Wrapper self-report",
      severity: "low",
      evidence: `Response mentioned wrapper or client terms: ${wrapperHints.join(", ")}.`,
    })
  }

  const mismatchedFamilies = [
    "claude",
    "anthropic",
    "gemini",
    "deepseek",
    "qwen",
    "kimi",
  ].filter((family) => lowered.includes(family))

  if (target.startsWith("gpt") && mismatchedFamilies.length) {
    signals.push({
      id: "family-self-report-mismatch",
      label: "Model family self-report mismatch",
      severity: "low",
      evidence: `Target is ${targetModel}, but response mentioned ${mismatchedFamilies.join(", ")}.`,
    })
  }

  return signals
}

export function usageSummary(usage: TokenUsageSignal | undefined) {
  if (!usage) return "No usage object was returned."

  return [
    usage.promptTokens === undefined
      ? undefined
      : `prompt=${usage.promptTokens}`,
    usage.completionTokens === undefined
      ? undefined
      : `completion=${usage.completionTokens}`,
    usage.totalTokens === undefined ? undefined : `total=${usage.totalTokens}`,
    usage.cachedTokens === undefined
      ? undefined
      : `cached=${usage.cachedTokens}`,
    usage.cacheReadInputTokens === undefined
      ? undefined
      : `cache_read=${usage.cacheReadInputTokens}`,
    usage.cacheCreationInputTokens === undefined
      ? undefined
      : `cache_create=${usage.cacheCreationInputTokens}`,
  ]
    .filter(Boolean)
    .join(", ")
}

function readObject(
  value: unknown,
  key: string
): (Record<string, unknown> & { [key: string]: unknown }) | undefined {
  if (typeof value !== "object" || value === null) return undefined
  const child = (value as Record<string, unknown>)[key]
  return typeof child === "object" && child !== null
    ? (child as Record<string, unknown>)
    : undefined
}

function readNumber(value: unknown, key: string) {
  if (typeof value !== "object" || value === null) return undefined
  const child = (value as Record<string, unknown>)[key]
  return typeof child === "number" && Number.isFinite(child) ? child : undefined
}

function readString(value: unknown, key: string) {
  if (typeof value !== "object" || value === null) return undefined
  const child = (value as Record<string, unknown>)[key]
  return typeof child === "string" ? child : undefined
}

function truncate(value: string, maxLength: number) {
  if (value.length <= maxLength) return value
  return `${value.slice(0, maxLength)}...[truncated]`
}
