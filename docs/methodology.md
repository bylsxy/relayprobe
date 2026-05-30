# Methodology

RelayProbe uses conservative evidence layers. A finding means "observable anomaly," not "the relay is malicious."

## L1 Protocol

The server route calls an OpenAI-compatible `/v1/chat/completions` endpoint and records status, latency, response preview, `tool_calls`, and provider usage fields when present. Remote plain HTTP endpoints are rejected unless they are localhost.

## L2 Integrity Contracts

Strict JSON and literal-output probes run with `temperature: 0`. Contract drift is useful supporting evidence, especially when an optional official baseline succeeds, but it is not enough on its own to attribute intent.

## L3 Canary Leakage

Each run creates unique fake secrets such as `sk-canary-seal-<uuid>`. A response containing the canary is high-confidence leakage evidence. A later unrelated response containing a prior canary is treated as cross-request contamination.

## L4 Active Lures

RelayProbe sends harmless prompts that look attractive to badly written middleware: fake credentials, untrusted text, strict output constraints, and defensive honey prompts. The goal is to detect prompt-injection MITM behavior without sending real secrets or exploit payloads.

## L5 Response Poisoning

The response scanner flags operator-facing payload markers:

- download-and-execute command chains
- encoded PowerShell patterns
- instruction override text
- "run/copy/paste/download" operator action requests
- markdown image callbacks with query parameters
- hidden Unicode controls
- long encoded blobs

These markers are stronger than normal tone or style differences because they can create downstream operator risk.

## L6 Tool Calls

The tool-integrity probe sends an OpenAI-compatible `tools` schema and expects a `tool_call` for `relayprobe_lookup_weather`. Missing, renamed, or text-only tool output suggests relay incompatibility or middleware stripping. This is evidence about the relay path, not proof of model substitution.

## L7 Usage Evidence

The wrapper-billing probe sends a tiny literal-output request and reads `usage.prompt_tokens`, cached-token details, and Anthropic-style cache fields if present. Unexpectedly large prompt/cache numbers can indicate hidden wrapper text, cache injection, or provider-specific accounting. Treat this as supporting evidence and compare against the official baseline and relay invoice.

## L8 Auditor Review

If `OPENAI_API_KEY` exists, the captured evidence is reviewed by the configured auditor model, defaulting to `gpt-5.5`. The auditor is instructed to avoid claims that a relay is safe or malicious and to call out false-positive risk.

## Scoring

Risk score is a weighted summary of findings:

- critical: cross-request canary recurrence or similarly severe evidence
- high: canary exposure, response poisoning payload markers, extreme hidden usage evidence
- medium: relay request failures, tool-call stripping, baseline mismatch, injection-lure drift
- low: identity self-report mismatch or weak wrapper hints
- info: configuration and scope notes
