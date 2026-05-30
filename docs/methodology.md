# Methodology

RelayProbe uses four layers. Each layer is intentionally conservative.

## L1 Protocol

The server route calls an OpenAI-compatible `/v1/chat/completions` endpoint and records status, latency, and a redacted response preview. Remote plain HTTP endpoints are rejected unless they are localhost.

## L2 Integrity

Strict JSON and literal-output cases are sent with `temperature: 0`. A parse failure or unexpected text is reported as structure drift. Structure drift alone is low or medium confidence unless a direct baseline succeeds.

## L3 Canary Leakage

Each run creates unique fake secrets such as `sk-canary-seal-<uuid>`. A response containing a canary is strong evidence of leakage or instruction failure. A later unrelated response containing a previous canary is treated as cross-request contamination.

## L4 Auditor Review

If `OPENAI_API_KEY` exists, the captured evidence is reviewed by the configured auditor model, defaulting to `gpt-5.5`. The auditor is instructed to avoid intent attribution and to call out false-positive risks.

## Scoring

Risk score is a weighted summary of findings:

- critical: cross-request canary evidence
- high: canary exposure in a response
- medium: failed relay request, baseline mismatch, or injection-lure structure drift
- low: strict-output drift without baseline confirmation
- info: configuration or scope notes

