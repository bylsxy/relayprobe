# False Positives

RelayProbe deliberately avoids strong claims when evidence can be explained by normal model behavior.

## Common Causes

- Model nondeterminism, even at low temperature
- Provider-specific model aliases
- Relay-side content filters that are stricter than the baseline
- Unsupported OpenAI-compatible parameters
- SSE or transport differences if a future streaming probe is added
- Prompt wording that accidentally asks the model to repeat a canary
- Cache behavior that returns stale but non-malicious output
- Providers that omit or rename `usage` fields
- Relays that do not support OpenAI-compatible `tool_calls`
- Tool-capable models that choose text output despite a forced tool choice
- Self-reported model identity text that is influenced by the prompt wording
- Tokenizer and billing differences between providers

## Reducing Noise

- Use the official baseline when possible.
- Keep probes short and deterministic.
- Repeat a suspicious run with new canaries.
- Treat style, tone, and verbosity changes as weak evidence.
- Treat exact canary recurrence as stronger evidence than normal text drift.
- Treat response-poisoning markers as stronger than style differences, but repeat with fresh canaries before escalation.
- Treat usage/token anomalies as supporting evidence until compared with invoices or a direct baseline.
- Keep identity probes low-weight unless they align with stronger tool, canary, or baseline evidence.
