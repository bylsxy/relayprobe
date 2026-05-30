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

## Reducing Noise

- Use the official baseline when possible.
- Keep probes short and deterministic.
- Repeat a suspicious run with new canaries.
- Treat style, tone, and verbosity changes as weak evidence.
- Treat exact canary recurrence as stronger evidence than normal text drift.

