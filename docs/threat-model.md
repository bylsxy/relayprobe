# Threat Model

RelayProbe assumes the relay can see requests and responses sent through it. The tool focuses on observable behavior, not hidden server intent.

## In Scope

- Added, removed, or rewritten prompt content
- Extra system/developer instructions inserted by middleware
- Response pollution such as ads, disclaimers, or hidden policy text
- Response poisoning that asks the operator to run commands, open callback images, or copy hidden text
- Fake-secret canaries appearing in a current or later response
- Cross-request contamination caused by caching or session bleed
- Tool-call stripping, conversion, or mutation in OpenAI-compatible requests
- Unexpected prompt/cache token usage that suggests hidden wrapper text
- Basic OpenAI-compatible chat completions failures

## Out of Scope

- Reverse engineering relay server code
- Scanning relay infrastructure
- Proving whether a relay stores logs offline
- Proving malicious ownership or intent
- Proving model identity based only on self-reported text
- Testing with real credentials, private documents, or personal data

## Output Language

Reports should say "observable anomaly" or "behavior inconsistent with the baseline." They should not say "the relay is malicious" or "the relay is safe."
