# Contributing

RelayProbe needs conservative security language and reproducible tests.

## Good Contributions

- New safe probe templates using fake data only
- Better OpenAI-compatible response parsing
- Clear false-positive documentation
- UI improvements that keep reports evidence-first
- Tests for scoring and canary detection

## Guardrails

- Do not add offensive scanning, credential harvesting, or relay reverse-engineering code.
- Do not add claims that RelayProbe can prove a relay is safe or malicious.
- Keep examples synthetic and publicly shareable.

## Local Checks

```bash
npm run lint
npm run typecheck
npm run build
```

