# Safe Testing

RelayProbe is for defensive checks against endpoints you are allowed to use.

## Do

- Use fake credentials and synthetic documents.
- Use canaries and honey prompts only for defensive verification of endpoints you are allowed to test.
- Use a dedicated relay key with the smallest possible balance.
- Run from a local machine or controlled environment.
- Save reports before escalating concerns.
- Repeat suspicious runs with fresh canaries.

## Do Not

- Send real `.env` files, private code, business documents, student data, or personal data.
- Scan relay infrastructure or try to bypass authentication.
- Reverse engineer proprietary relay code without permission.
- Turn response-poisoning probes into real exploit payloads.
- Publish accusations based only on one noisy model response.
- Use RelayProbe as proof that a relay is safe.

## Recommended Test Account Setup

Create a disposable relay account, fund it minimally, and rotate the relay key after testing. If the relay supports request logs, disable logging before running probes.
