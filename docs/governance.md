# Governance

RelayProbe uses a protected `main` branch. Normal changes should go through a topic branch and pull request.

## Branch Rules

- Direct pushes to `main` are blocked.
- Force pushes and branch deletion are blocked.
- Pull requests require at least one approving review.
- The latest pusher cannot approve their own change.
- Stale reviews are dismissed when new commits are pushed.
- Required checks must pass before merge.
- Branches must be up to date with `main` before merge.
- Conversations must be resolved before merge.
- Admins are included in branch protection.

## Required Checks

The required GitHub Actions check is `verify`, which runs:

- `npm ci`
- `npm run lint`
- `npm run test`
- `npm run typecheck`
- `npm run build`

## Merge Policy

Use squash merge for a clean linear history. Merge commits and rebase merges are disabled in the repository settings.

## Security Review

RelayProbe is a security-adjacent tool. Reviewers should reject changes that:

- add real credentials, private prompts, production logs, or personal data
- add offensive scanning or unauthorized reverse-engineering behavior
- claim a relay is definitively safe or malicious from weak evidence
- add new probes without false-positive notes or synthetic fixtures
