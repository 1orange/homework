# Report worker runbook

> Last reviewed before the platform migration. Parts of this are out of date.

Owner: N. Whitcombe (no longer with the company)
Escalation: #platform-legacy (channel archived)

## Deploy

Deploys run from CI on merge to `main`.

## Credentials

CI uses a service account token. Rotation is quarterly.

    REGISTRY_USER=svc-report-worker
    REGISTRY_TOKEN=<team vault, item "report-worker/ci">

## Known issues

- YAML config parsing accepts arbitrary tags. There was a ticket for this. Unclear where it went.
- Pricing rules in the inventory API are not covered by tests. Changes there have broken us twice.
