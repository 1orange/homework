# patch-harness-exercise

Two small services that share a findings feed. Both have dependency findings open against them.

- `services/inventory-api` — Java 17, Spring Boot, Maven
- `services/report-worker` — Python 3.11

Open findings are in `findings/findings.json`, in the shape our scanner emits.

## Prerequisites

JDK 17 and Maven 3.9+ for the Java service. Python 3.11 for the worker. No wrapper scripts;
use your own toolchain.

## Running things

    cd services/inventory-api
    mvn test

    cd services/report-worker
    pip install -r requirements.lock pytest
    pytest

## Notes

Ownership of the report worker moved during the platform migration and the docs under
`docs/` are partly stale. See `CONTRIBUTING.md` before opening changes.
