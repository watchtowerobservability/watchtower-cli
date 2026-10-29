---
name: watchtower-instrument
description: Instrument this repository with OpenTelemetry so it reports traces, metrics and logs to Watchtower. Use when asked to add observability, tracing or OTLP export.
---

# Instrument a repository for Watchtower

1. Run `wtctl instrument plan --dir .` and read the plan. It names the detected language, the files it would write and the environment variables the app needs.
2. Review the plan with the user. Never invent an endpoint or a key: the OTLP endpoint and the ingestion key (`wti_...`) come from the user, as environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`). Never write a key into a file.
3. Run `wtctl instrument apply --dir .` to write the OpenTelemetry setup files.
4. To propose the change, run `wtctl instrument apply --dir . --open-pr --repo owner/name --api <url> --key <wtk_...> --project <id>`. It only works when the project owner turned on AI pull requests, it always opens a draft pull request from a new `watchtower/instrument-*` branch, and it refuses the repository's default branch.
5. Tell the user a human must review and merge the draft. Do not merge it yourself.
