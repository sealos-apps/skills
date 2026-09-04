# Sealos Apps Public Deploy Standard

The canonical public standard lives in `skills/sealos-apps-audit/references/deploy-standard.zh.md`.

Keep this document as the human-facing entry point for contributors. Update both this file and the skill reference when a public rule changes.

Current policy decisions:

- OSS sync is mandatory.
- Domestic database compatibility is optional and feature-triggered.
- Release workflows must stamp every chart's `appVersion`; tag runs use the exact release tag and non-tag runs may use the triggering commit SHA. `Chart.version` is independent.
- Public skills must not depend on private repository layouts or private release directories.
