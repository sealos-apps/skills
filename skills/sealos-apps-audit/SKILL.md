---
name: sealos-apps-audit
description: Read-only audit for public Sealos app source repositories. Use when Codex needs to check, review, validate, or report whether a Sealos app repository follows deploy/Helm/GitHub Actions release standards, including Dockerfile/Kubefile/Sealfile, charts, runtime and cluster image separation, public GHCR image naming, linux/amd64 and linux/arm64 runtime/cluster multi-arch evidence, mandatory OSS tar/md5 sync, apps/core values loading, tools.sh dependency, global.http HTTP/HTTPS behavior with local helm-template HTTP-mode validation, Node TLS based on cert-config CERT_MODE, KubeBlocks, and optional domestic database compatibility. Outputs findings and remediation only; never deploys, builds, pushes, or mutates clusters.
---

# Sealos Apps Audit

## Overview

Use this skill to audit Sealos app source repositories without modifying them. The audit script is deterministic and should be the default path for full repository checks.

## Workflow

1. Confirm the target repository root.
2. Confirm the deploy directory before running the script. Suggest `deploy` when the user has not provided one, but do not silently assume it.
3. Confirm the app type before running the script:
   - `app`: regular Sealos app, expected to load apps values.
   - `sealos-core`: SealosCore component, expected to load core values.
4. When the user asks about rule meaning or remediation details, read `references/deploy-standard.zh.md`.
5. When the user asks how the human report should be written, read `references/report-format.zh.md`.
6. Run the audit script:

   ```bash
   python3 <this-skill>/scripts/audit_sealos_apps.py <repo-root> --deploy-dir <deploy-dir> --app-type <app-or-sealos-core>
   ```

   Use repeated `--deploy-dir` flags for multiple deploy directories.

7. Use JSON only for automation or debugging:

   ```bash
   python3 <this-skill>/scripts/audit_sealos_apps.py <repo-root> --deploy-dir <deploy-dir> --app-type <app-or-sealos-core> --format json
   ```

8. Report the Markdown output using `总体结论`, `主要问题`, and `通过项依据`. Do not use the raw finding table as the main human report.

## Public Rule Notes

- `global.http` is checked across entrypoint arguments, chart values, template static scanning, and local `helm template` HTTP-mode rendering when Helm is available.
- Node TLS is required only when Node/frontend signals are detected, and must connect `CERT_MODE` to `platform.tlsRejectUnauthorized` and container `NODE_TLS_REJECT_UNAUTHORIZED`.
- GitHub Actions must avoid the legacy image names `ghcr.io/${{ github.repository }}` and `ghcr.io/${{ github.repository }}-cluster`; use the nested public GHCR package names documented in `references/deploy-standard.zh.md`.
- Multi-arch evidence must distinguish runtime and cluster artifacts when manifest/imagetools are used; buildx multi-platform evidence is accepted when amd64 and arm64 are both present.
- Human reports should include evidence, impact, remediation, and recheck guidance for each `FAIL` or `WARN`.

## Boundaries

- Do not edit the audited repository.
- Do not read or cite memory or previous session history in the audit result.
- Do not connect through SSH.
- Do not run `kubectl apply`, `helm upgrade`, Docker build, image push, registry write, or any cluster write action.
- Local static rendering or read-only inspection is allowed only when explicitly requested or already implemented by the script.
- OSS sync is a mandatory release rule.
- Domestic database compatibility is optional: report `N/A` when no relevant feature is detected.

## Resources

- `scripts/audit_sealos_apps.py`: read-only audit command.
- `references/deploy-standard.zh.md`: public Sealos app deploy standard.
- `references/report-format.zh.md`: expected human report format.
- `references/tools-functions.public.json`: public tools function capability catalog.
