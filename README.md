# sealos-apps skills

Public Codex skills for the `sealos-apps` organization.

## Skills

- `sealos-apps-audit`: read-only audit for Sealos app source repositories, covering deploy layout, Helm entrypoints, GitHub Actions release flow, public GHCR image naming, runtime/cluster multi-arch evidence, mandatory OSS sync, values loading, `global.http` HTTP-mode rendering, Node TLS, and optional database compatibility checks.

## Use

Run the audit script directly:

```bash
python3 skills/sealos-apps-audit/scripts/audit_sealos_apps.py \
  /path/to/app-repo \
  --deploy-dir deploy \
  --app-type app
```

Use JSON output for automation:

```bash
python3 skills/sealos-apps-audit/scripts/audit_sealos_apps.py \
  /path/to/app-repo \
  --deploy-dir deploy \
  --app-type app \
  --format json
```

The audit is read-only. It does not deploy, build, push images, or mutate clusters.

Rule details live in `skills/sealos-apps-audit/references/deploy-standard.zh.md`; human report requirements live in `skills/sealos-apps-audit/references/report-format.zh.md`.

## Validate This Repository

```bash
python3 -m py_compile skills/sealos-apps-audit/scripts/audit_sealos_apps.py
python3 -m unittest discover -s tests
python3 scripts/quick_validate.py skills/sealos-apps-audit
grep -v '^[[:space:]]*$' tests/public-boundary-denylist.txt > /tmp/public-boundary-denylist.txt
if grep -R -n -f /tmp/public-boundary-denylist.txt --exclude=public-boundary-denylist.txt --exclude-dir=.git .; then exit 1; fi
```
