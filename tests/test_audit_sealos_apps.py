from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "sealos-apps-audit" / "scripts" / "audit_sealos_apps.py"
FIXTURES = ROOT / "tests" / "fixtures"


def run_audit(fixture: str) -> dict[str, object]:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(FIXTURES / fixture),
            "--deploy-dir",
            "deploy",
            "--app-type",
            "app",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise AssertionError(result.stderr or result.stdout)
    return json.loads(result.stdout)


def levels_by_rule(payload: dict[str, object]) -> dict[str, list[str]]:
    levels: dict[str, list[str]] = {}
    for finding in payload["findings"]:
        levels.setdefault(finding["rule_id"], []).append(finding["level"])
    return levels


class SealosAppsAuditTest(unittest.TestCase):
    def test_app_pass_has_no_failures_and_oss_is_pass(self) -> None:
        payload = run_audit("app-pass")
        findings = payload["findings"]
        self.assertFalse([item for item in findings if item["level"] == "FAIL"])
        levels = levels_by_rule(payload)
        self.assertIn("PASS", levels["WORKFLOW_OSS_SYNC"])
        self.assertIn("N/A", levels["DOMESTIC_DB_GLOBAL_CONFIG"])

    def test_missing_oss_is_failure(self) -> None:
        payload = run_audit("app-oss-missing")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_OSS_SYNC"])

    def test_oss_tar_without_md5_upload_is_failure(self) -> None:
        payload = run_audit("app-oss-md5-missing")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_OSS_SYNC"])

    def test_domestic_database_is_feature_triggered(self) -> None:
        payload = run_audit("app-domestic-db-optional")
        levels = levels_by_rule(payload)
        self.assertIn("PASS", levels["DOMESTIC_DB_GLOBAL_CONFIG"])
        self.assertIn("PASS", levels["DATABASE_KUBEBLOCKS_VERSION"])

    def test_http_mode_hardcoded_url_is_failure(self) -> None:
        payload = run_audit("app-http-mode")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["GLOBAL_HTTP_HARDCODED_EXTERNAL_URL"])

    def test_basic_bad_fixture_fails_deploy_rules(self) -> None:
        payload = run_audit("app-fail")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["DEPLOY_BUILD_FILE"])
        self.assertIn("FAIL", levels["HELM_ENTRYPOINT"])


if __name__ == "__main__":
    unittest.main()
