from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "sealos-apps-audit" / "scripts" / "audit_sealos_apps.py"
FIXTURES = ROOT / "tests" / "fixtures"


def load_audit_module() -> object:
    spec = importlib.util.spec_from_file_location("audit_sealos_apps_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load audit module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


def run_audit_markdown(fixture: str) -> str:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(FIXTURES / fixture),
            "--deploy-dir",
            "deploy",
            "--app-type",
            "app",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout


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
        self.assertIn("PASS", levels["WORKFLOW_CHART_APP_VERSION_SYNC"])
        self.assertIn("N/A", levels["DOMESTIC_DB_GLOBAL_CONFIG"])

    def test_tag_release_stamps_chart_app_version(self) -> None:
        payload = run_audit("app-pass")
        levels = levels_by_rule(payload)
        self.assertIn("PASS", levels["WORKFLOW_CHART_APP_VERSION_SYNC"])

    def test_missing_chart_app_version_is_failure(self) -> None:
        payload = run_audit("app-oss-missing")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_CHART_APP_VERSION_SYNC"])

    def test_chart_app_version_without_ci_update_is_failure(self) -> None:
        payload = run_audit("app-oss-md5-missing")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_CHART_APP_VERSION_SYNC"])

    def test_tag_and_sha_sources_are_distinguished(self) -> None:
        audit = load_audit_module()
        self.assertEqual("tag", audit.workflow_trigger_profile('on:\n  push:\n    tags: ["v*"]'))
        self.assertEqual("sha", audit.workflow_trigger_profile("on:\n  push:\n    branches: [main]"))
        self.assertEqual((True, False), audit.workflow_source_kinds(
            "yq -i '.appVersion = strenv(GITHUB_REF_NAME)' deploy/charts/example-app/Chart.yaml",
            "",
        ))
        self.assertEqual((False, False), audit.workflow_source_kinds(
            "sed -i 's/appVersion:.*/appVersion: ${GITHUB_REF_NAME}/' deploy/charts/example-app/Chart.yaml",
            "",
        ))
        self.assertEqual((False, True), audit.workflow_source_kinds(
            "yq -i '.appVersion = (\"sha-\" + strenv(GITHUB_SHA))' deploy/charts/example-app/Chart.yaml",
            "",
        ))

    def test_app_version_evidence_rejects_decoys_and_unsafe_paths(self) -> None:
        audit = load_audit_module()
        root = Path("/repo")
        charts = [root / "deploy" / "charts" / "example-app"]
        self.assertEqual(frozenset(), audit.workflow_chart_targets(
            "working-directory: deploy/charts/example-app\n"
            "yq -i '.appVersion = strenv(GITHUB_REF_NAME)' /tmp/nope/Chart.yaml",
            root,
            charts,
        ))
        self.assertEqual(frozenset(), audit.workflow_chart_targets(
            "working-directory: deploy/charts/example-app\n"
            "yq -i '.appVersion = strenv(GITHUB_REF_NAME)' deploy\\charts\\example-app\\Chart.yaml",
            root,
            charts,
        ))
        self.assertEqual(frozenset(), audit.workflow_chart_targets(
            "yq -i '.appVersion = strenv(GITHUB_REF_NAME)' ${{ github.workspace }}deploy/charts/example-app/Chart.yaml",
            root,
            charts,
        ))
        self.assertFalse(audit.workflow_app_version_mutation(
            'echo "yq -i \' .appVersion = strenv(GITHUB_REF_NAME) \' deploy/charts/example-app/Chart.yaml"',
        ))
        self.assertFalse(audit.workflow_app_version_mutation(
            "sed 's/appVersion:.*/appVersion: fixed/' deploy/charts/example-app/Chart.yaml",
        ))

    def test_app_version_source_and_guard_parsers_are_conservative(self) -> None:
        audit = load_audit_module()
        command = "yq -i '.appVersion = strenv(VERSION)' deploy/charts/example-app/Chart.yaml"
        self.assertEqual((False, False), audit.workflow_source_kinds(command, "with:\n  env:\n    VERSION: ${{ github.ref_name }}"))
        self.assertEqual((False, False), audit.workflow_source_kinds(
            "yq -i \".appVersion = 0 | .buildTag = strenv(GITHUB_SHA)\" deploy/charts/example-app/Chart.yaml",
            "",
        ))
        self.assertEqual((False, False), audit.workflow_source_kinds(
            "yq -i \".appVersion = 'strenv(GITHUB_SHA)'\" deploy/charts/example-app/Chart.yaml",
            "",
        ))
        self.assertEqual("invalid", audit.workflow_guard_profile("", "github.ref_type == 'tag' || true", ""))
        self.assertEqual("invalid", audit.workflow_guard_profile("", "${{ false }}", ""))
        self.assertEqual("mixed", audit.workflow_guard_profile(
            "if [ \"$GITHUB_REF_TYPE\" = \"tag\" ]; then\n"
            " yq -i '.appVersion = strenv(GITHUB_REF_NAME)' Chart.yaml\n"
            "else\n"
            " yq -i '.appVersion = strenv(GITHUB_SHA)' Chart.yaml\nfi",
        ))

    def test_trigger_and_packaging_boundaries_ignore_text_markers(self) -> None:
        audit = load_audit_module()
        self.assertEqual("mixed", audit.workflow_trigger_profile("on: {push: {tags: ['v*']}}"))
        self.assertEqual("tag", audit.workflow_trigger_profile("on:\n  push:\n    tags-ignore: ['nightly']"))
        self.assertEqual("mixed", audit.workflow_trigger_profile("on:\n  mystery_event:"))
        step = audit.WorkflowStep(1, 2, "- run: echo 'sealos build deploy'", "echo 'sealos build deploy'", None, "")
        job = audit.WorkflowJob(Path("workflow.yaml"), "release", 1, 2, step.text, frozenset(), "", (step,))
        self.assertEqual([], audit.workflow_job_packaging_lines(job))
        script_step = audit.WorkflowStep(1, 2, "- run: ./ship.sh", "./ship.sh", None, "")
        script_job = audit.WorkflowJob(Path("workflow.yaml"), "release", 1, 2, script_step.text, frozenset(), "", (script_step,))
        self.assertEqual([1], audit.workflow_job_packaging_lines(script_job))
        suppressed_step = audit.WorkflowStep(1, 2, "- run: yq ... || true", "yq -i '.appVersion = strenv(GITHUB_REF_NAME)' Chart.yaml || true", None, "")
        suppressed_job = audit.WorkflowJob(Path("workflow.yaml"), "release", 1, 2, suppressed_step.text, frozenset(), "", (suppressed_step,))
        self.assertFalse(audit.workflow_path_is_safe(suppressed_job))

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

    def test_http_ingress_tls_must_be_conditional(self) -> None:
        payload = run_audit("app-http-ingress-unconditional")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["GLOBAL_HTTP_INGRESS_TLS"])

    def test_node_tls_requires_full_template_and_values_chain(self) -> None:
        payload = run_audit("app-node-tls-incomplete")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["NODE_TLS_REJECT_UNAUTHORIZED"])

    def test_legacy_ghcr_repository_image_names_are_forbidden(self) -> None:
        payload = run_audit("app-legacy-image-naming")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_IMAGE_SPLIT"])
        self.assertIn("FAIL", levels["WORKFLOW_IMAGE_NAMING"])

    def test_manifest_multi_arch_requires_runtime_and_cluster_context(self) -> None:
        payload = run_audit("app-multi-arch-context-missing")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_MULTI_ARCH"])

    def test_arch_variables_and_runner_matrix_cover_runtime_and_cluster(self) -> None:
        payload = run_audit("app-workflow-arch-vars")
        levels = levels_by_rule(payload)
        self.assertIn("PASS", levels["WORKFLOW_MULTI_ARCH"])

    def test_runtime_multi_arch_without_cluster_multi_arch_fails(self) -> None:
        payload = run_audit("app-multi-arch-runtime-only")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_MULTI_ARCH"])

    def test_oss_arrays_and_loop_variables_are_followed(self) -> None:
        payload = run_audit("app-oss-array-loop")
        levels = levels_by_rule(payload)
        self.assertIn("PASS", levels["WORKFLOW_OSS_SYNC"])

    def test_md5_generation_without_upload_fails(self) -> None:
        payload = run_audit("app-oss-md5-not-uploaded")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_OSS_SYNC"])

    def test_oss_evidence_in_comments_is_ignored(self) -> None:
        payload = run_audit("app-oss-comments-only")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["WORKFLOW_OSS_SYNC"])

    def test_basic_bad_fixture_fails_deploy_rules(self) -> None:
        payload = run_audit("app-fail")
        levels = levels_by_rule(payload)
        self.assertIn("FAIL", levels["DEPLOY_BUILD_FILE"])
        self.assertIn("FAIL", levels["HELM_ENTRYPOINT"])

    def test_missing_workflow_marks_workflow_summary_categories_failed(self) -> None:
        report = run_audit_markdown("app-fail")
        self.assertIn("| Runtime/Cluster 镜像分离 | FAIL | 缺少 .github/workflows 下的构建流水线。 |", report)
        self.assertIn("| 双架构 | FAIL | 缺少 .github/workflows 下的构建流水线。 |", report)
        self.assertIn("| OSS 推送 | FAIL | 缺少 .github/workflows 下的构建流水线。 |", report)


if __name__ == "__main__":
    unittest.main()
