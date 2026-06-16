#!/usr/bin/env python3
"""Read-only Sealos app source audit."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "PASS": 2, "N/A": 3}
TEXT_EXTENSIONS = {".bash", ".conf", ".dockerfile", ".env", ".js", ".json", ".jsx", ".mjs", ".sh", ".tpl", ".ts", ".tsx", ".txt", ".yaml", ".yml"}
IGNORED_DIRS = {".git", ".next", ".turbo", "build", "dist", "node_modules", "vendor"}
CATEGORY_RULES = [
    ("Deploy 结构", ["DEPLOY_DIR", "DEPLOY_BUILD_FILE", "DEPLOY_CHART", "CLUSTER_IMAGE_PACKAGING"]),
    ("Helm 部署", ["HELM_ENTRYPOINT", "HELM_CREATE_NAMESPACE", "HELM_NAMESPACE_TEMPLATE"]),
    ("Runtime/Cluster 镜像分离", ["WORKFLOW_EXISTS", "WORKFLOW_IMAGE_SPLIT", "WORKFLOW_IMAGE_NAMING", "WORKFLOW_IMAGE_CACHE"]),
    ("双架构", ["WORKFLOW_EXISTS", "WORKFLOW_MULTI_ARCH"]),
    ("OSS 推送", ["WORKFLOW_EXISTS", "WORKFLOW_OSS_SYNC"]),
    ("Values 读取策略", ["VALUES_CHART_CONTENT", "VALUES_STRATEGY"]),
    ("Tools 函数依赖", ["TOOLS_FUNCTION_DEPENDENCY"]),
    ("Node TLS", ["NODE_TLS_REJECT_UNAUTHORIZED"]),
    ("`global.http` HTTP 模式", ["GLOBAL_HTTP_"]),
    ("数据库", ["DATABASE_KUBEBLOCKS_VERSION"]),
    ("国产数据库", ["DOMESTIC_DB_GLOBAL_CONFIG"]),
]
SCRIPT_PATH = Path(__file__).resolve()
TOOLS_CATALOG_PATH = SCRIPT_PATH.parents[1] / "references" / "tools-functions.public.json"
TOOLS_PATH_PATTERN = re.compile(r"(?:^|\s)(?:\.|source)\s+['\"]?/root/\.sealos/cloud/scripts/tools\.sh['\"]?")
SHELL_FUNCTION_PATTERN = re.compile(r"(?m)^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?\s*\{")
NODE_SIGNAL_PATTERN = re.compile(
    r"NODE_TLS_REJECT_UNAUTHORIZED|"
    r"^\s*frontend\s*:|"
    r"\bfrontend\.(?:enabled|image|env|namespace|replicas)\b|"
    r"\bname:\s*[^\n]*frontend\b|"
    r"\bapp:\s*[^\n]*frontend\b|"
    r"\bnode_modules\b|"
    r"\bnpm\s+(?:ci|install|run|start|build)\b|"
    r"\bpnpm\s+(?:install|run|start|build)\b|"
    r"\byarn\s+(?:install|run|start|build)\b|"
    r"\bnext\s+(?:start|build)\b",
    re.IGNORECASE | re.MULTILINE,
)
SIZE_PATTERN = re.compile(
    r"docker\s+image\s+inspect[\s\S]{0,200}\.Size|"
    r"docker\s+images\b|"
    r"docker\s+image\s+ls\b|"
    r"docker\s+buildx\s+imagetools\s+inspect\b|"
    r"du\s+(?:-[A-Za-z]*h[A-Za-z]*|--human-readable)[^\n]*(?:release-assets|\.tar\.gz)|"
    r"ls\s+-[A-Za-z]*h[A-Za-z]*[^\n]*(?:release-assets|\.tar\.gz)|"
    r"stat\s+(?:-c%s|-f%z|--format=%s)[^\n]*(?:release-assets|\.tar\.gz)|"
    r"wc\s+-c[^\n]*(?:release-assets|\.tar\.gz)",
    re.IGNORECASE,
)
DOMESTIC_DB_PATTERN = re.compile(
    r"databaseMongodbURI|databasePostgresqlURL|global\.featureConfigs\.database\.components|components:\s*(?:\n|\r\n)\s+(?:postgresql|mongodb):|cockroachdb|opengauss|kingbase|dameng|gaussdb|tidb|oceanbase|polardb",
    re.IGNORECASE,
)
TOOLS_CAPABILITY_RULES = [
    ("ConfigMap 读写", {"get_cm_value", "set_cm_value", "ensure_cm_value", "fetch_configmap_data_key", "fetch_configmap_field"}, [r"\bkubectl\s+get\s+configmap\b", r"\bkubectl\s+patch\s+configmap\b", r"\bkubectl\s+-n\s+[^;\n]+create\s+configmap\b", r"\bjsonpath=\{\.data\."], "FAIL"),
    ("runtime global.yaml 读取", {"read_yaml_file_path"}, [r"/root/\.sealos/cloud/values/global\.yaml", r"\bglobal\.featureConfigs\b", r"\bglobal\.http\b", r"\byq\s+e\b"], "FAIL"),
    ("global.http URL/协议/端口", {"bool_is_true", "global_http_disable_https", "global_http_effective_port", "global_http_external_url", "global_http_port_suffix", "global_http_scheme"}, [r"\bdisableHttps\b", r"\bSEALOS_DISABLE_HTTPS\b", r"\bSEALOS_HTTP_PORT\b", r"\bSEALOS_CLOUD_PORT\b", r"\bhttps\|acme\b", r"\bhttp://|\bhttps://", r":443\b"], "FAIL"),
    ("证书模式/Node TLS", {"read_cert_tls_reject_unauthorized"}, [r"\bCERT_MODE\b", r"\bcert-config\b", r"\bNODE_TLS_REJECT_UNAUTHORIZED\b"], "FAIL"),
    ("平台通用配置读取", {"read_jwt_internal", "read_prometheus_url", "read_account_service_name"}, [r"\bjwtInternal\b", r"\bACCOUNT_API_JWT_SECRET\b", r"\bprometheus\b", r"\baccount-manager-env\b"], "WARN"),
    ("Feature Flag", {"is_feature_enabled", "init_feature_flags"}, [r"\benabledFeatures\b", r"\bfeatureConfigs\.enabledFeatures\b"], "WARN"),
]


@dataclass
class Finding:
    rule_id: str
    level: str
    message: str
    remediation: str
    path: str | None = None
    line: int | None = None


@dataclass
class AuditResult:
    deploy_dir: Path
    findings: list[Finding]


class Checker:
    def __init__(self, root: Path, deploy_dir: Path, app_type: str) -> None:
        self.root = root.resolve()
        self.deploy_dir = deploy_dir.resolve()
        self.app_type = app_type
        self.findings: list[Finding] = []
        self.workflow_dir = self.root / ".github" / "workflows"
        self.workflow_files: list[Path] = []
        self.chart_dirs: list[Path] = []
        self.entrypoint_files: list[Path] = []
        self.build_file: Path | None = None
        self.tools_functions = load_tools_catalog()

    def run(self) -> list[Finding]:
        self.discover()
        self.check_deploy_structure()
        self.check_helm_entrypoint()
        self.check_namespace_templates()
        self.check_cluster_image_packaging()
        self.check_workflows()
        self.check_values_strategy()
        self.check_tools_dependency()
        self.check_global_http()
        self.check_node_tls()
        self.check_database()
        return sorted(self.findings, key=lambda item: (SEVERITY_ORDER[item.level], item.rule_id, item.path or "", item.line or 0))

    def discover(self) -> None:
        if self.deploy_dir.is_dir():
            for name in ["Kubefile", "Sealfile", "Dockerfile"]:
                candidate = self.deploy_dir / name
                if candidate.is_file():
                    self.build_file = candidate
                    break
            charts_root = self.deploy_dir / "charts"
            if charts_root.is_dir():
                self.chart_dirs = sorted(path.parent for path in charts_root.glob("*/Chart.yaml"))
            self.entrypoint_files = sorted(
                path
                for path in self.deploy_dir.rglob("*")
                if path.is_file() and path.suffix in {".sh", ".bash"} and ("entrypoint" in path.name.lower() or "install" in path.name.lower())
            )
        if self.workflow_dir.is_dir():
            self.workflow_files = sorted(path for path in self.workflow_dir.glob("*") if path.is_file() and path.suffix in {".yaml", ".yml"})

    def add(self, rule_id: str, level: str, message: str, remediation: str, path: Path | None = None, line: int | None = None) -> None:
        self.findings.append(Finding(rule_id, level, message, remediation, str(path.resolve()) if path else None, line))

    def rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root))
        except ValueError:
            return str(path)

    def check_deploy_structure(self) -> None:
        if self.deploy_dir.is_dir():
            self.add("DEPLOY_DIR", "PASS", "存在用户确认的 deploy 检测目录。", "无需整改。", self.deploy_dir)
        else:
            self.add("DEPLOY_DIR", "FAIL", "缺少用户确认的 deploy 检测目录。", "新增 deploy 目录，或重新传入正确的 --deploy-dir。", self.deploy_dir)
            return
        if self.build_file:
            self.add("DEPLOY_BUILD_FILE", "PASS", f"存在 {self.build_file.name}。", "无需整改。", self.build_file, 1)
        else:
            self.add("DEPLOY_BUILD_FILE", "FAIL", "缺少 Dockerfile、Kubefile 或 Sealfile。", "在 deploy 目录提供 Dockerfile、Kubefile 或 Sealfile 构建 cluster image。", self.deploy_dir)
        if self.chart_dirs:
            self.add("DEPLOY_CHART", "PASS", f"发现 {len(self.chart_dirs)} 个 Helm chart。", "无需整改。", self.chart_dirs[0] / "Chart.yaml", 1)
        else:
            self.add("DEPLOY_CHART", "FAIL", "缺少 charts/<name>/Chart.yaml。", "在 deploy/charts/<name>/ 下提供 Helm chart。", self.deploy_dir / "charts")
        for chart in self.chart_dirs:
            expected = f"{chart.name}-values.yaml"
            missing = []
            if not (chart / "values.yaml").is_file():
                missing.append("values.yaml")
            if not (chart / "templates").is_dir():
                missing.append("templates/")
            if not (chart / expected).is_file():
                missing.append(expected)
            if missing:
                self.add("VALUES_CHART_CONTENT", "FAIL", f"{self.rel(chart)} 缺少 {', '.join(missing)}。", f"补齐 values.yaml、templates/ 和 {expected}。", chart)
            else:
                self.add("VALUES_CHART_CONTENT", "PASS", f"{self.rel(chart)} chart values 内容完整。", "无需整改。", chart / "Chart.yaml", 1)

    def check_helm_entrypoint(self) -> None:
        if not self.entrypoint_files:
            self.add("HELM_ENTRYPOINT", "FAIL", "未发现 deploy 下的 entrypoint/install shell 脚本。", "提供 entrypoint 或 install 脚本，并在其中使用 helm upgrade -i。", self.deploy_dir)
            self.add("HELM_CREATE_NAMESPACE", "FAIL", "无法确认 Helm 部署包含 --create-namespace。", "在 helm upgrade -i 命令中加入 --create-namespace。", self.deploy_dir)
            return
        helm_hits = search_paths(self.entrypoint_files, re.compile(r"\bhelm\s+upgrade\s+-i\b|\bhelm\s+upgrade\s+--install\b"))
        namespace_hits = search_paths(self.entrypoint_files, re.compile(r"--create-namespace"))
        if helm_hits:
            path, line, _ = helm_hits[0]
            self.add("HELM_ENTRYPOINT", "PASS", "部署入口使用 helm upgrade install 语义。", "无需整改。", path, line)
        else:
            self.add("HELM_ENTRYPOINT", "FAIL", "entrypoint/install 脚本未使用 helm upgrade -i 或 helm upgrade --install。", "将主部署入口改为 helm upgrade -i <release> -n <namespace> --create-namespace <chart>。", self.entrypoint_files[0])
        if namespace_hits:
            path, line, _ = namespace_hits[0]
            self.add("HELM_CREATE_NAMESPACE", "PASS", "Helm 部署包含 --create-namespace。", "无需整改。", path, line)
        else:
            self.add("HELM_CREATE_NAMESPACE", "FAIL", "Helm 部署缺少 --create-namespace。", "在 helm upgrade -i 命令中加入 --create-namespace。", self.entrypoint_files[0])

    def check_namespace_templates(self) -> None:
        templates = list(self.template_files())
        if not templates:
            self.add("HELM_NAMESPACE_TEMPLATE", "N/A", "未发现 Helm templates 目录，跳过 Namespace 模板检查。", "无需整改；Deploy 结构规则会单独报告缺失。")
            return
        hits = search_paths(templates, re.compile(r"(?m)^\s*kind\s*:\s*Namespace\s*$"))
        if hits:
            path, line, _ = hits[0]
            self.add("HELM_NAMESPACE_TEMPLATE", "FAIL", "Helm chart 模板自行创建 Namespace。", "删除 Namespace 模板，统一通过 helm upgrade --create-namespace 创建命名空间。", path, line)
        else:
            self.add("HELM_NAMESPACE_TEMPLATE", "PASS", "Helm chart 模板未自行创建 Namespace。", "无需整改。", templates[0], 1)

    def check_cluster_image_packaging(self) -> None:
        if not self.build_file:
            return
        text = read_text(self.build_file)
        copies_all = bool(re.search(r"(?m)^\s*COPY\s+\.\s+\.", text, re.IGNORECASE))
        checks = {
            "registry": re.search(r"\bCOPY\b.*\bregistry\b", text, re.IGNORECASE) or (copies_all and (self.deploy_dir / "registry").is_dir()),
            "charts": re.search(r"\bCOPY\b.*\bcharts\b", text, re.IGNORECASE) or (copies_all and (self.deploy_dir / "charts").is_dir()),
            "entrypoint/install": re.search(r"\bCOPY\b.*(?:entrypoint|install)|CMD\s+\[.*(?:entrypoint|install)|ENTRYPOINT\s+\[.*(?:entrypoint|install)", text, re.IGNORECASE | re.DOTALL)
            or (copies_all and bool(self.entrypoint_files)),
        }
        missing = [name for name, ok in checks.items() if not ok]
        if missing:
            self.add("CLUSTER_IMAGE_PACKAGING", "FAIL", f"{self.build_file.name} 未明确打包 {', '.join(missing)}。", "确保 cluster image 构建文件打包 registry、charts 和 entrypoint/install 脚本。", self.build_file, 1)
        else:
            self.add("CLUSTER_IMAGE_PACKAGING", "PASS", f"{self.build_file.name} 打包 registry、charts 和安装入口。", "无需整改。", self.build_file, 1)

    def check_workflows(self) -> None:
        if not self.workflow_files:
            self.add("WORKFLOW_EXISTS", "FAIL", "缺少 .github/workflows 下的构建流水线。", "新增 GitHub Actions 流水线，覆盖 runtime image、cluster image、manifest、tar/md5 和 OSS 同步。", self.workflow_dir)
            return
        combined = "\n".join(read_text(path) for path in self.workflow_files)

        split_status, split_message, split_remediation, split_path, split_line = self.workflow_image_split_result(combined)
        if split_status == "PASS":
            self.add("WORKFLOW_IMAGE_SPLIT", "PASS", split_message, "无需整改。", split_path, split_line)
        else:
            self.add("WORKFLOW_IMAGE_SPLIT", "FAIL", split_message, split_remediation, split_path, split_line)

        naming_status, naming_message, naming_remediation, naming_path, naming_line = self.workflow_image_naming_result(combined)
        self.add("WORKFLOW_IMAGE_NAMING", naming_status, naming_message, naming_remediation, naming_path, naming_line)

        has_amd64 = "linux/amd64" in combined or re.search(r"\barch:\s*amd64\b|\[\s*amd64", combined)
        has_arm64 = "linux/arm64" in combined or re.search(r"\barch:\s*arm64\b|arm64\s*\]", combined)
        runtime_manifest_hits, cluster_manifest_hits = self.workflow_artifact_context_hits(
            re.compile(r"docker\s+(?:buildx\s+imagetools|manifest)\s+create", re.IGNORECASE)
        )
        runtime_buildx_hits, cluster_buildx_hits = self.workflow_artifact_context_hits(
            re.compile(r"docker/build-push-action@|docker\s+buildx\s+build", re.IGNORECASE),
            require_both_platforms=True,
        )
        runtime_multi_arch_hits = runtime_manifest_hits + runtime_buildx_hits
        cluster_multi_arch_hits = cluster_manifest_hits + cluster_buildx_hits
        if has_amd64 and has_arm64 and runtime_multi_arch_hits and cluster_multi_arch_hits:
            manifest_multi_arch = bool(runtime_manifest_hits and cluster_manifest_hits)
            buildx_multi_arch = bool(runtime_buildx_hits and cluster_buildx_hits)
            evidence_hits = runtime_manifest_hits + cluster_manifest_hits if manifest_multi_arch else runtime_buildx_hits + cluster_buildx_hits
            if manifest_multi_arch:
                evidence = "manifest"
            elif buildx_multi_arch:
                evidence = "buildx"
            else:
                evidence = "manifest/buildx"
            path, line, _ = evidence_hits[0]
            self.add("WORKFLOW_MULTI_ARCH", "PASS", f"双架构检查通过：检测到 amd64/arm64，并通过 {evidence} 分别覆盖 runtime 与 cluster 多架构产物。", "无需整改。", path, line)
        else:
            self.add("WORKFLOW_MULTI_ARCH", "FAIL", "未确认双架构产物：需要 amd64/arm64，并分别覆盖 runtime 与 cluster 多架构发布。", "增加 linux/amd64、linux/arm64 构建，并使用 docker manifest/buildx imagetools 或 docker buildx 多平台构建发布 runtime 与 cluster 产物。", self.workflow_files[0])

        registry_hits = search_paths(
            self.workflow_files,
            re.compile(
                r"sealos\s+registry\s+save[\s\S]{0,320}--registry-dir(?:=|\s+)\"?registry\"?[\s\S]{0,320}--arch|"
                r"sealos\s+registry\s+save[\s\S]{0,320}--arch[\s\S]{0,320}--registry-dir(?:=|\s+)\"?registry\"?|"
                r"\bsreg\s+save\b",
                re.IGNORECASE,
            ),
        )
        sealos_build_hits = search_paths(self.workflow_files, re.compile(r"\bsealos\s+build\b", re.IGNORECASE))
        if registry_hits:
            path, line, _ = registry_hits[0]
            self.add("WORKFLOW_IMAGE_CACHE", "PASS", "cluster image 构建前执行 sealos registry save 或 sreg save。", "无需整改。", path, line)
        elif sealos_build_hits:
            path, line, _ = sealos_build_hits[0]
            self.add("WORKFLOW_IMAGE_CACHE", "PASS", "workflow 使用 sealos build 构建 cluster image，可作为镜像缓存/集群镜像构建入口。", "无需整改。", path, line)
        else:
            self.add("WORKFLOW_IMAGE_CACHE", "FAIL", "流水线缺少 cluster image 镜像缓存入口。", "在 cluster image 构建前执行 sealos build、sealos registry save --registry-dir=registry --arch <arch> . 或 sreg save。", self.workflow_files[0])
        size_hit = first_match(self.workflow_files, SIZE_PATTERN)
        if size_hit[0]:
            self.add("WORKFLOW_IMAGE_SIZE_REPORT", "PASS", "流水线输出镜像或 tar 包大小信息。", "无需整改。", size_hit[0], size_hit[1])
        else:
            self.add("WORKFLOW_IMAGE_SIZE_REPORT", "FAIL", "流水线缺少镜像/产物大小输出步骤。", "增加 docker image inspect、docker images、docker buildx imagetools inspect、du -h、ls -lh、stat 或 wc -c 等大小输出。", self.workflow_files[0])
        oss_tar_upload = re.search(r"\bossutil(?:64)?\s+cp\b[^\n]*\.tar(?:\.gz)?[^\n]*oss://", combined, re.IGNORECASE)
        oss_md5_upload = re.search(r"\bossutil(?:64)?\s+cp\b[^\n]*\.md5[^\n]*oss://", combined, re.IGNORECASE)
        md5_generated = re.search(r"\bmd5sum\b[^\n]*\.tar(?:\.gz)?[^\n]*(?:>|tee)[^\n]*\.md5|\.tar(?:\.gz)?\.md5", combined, re.IGNORECASE)
        oss_ok = bool(oss_tar_upload and oss_md5_upload and md5_generated)
        if oss_ok:
            path, line = first_match(self.workflow_files, re.compile(r"\bossutil(?:64)?\s+cp\b", re.IGNORECASE))
            self.add("WORKFLOW_OSS_SYNC", "PASS", "流水线包含 cluster tar/tar.gz、md5 和 OSS 推送。", "无需整改。", path, line)
        else:
            missing = []
            if not oss_tar_upload:
                missing.append("tar/tar.gz OSS 上传")
            if not md5_generated:
                missing.append("md5 生成")
            if not oss_md5_upload:
                missing.append(".md5 OSS 上传")
            self.add("WORKFLOW_OSS_SYNC", "FAIL", "流水线未完整包含强制 OSS 同步：" + "、".join(missing) + "。", "导出 cluster tar/tar.gz、生成 md5，并使用 ossutil cp 分别上传 tar/tar.gz 和 .md5 到 OSS。", self.workflow_files[0])

    def workflow_image_split_result(self, combined: str) -> tuple[str, str, str, Path, int | None]:
        recommended_runtime = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}/\$\{\{\s*github\.repository\s*\}\}(?!-cluster)", combined)
        recommended_cluster = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}/\$\{\{\s*github\.repository\s*\}\}-cluster", combined)
        legacy_runtime = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}(?!-cluster)(?=[:\"'@\s]|$)", combined)
        legacy_cluster = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}-cluster", combined)

        if legacy_runtime or legacy_cluster:
            path, line = self.workflow_match_location(legacy_cluster or legacy_runtime)
            return (
                "FAIL",
                "流水线使用已禁止的兼容镜像命名格式 ghcr.io/${{ github.repository }} 或 ghcr.io/${{ github.repository }}-cluster。",
                "改为推荐格式：runtime 使用 ghcr.io/${{ github.repository }}/${{ github.repository }}，cluster 使用 ghcr.io/${{ github.repository }}/${{ github.repository }}-cluster。",
                path,
                line,
            )
        if recommended_runtime and recommended_cluster:
            path, line = self.workflow_match_location(recommended_cluster)
            return (
                "PASS",
                "流水线区分 runtime image 与 cluster image，且使用推荐镜像命名格式 ghcr.io/${{ github.repository }}/${{ github.repository }} 与 -cluster。",
                "无需整改。",
                path,
                line,
            )

        runtime_image = re.search(r"RUNTIME_IMAGE|GHCR_RUNTIME_IMAGE|runtime image|frontend|backend", combined, re.IGNORECASE)
        cluster_image = re.search(r"ghcr\.io/[^\s\"']+-cluster|SEALOS_IMAGE|GHCR_SEALOS_IMAGE|CLUSTER_IMAGE|cluster image|sealos image|-cluster", combined, re.IGNORECASE)
        if runtime_image and cluster_image:
            path, line = self.workflow_match_location(cluster_image)
            return (
                "PASS",
                "流水线区分 runtime image 与 cluster image。",
                "无需整改。",
                path,
                line,
            )
        path, line = self.workflow_match_location(cluster_image or runtime_image)
        return (
            "FAIL",
            "流水线未明确区分 runtime image 与 cluster image。",
            "分别定义并构建 runtime image 与 cluster image；推荐使用 ghcr.io/${{ github.repository }}/${{ github.repository }} 与 ghcr.io/${{ github.repository }}/${{ github.repository }}-cluster。",
            path,
            line,
        )

    def workflow_image_naming_result(self, combined: str) -> tuple[str, str, str, Path, int | None]:
        recommended_runtime = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}/\$\{\{\s*github\.repository\s*\}\}(?!-cluster)", combined)
        recommended_cluster = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}/\$\{\{\s*github\.repository\s*\}\}-cluster", combined)
        legacy_runtime = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}(?!-cluster)(?=[:\"'@\s]|$)", combined)
        legacy_cluster = re.search(r"ghcr\.io/\$\{\{\s*github\.repository\s*\}\}-cluster", combined)
        if legacy_runtime or legacy_cluster:
            path, line = self.workflow_match_location(legacy_cluster or legacy_runtime)
            return (
                "FAIL",
                "流水线使用禁止的 GHCR 镜像命名格式 ghcr.io/${{ github.repository }} 或 ghcr.io/${{ github.repository }}-cluster。",
                "改为 ghcr.io/${{ github.repository }}/${{ github.repository }} 和 ghcr.io/${{ github.repository }}/${{ github.repository }}-cluster，保持 runtime 与 cluster package 可区分。",
                path,
                line,
            )
        if recommended_runtime and recommended_cluster:
            path, line = self.workflow_match_location(recommended_cluster)
            return (
                "PASS",
                "流水线使用推荐的公开 GHCR 镜像命名格式。",
                "无需整改。",
                path,
                line,
            )
        return (
            "PASS",
            "未发现禁止的 GHCR 镜像命名格式。",
            "如使用 github.repository 动态命名，建议采用 ghcr.io/${{ github.repository }}/${{ github.repository }} 和 -cluster 嵌套格式。",
            self.workflow_files[0],
            None,
        )

    def workflow_match_location(self, match: re.Match[str] | None) -> tuple[Path, int | None]:
        if not match:
            return self.workflow_files[0], None
        path, line = match_location(self.workflow_files, match)
        return path or self.workflow_files[0], line

    def workflow_artifact_context_hits(
        self,
        create_pattern: re.Pattern[str],
        require_both_platforms: bool = False,
    ) -> tuple[list[tuple[Path, int, str]], list[tuple[Path, int, str]]]:
        runtime_hits = []
        cluster_hits = []
        runtime_pattern = re.compile(r"RUNTIME|runtime|backend|frontend|ghcr\.io/[^\s\"']+(?<!-cluster)(?=[:@\s]|$)", re.IGNORECASE)
        cluster_pattern = re.compile(r"SEALOS|CLUSTER|cluster|-cluster", re.IGNORECASE)
        for path in self.workflow_files:
            lines = read_text(path).splitlines()
            for index, line in enumerate(lines, start=1):
                if not create_pattern.search(line):
                    continue
                command_context = workflow_command_context(lines, index - 1)
                if require_both_platforms and not context_has_both_platforms(command_context):
                    command_context = ""
                if command_context and cluster_pattern.search(command_context):
                    cluster_hits.append((path, index, command_context))
                    continue
                if command_context and runtime_pattern.search(command_context):
                    runtime_hits.append((path, index, command_context))
                    continue

                step_context = workflow_step_context(lines, index - 1)
                if require_both_platforms and not context_has_both_platforms(step_context):
                    continue
                has_cluster = bool(cluster_pattern.search(step_context))
                has_runtime = bool(runtime_pattern.search(step_context))
                if has_cluster and not has_runtime:
                    cluster_hits.append((path, index, step_context))
                elif has_runtime and not has_cluster:
                    runtime_hits.append((path, index, step_context))
        return runtime_hits, cluster_hits

    def check_values_strategy(self) -> None:
        if not self.entrypoint_files:
            self.add("VALUES_STRATEGY", "FAIL", "未发现 entrypoint/install，无法确认 Values 读取策略。", "提供 entrypoint 或 install 脚本，并按 app 类型加载 apps/core values。", self.deploy_dir)
            return
        combined = "\n".join(read_text(path) for path in self.entrypoint_files)
        chart_names = [chart.name for chart in self.chart_dirs]
        scope = "core" if self.app_type == "sealos-core" else "apps"
        state = self.values_state(combined, scope, chart_names)
        hits = search_paths(self.entrypoint_files, re.compile(rf"/root/\.sealos/cloud/values/{scope}|values/{scope}"))
        path, line = (hits[0][0], hits[0][1]) if hits else (self.entrypoint_files[0], None)
        if state["missing"]:
            self.add("VALUES_STRATEGY", "FAIL", f"未满足 {scope} Values 读取策略：缺少 {', '.join(state['missing'])}。", f"在 entrypoint 中检查 /root/.sealos/cloud/values/{scope}/<name>/；缺失时输出 WARN 并复制默认 *-values.yaml；Helm 只稳定读取该目录内所有 *-values.yaml。", path, line)
        elif not state["warn"]:
            self.add("VALUES_STRATEGY", "WARN", "Values 策略通过，但缺少默认 values 复制时的 WARN 提示。", "复制默认 values 前输出 WARN，说明 cloud values 目录缺失并正在写入默认值。", path, line)
        else:
            self.add("VALUES_STRATEGY", "PASS", f"Values 策略通过：按 {scope} scope 读取 cloud values。", "无需整改。", path, line)

    def values_state(self, text: str, scope: str, chart_names: list[str]) -> dict[str, object]:
        names = "|".join(re.escape(name) for name in chart_names) or r"[A-Za-z0-9_.-]+"
        base = rf"/root/\.sealos/cloud/values/{scope}|values/{scope}"
        named_dir = bool(re.search(rf"(?:{base})/(?:{names}|\$\{{?[A-Za-z_][A-Za-z0-9_]*\}}?)(?:/|['\"\s]|$)", text, re.IGNORECASE))
        values_file = r"\*-values\.ya?ml|[A-Za-z_][A-Za-z0-9_]*VALUES[A-Za-z0-9_]*|\$\{?[A-Za-z_][A-Za-z0-9_]*VALUES[A-Za-z0-9_]*\}?"
        values_dir = rf"{base}|VALUES_DIR|values_dir|APP_VALUES_DIR|app_values_dir|CORE_VALUES_DIR|core_values_dir|\$\{{?VALUES_DIR\}}?|\$\{{?APP_VALUES_DIR\}}?|\$\{{?CORE_VALUES_DIR\}}?"
        copy_default = bool(re.search(rf"\b(?:cp|install|rsync)\b[\s\S]{{0,320}}(?:{values_file})[\s\S]{{0,320}}(?:{values_dir})|\b(?:cp|install|rsync)\b[\s\S]{{0,320}}(?:{values_dir})[\s\S]{{0,320}}(?:{values_file})", text, re.IGNORECASE))
        values_glob = bool(re.search(rf"\*-values\.ya?ml|find\s+[\s\S]{{0,240}}values/{scope}|for\s+[\s\S]{{0,240}}values/{scope}", text))
        stable = "sort" in text
        helm_arg = bool(
            re.search(
                rf"(?:-f|--values)\s+[\s\S]{{0,240}}(?:values/{scope}|VALUES_DIR|values_dir|VALUES_FILES|values_files)|"
                r"values_args\s*\+=\s*\([^)]*(?:-f|--values)|\$\{?values_args\[@\]\}?",
                text,
                re.IGNORECASE,
            )
        )
        direct_chart = bool(re.search(r"(?:-f|--values)\s+(?:['\"])?(?:\.{0,2}/)?(?:deploy/)?charts?/[\S'\"]*-values\.ya?ml", text, re.IGNORECASE))
        warn = bool(re.search(rf"(?:warn|WARN|warning|WARNING)[\s\S]{{0,240}}(?:{base})|(?:{base})[\s\S]{{0,240}}(?:warn|WARN|warning|WARNING)", text))
        missing = []
        if not named_dir:
            missing.append(f"/root/.sealos/cloud/values/{scope}/<name>/")
        if not copy_default:
            missing.append("缺失时复制默认 *-values.yaml")
        if not values_glob:
            missing.append("*-values.yaml 遍历")
        if not stable:
            missing.append("稳定排序")
        if not helm_arg:
            missing.append("Helm -f/--values 从 cloud values 目录追加")
        if direct_chart:
            missing.append("不得直接读取 chart 默认 *-values.yaml")
        return {"missing": missing, "warn": warn}

    def check_tools_dependency(self) -> None:
        if not self.entrypoint_files:
            self.add("TOOLS_FUNCTION_DEPENDENCY", "N/A", "未发现 entrypoint/install，跳过 tools 函数依赖检查。", "无需整改。")
            return
        text = "\n".join(read_text(path) for path in self.entrypoint_files)
        has_tools = bool(TOOLS_PATH_PATTERN.search(text))
        defined = set(SHELL_FUNCTION_PATTERN.findall(text))
        duplicated = sorted(defined & self.tools_functions)
        hits = []
        for name, functions, signals, level in TOOLS_CAPABILITY_RULES:
            if not (functions & self.tools_functions):
                continue
            if any(re.search(signal, text, re.IGNORECASE) for signal in signals):
                hits.append((name, sorted(functions & self.tools_functions), level))
        if duplicated:
            path, line = first_match(self.entrypoint_files, re.compile("|".join(re.escape(name) for name in duplicated)))
            self.add("TOOLS_FUNCTION_DEPENDENCY", "FAIL", "entrypoint/install 自定义了公共 tools.sh 已提供的函数：" + ", ".join(duplicated) + "。", "删除自定义实现，source /root/.sealos/cloud/scripts/tools.sh，并直接调用平台函数。", path, line)
        elif hits and not has_tools:
            level = "FAIL" if any(hit[2] == "FAIL" for hit in hits) else "WARN"
            functions = sorted({function for _, funcs, _ in hits for function in funcs})
            self.add("TOOLS_FUNCTION_DEPENDENCY", level, "entrypoint/install 使用平台配置能力但未依赖 tools.sh：" + ", ".join(hit[0] for hit in hits) + "。", "在入口脚本开头 source /root/.sealos/cloud/scripts/tools.sh，并改用平台函数：" + ", ".join(functions) + "。", self.entrypoint_files[0])
        elif hits:
            self.add("TOOLS_FUNCTION_DEPENDENCY", "PASS", "entrypoint/install 依赖 tools.sh 处理平台配置能力。", "无需整改。", self.entrypoint_files[0])
        else:
            self.add("TOOLS_FUNCTION_DEPENDENCY", "N/A", "entrypoint/install 未使用 tools.sh 覆盖的平台配置能力，规则未触发。", "无需整改。")

    def check_global_http(self) -> None:
        value_names = ["cloudDomain", "cloudPort", "httpPort", "disableHttps", "certSecretName"]
        script_text = "\n".join(read_text(path) for path in self.entrypoint_files)
        values_text = "\n".join(read_text(chart / "values.yaml") for chart in self.chart_dirs if (chart / "values.yaml").is_file())
        helper_http = self.uses_global_http_helpers(script_text)

        missing_script = [] if helper_http else [name for name in value_names if name not in script_text]
        missing_values = [] if helper_http else [name for name in value_names if re.search(rf"(?m)^\s*{re.escape(name)}\s*:", values_text) is None]

        if missing_script:
            self.add("GLOBAL_HTTP_ENTRYPOINT", "FAIL", "entrypoint 未读取/传入 global.http 相关参数：" + ", ".join(missing_script) + "。", "从 sealos-config 读取 cloudDomain、cloudPort、httpPort、disableHttps、certSecretName，并通过 --set-string 传给 Helm；也可以使用 global_http_disable_https/global_http_external_url helper。", self.entrypoint_files[0] if self.entrypoint_files else self.deploy_dir)
        else:
            hits = search_paths(self.entrypoint_files, re.compile(r"global_http_disable_https|global_http_external_url|disableHttps|certSecretName|httpPort"))
            path, line = (hits[0][0], hits[0][1]) if hits else (self.entrypoint_files[0] if self.entrypoint_files else self.deploy_dir, None)
            message = "entrypoint 通过全局 HTTP helper 读取并传递 HTTP/HTTPS 参数。" if helper_http else "entrypoint 读取 global.http 所需参数。"
            self.add("GLOBAL_HTTP_ENTRYPOINT", "PASS", message, "无需整改。", path, line)

        if missing_values:
            self.add("GLOBAL_HTTP_VALUES", "FAIL", "values.yaml 未声明 global.http 所需参数：" + ", ".join(missing_values) + "。", "在 chart values 中提供 cloudDomain、cloudPort、httpPort、disableHttps、certSecretName 默认值。", self.chart_dirs[0] / "values.yaml" if self.chart_dirs else self.deploy_dir)
        else:
            path = self.chart_dirs[0] / "values.yaml" if self.chart_dirs else self.deploy_dir
            message = "entrypoint 使用全局 HTTP helper，chart 通过 helper 结果/Helm override 接收 HTTP/HTTPS 模式。" if helper_http else "values.yaml 声明 global.http 所需参数。"
            self.add("GLOBAL_HTTP_VALUES", "PASS", message, "无需整改。", path, 1 if path.is_file() else None)

        hardcoded = []
        for path in self.template_files():
            for line_no, line in iter_lines(path):
                if "https://" in line or re.search(r":443\b", line):
                    if line_is_helper_or_example(self.rel(path), line):
                        continue
                    if self.is_external_template_line(line):
                        hardcoded.append((path, line_no))
        if hardcoded:
            path, line = hardcoded[0]
            self.add("GLOBAL_HTTP_HARDCODED_EXTERNAL_URL", "FAIL", f"模板存在硬编码外部 https:// 或 :443，共 {len(hardcoded)} 处。", "使用协议/端口 helper，根据 disableHttps 输出 http:// 或 https://，HTTP 模式下删除 :443 或改为 :80。", path, line)
        else:
            self.add("GLOBAL_HTTP_HARDCODED_EXTERNAL_URL", "PASS", "未发现模板硬编码外部 https:// 或 :443。", "无需整改。", self.chart_dirs[0] if self.chart_dirs else self.deploy_dir)

        tls_unconditional = []
        cert_hardcoded = []
        for path in self.template_files():
            if not is_ingress_template(path):
                continue
            for line_no, line in iter_lines(path):
                if re.match(r"\s*tls\s*:", line) and not nearby_has_template_if(path, line_no):
                    tls_unconditional.append((path, line_no))
                if "secretName:" in line and "certSecretName" not in line and ".Values" not in line:
                    cert_hardcoded.append((path, line_no))
        if tls_unconditional or cert_hardcoded:
            path, line = (tls_unconditional or cert_hardcoded)[0]
            self.add("GLOBAL_HTTP_INGRESS_TLS", "FAIL", "Ingress TLS 或证书引用未按 disableHttps/certSecretName 条件化。", "disableHttps=true 时不生成 tls；disableHttps=false 时生成 tls，secretName 使用 .Values.certSecretName。", path, line)
        else:
            self.add("GLOBAL_HTTP_INGRESS_TLS", "PASS", "Ingress TLS/证书逻辑已条件化或未发现 TLS。", "无需整改。", self.chart_dirs[0] if self.chart_dirs else self.deploy_dir)

        self.check_helm_template_http_mode()

    def check_node_tls(self) -> None:
        files = list(self.deploy_text_files())
        signal = search_paths(files, NODE_SIGNAL_PATTERN)
        if not signal:
            self.add("NODE_TLS_REJECT_UNAUTHORIZED", "N/A", "未检测到 Node/前端运行环境特征，跳过 Node TLS 检查。", "无需整改。")
            return
        template_files = list(self.template_files())
        template_text = "\n".join(read_text(path) for path in template_files)
        values_text = "\n".join(read_text(chart / "values.yaml") for chart in self.chart_dirs if (chart / "values.yaml").is_file())
        script_text = "\n".join(read_text(path) for path in self.entrypoint_files)
        missing = []
        if "NODE_TLS_REJECT_UNAUTHORIZED" not in template_text:
            missing.append("容器环境变量 NODE_TLS_REJECT_UNAUTHORIZED")
        if not re.search(r"NODE_TLS_REJECT_UNAUTHORIZED[\s\S]{0,160}\.Values\.platform\.tlsRejectUnauthorized", template_text):
            missing.append("NODE_TLS_REJECT_UNAUTHORIZED 使用 .Values.platform.tlsRejectUnauthorized")
        if not re.search(r"(?m)^\s*platform\s*:[\s\S]*?^\s{2,}tlsRejectUnauthorized\s*:\s*[\"']?1[\"']?", values_text):
            missing.append('values.yaml 默认 platform.tlsRejectUnauthorized: "1"')
        if "read_cert_tls_reject_unauthorized" not in script_text and not re.search(r"cert-config[\s\S]{0,240}CERT_MODE|CERT_MODE[\s\S]{0,240}cert-config", script_text):
            missing.append("entrypoint/install 从 sealos-system/cert-config 读取 CERT_MODE")
        if "read_cert_tls_reject_unauthorized" not in script_text and not re.search(r"https\|acme[\s\S]{0,120}(?:printf|echo)\s+['\"]0['\"]|(?:printf|echo)\s+['\"]0['\"][\s\S]{0,120}https\|acme", script_text):
            missing.append("CERT_MODE=https|acme 时 tlsRejectUnauthorized=0")
        if "read_cert_tls_reject_unauthorized" not in script_text and not re.search(r"(?:printf|echo)\s+['\"]1['\"]|tlsRejectUnauthorized[^\n]*1", script_text):
            missing.append("其它证书模式默认 tlsRejectUnauthorized=1")
        if not re.search(r"--set-string\s+[\"']?platform\.tlsRejectUnauthorized=", script_text):
            missing.append("Helm --set-string platform.tlsRejectUnauthorized")
        path, line, _ = signal[0]
        if missing:
            self.add("NODE_TLS_REJECT_UNAUTHORIZED", "FAIL", "检测到 Node/前端运行环境，但 NODE_TLS_REJECT_UNAUTHORIZED 支持不完整：缺少 " + "、".join(missing) + "。", "从 sealos-system/cert-config 读取 CERT_MODE；CERT_MODE=https|acme 时传 platform.tlsRejectUnauthorized=0，其它模式传 1；values.yaml 默认 platform.tlsRejectUnauthorized: \"1\"；前端容器注入 NODE_TLS_REJECT_UNAUTHORIZED={{ .Values.platform.tlsRejectUnauthorized }}。", path, line)
        else:
            self.add("NODE_TLS_REJECT_UNAUTHORIZED", "PASS", "Node/前端运行环境已按证书模式支持 NODE_TLS_REJECT_UNAUTHORIZED。", "无需整改。", path, line)

    def uses_global_http_helpers(self, text: str) -> bool:
        return bool(
            re.search(r"source\s+['\"]?/root/\.sealos/cloud/scripts/tools\.sh|global_http_disable_https|global_http_external_url", text)
            and re.search(r"global_http_disable_https", text)
            and re.search(r"global_http_external_url", text)
        )

    def is_external_template_line(self, line: str) -> bool:
        lower = line.lower()
        if ".svc" in lower or "cluster.local" in lower or "github.com" in lower:
            return False
        return bool(re.search(r"url|host|origin|domain|callback|redirect|ingress|tls|cors|csp|icon|public", lower) or "https://" in lower)

    def check_helm_template_http_mode(self) -> None:
        if not self.chart_dirs:
            return
        helm_bin = shutil.which("helm")
        if not helm_bin:
            self.add("GLOBAL_HTTP_HELM_TEMPLATE", "WARN", "未安装 helm，跳过 HTTP/HTTPS 双模式渲染验证。", "安装 helm 后运行检测器，或手动执行 helm template 验证 disableHttps=true/false。", self.chart_dirs[0])
            return
        for chart in self.chart_dirs:
            cmd = [helm_bin, "template", "sealos-app-check", str(chart)]
            cmd.extend(self.http_mode_helm_args(chart))
            result = subprocess.run(cmd, cwd=self.root, text=True, capture_output=True, check=False)
            if result.returncode != 0:
                self.add("GLOBAL_HTTP_HELM_TEMPLATE", "WARN", f"helm template 执行失败：{result.stderr.strip() or result.stdout.strip()}", "修复 chart 渲染错误后重新验证 HTTP/HTTPS 双模式。", chart)
                continue
            rendered = result.stdout
            bad_https = [line for line in rendered.splitlines() if "https://" in line and is_external_rendered_line(line)]
            bad_443 = [line for line in rendered.splitlines() if re.search(r":443\b", line) and is_external_rendered_line(line)]
            bad_tls = rendered_has_ingress_tls(rendered)
            if bad_https or bad_443 or bad_tls:
                parts = []
                if bad_https:
                    parts.append(f"HTTP 模式仍包含外部 https:// {len(bad_https)} 处")
                if bad_443:
                    parts.append(f"HTTP 模式仍包含外部 :443 {len(bad_443)} 处")
                if bad_tls:
                    parts.append("HTTP 模式仍生成 tls")
                self.add("GLOBAL_HTTP_HELM_TEMPLATE", "FAIL", "；".join(parts) + "。", "让模板基于 disableHttps 切换协议、端口和 TLS；HTTP 模式输出不得残留外部 https://、:443 或无条件 tls。", chart)
            else:
                self.add("GLOBAL_HTTP_HELM_TEMPLATE", "PASS", f"{self.rel(chart)} HTTP 模式渲染通过。", "无需整改。", chart)

    def http_mode_helm_args(self, chart: Path) -> list[str]:
        values_text = read_text(chart / "values.yaml") if (chart / "values.yaml").is_file() else ""
        args = [
            "--set",
            "disableHttps=true",
            "--set",
            "httpPort=80",
            "--set",
            "cloudPort=443",
            "--set",
            "cloudDomain=example.test",
            "--set",
            "certSecretName=test-cert",
        ]
        if "global:" in values_text and "clusterDomain:" in values_text:
            args.extend(["--set-string", "global.clusterDomain=example.test"])
        if "ingress:" in values_text and "tls:" in values_text and "enabled:" in values_text:
            args.extend(["--set", "ingress.tls.enabled=false", "--set-string", "ingress.sslRedirect=false"])
        if "frontend:" in values_text and "ingress:" in values_text:
            args.extend(
                [
                    "--set-string",
                    "app.urlScheme=http",
                    "--set",
                    "frontend.ingress.tls=",
                    "--set-string",
                    "frontend.ingress.hosts[0].host=registry.example.test",
                    "--set-string",
                    "frontend.ingress.hosts[0].paths[0].path=/",
                    "--set-string",
                    "frontend.ingress.hosts[0].paths[0].pathType=Prefix",
                    "--set-string",
                    "frontend.ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/ssl-redirect=false",
                ]
            )
        return args

    def check_database(self) -> None:
        files = list(self.deploy_text_files())
        text = "\n".join(read_text(path) for path in files)
        kb_signal = re.search(r"kubeblocks|kbcli|ClusterDefinition|global\.featureConfigs\.database|kubeblocksVersion", text, re.IGNORECASE)
        if not kb_signal:
            self.add("DATABASE_KUBEBLOCKS_VERSION", "N/A", "未检测到 KB/KubeBlocks/内置数据库特征，跳过数据库检查。", "无需整改。")
        else:
            has_version = "kubeblocksVersion" in text and "0.8.2" in text
            if has_version:
                path, line = first_match(files, re.compile(r"kubeblocksVersion|0\.8\.2"))
                self.add("DATABASE_KUBEBLOCKS_VERSION", "PASS", "KB/内置数据库读取 kubeblocksVersion，并提供 0.8.2 默认版本。", "无需整改。", path, line)
            else:
                path, line = first_match(files, re.compile(r"kubeblocks|ClusterDefinition|database", re.IGNORECASE))
                self.add("DATABASE_KUBEBLOCKS_VERSION", "FAIL", "KB 数据库版本逻辑不完整：缺少 kubeblocksVersion 或默认 0.8.2。", "读取 global.featureConfigs.database.kubeblocksVersion，并提供默认值 \"0.8.2\"。", path, line)
        if not DOMESTIC_DB_PATTERN.search(text):
            self.add("DOMESTIC_DB_GLOBAL_CONFIG", "N/A", "未检测到国产数据库 components 映射或连接配置特征，规则未触发。", "无需整改。")
            return
        missing = []
        for token in ["components", "postgresql", "mongodb", "databaseMongodbURI", "databasePostgresqlURL"]:
            if token not in text:
                missing.append(token)
        path, line = first_match(files, DOMESTIC_DB_PATTERN)
        if missing:
            self.add("DOMESTIC_DB_GLOBAL_CONFIG", "FAIL", "国产数据库配置读取不完整：缺少 " + ", ".join(missing) + "。", "读取 components.<dbKind>.<app>.type/name，并从 sealos-config 读取 databaseMongodbURI 与 databasePostgresqlURL。", path, line)
        else:
            self.add("DOMESTIC_DB_GLOBAL_CONFIG", "PASS", "国产数据库读取 components 映射和数据库连接配置完整。", "无需整改。", path, line)

    def template_files(self) -> Iterable[Path]:
        for chart in self.chart_dirs:
            templates = chart / "templates"
            if templates.is_dir():
                yield from sorted(path for path in templates.rglob("*") if path.is_file())

    def deploy_text_files(self) -> Iterable[Path]:
        roots = [self.deploy_dir, self.workflow_dir]
        for root in roots:
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    parts = path.relative_to(self.root).parts
                except ValueError:
                    parts = path.parts
                if any(part in IGNORED_DIRS for part in parts):
                    continue
                if path.suffix in TEXT_EXTENSIONS or path.name in {"Dockerfile", "Kubefile", "Sealfile"}:
                    yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def iter_lines(path: Path) -> Iterable[tuple[int, str]]:
    for index, line in enumerate(read_text(path).splitlines(), start=1):
        yield index, line


def search_paths(paths: Iterable[Path], pattern: re.Pattern[str]) -> list[tuple[Path, int, str]]:
    hits = []
    for path in paths:
        for line_no, line in iter_lines(path):
            if pattern.search(line):
                hits.append((path, line_no, line))
    return hits


def first_match(paths: Iterable[Path], pattern: re.Pattern[str]) -> tuple[Path | None, int | None]:
    hits = search_paths(paths, pattern)
    if not hits:
        return None, None
    return hits[0][0], hits[0][1]


def match_location(paths: Iterable[Path], match: re.Match[str]) -> tuple[Path | None, int | None]:
    offset = 0
    for path in paths:
        text = read_text(path)
        next_offset = offset + len(text) + 1
        if offset <= match.start() < next_offset:
            return path, text.count("\n", 0, match.start() - offset) + 1
        offset = next_offset
    return None, None


def nearby_has_template_if(path: Path, line_no: int) -> bool:
    lines = read_text(path).splitlines()
    start = max(0, line_no - 5)
    end = min(len(lines), line_no + 2)
    return any("{{" in line and ("if" in line or "with" in line) for line in lines[start:end])


def is_ingress_template(path: Path) -> bool:
    text = read_text(path)
    return bool(re.search(r"(?m)^\s*kind\s*:\s*Ingress\s*$", text) or re.search(r"networking\.k8s\.io/.+Ingress", text))


def line_is_helper_or_example(rel_path: str, line: str) -> bool:
    lower = line.lower()
    if rel_path.lower().endswith(("notes.txt", "readme.md")):
        return True
    if "global_http_external_url" in lower:
        return True
    if "default" in lower and "printf" in lower and "://" in lower:
        return True
    if "urlscheme" in lower:
        return True
    return False


def workflow_command_context(lines: list[str], index: int) -> str:
    context = [lines[index]]
    previous = lines[index].rstrip()
    for next_line in lines[index + 1 :]:
        if not previous.endswith("\\"):
            break
        stripped = next_line.strip()
        if not stripped:
            break
        context.append(next_line)
        previous = next_line.rstrip()
        if len(context) >= 8:
            break
    return "\n".join(context)


def workflow_step_context(lines: list[str], index: int) -> str:
    start = index
    while start > 0 and not re.match(r"\s*-\s+(?:name|run|uses|working-directory)\s*:", lines[start]):
        start -= 1
    end = index + 1
    while end < len(lines) and not re.match(r"\s*-\s+(?:name|run|uses|working-directory)\s*:", lines[end]):
        end += 1
    return "\n".join(lines[start:end])


def context_has_both_platforms(context: str) -> bool:
    return bool(
        ("linux/amd64" in context or re.search(r"\bamd64\b", context))
        and ("linux/arm64" in context or re.search(r"\barm64\b", context))
    )


def is_external_rendered_line(line: str) -> bool:
    lower = line.lower()
    if ".svc" in lower or "cluster.local" in lower or "github.com" in lower:
        return False
    return bool(re.search(r"url|host|origin|domain|callback|redirect|ingress|tls|cors|csp|icon|public", lower) or "https://" in lower)


def rendered_has_ingress_tls(rendered: str) -> bool:
    in_ingress = False
    ingress_indent = 0
    for line in rendered.splitlines():
        if re.match(r"^\s*kind:\s*Ingress\s*$", line):
            in_ingress = True
            ingress_indent = 0
            continue
        if in_ingress and re.match(r"^---\s*$", line):
            in_ingress = False
            continue
        if in_ingress and re.match(r"^\s*spec:\s*$", line):
            ingress_indent = len(line) - len(line.lstrip())
            continue
        if in_ingress and re.match(r"^\s*tls:\s*$", line):
            indent = len(line) - len(line.lstrip())
            if indent >= ingress_indent:
                return True
    return False


def load_tools_catalog() -> set[str]:
    if not TOOLS_CATALOG_PATH.is_file():
        return set()
    try:
        data = json.loads(read_text(TOOLS_CATALOG_PATH))
    except json.JSONDecodeError:
        return set()
    functions = data.get("functions", {}).get("all", [])
    if not isinstance(functions, list):
        return set()
    return {str(function) for function in functions}


def aggregate_categories(findings: list[Finding]) -> list[tuple[str, str, str]]:
    rows = []
    for name, selectors in CATEGORY_RULES:
        matched = [item for item in findings if any(item.rule_id == selector or item.rule_id.startswith(selector) for selector in selectors)]
        if not matched:
            rows.append((name, "N/A", "未检测到相关规则结果。"))
            continue
        levels = {item.level for item in matched}
        if "FAIL" in levels:
            level = "FAIL"
            detail = first_message(matched, "FAIL")
        elif "WARN" in levels:
            level = "WARN"
            detail = first_message(matched, "WARN")
        elif levels == {"N/A"}:
            level = "N/A"
            detail = "未检测到相关特征，规则未触发。"
        elif "PASS" in levels:
            level = "PASS"
            detail = "检查通过。"
        else:
            level = "N/A"
            detail = "未检测到相关规则结果。"
        rows.append((name, level, detail))
    return rows


def first_message(findings: list[Finding], level: str) -> str:
    for finding in findings:
        if finding.level == level:
            return finding.message
    return ""


def format_location(finding: Finding) -> str:
    if not finding.path:
        return "-"
    if finding.line:
        return f"{finding.path}:{finding.line}"
    return finding.path


def escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def render_markdown(root: Path, results: list[AuditResult], app_type: str) -> str:
    lines = ["# Sealos 应用源码规范审计报告", "", f"目标仓库：`{root.resolve()}`", f"应用类型：`{app_type}`", ""]
    for index, result in enumerate(results, start=1):
        if len(results) > 1:
            lines.extend([f"## 检测目录 {index}: `{result.deploy_dir.resolve()}`", ""])
        else:
            lines.extend([f"检测目录：`{result.deploy_dir.resolve()}`", ""])
        lines.extend(["**总体结论**", "", "| 项目 | 结果 | 说明 |", "| --- | --- | --- |"])
        for name, level, detail in aggregate_categories(result.findings):
            lines.append(f"| {name} | {level} | {escape_table(detail)} |")
        problems = [item for item in result.findings if item.level in {"FAIL", "WARN"}]
        lines.extend(["", "**主要问题**", ""])
        if problems:
            for item_index, item in enumerate(problems, start=1):
                lines.extend([f"{item_index}. {item.message}", f"   位置：`{format_location(item)}`", "", f"   整改建议：{item.remediation}", ""])
        else:
            lines.extend(["未发现 FAIL/WARN 问题。", ""])
        passes = [item for item in result.findings if item.level == "PASS" and item.path]
        lines.extend(["**通过项依据**", ""])
        if passes:
            for item in passes[:20]:
                message = item.message.rstrip("。.")
                lines.append(f"- {message}：`{format_location(item)}`")
        else:
            lines.append("- 无 PASS 项依据。")
        lines.extend(["", "未执行线上集群写操作；本次只基于项目文件做只读检测。", ""])
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sealos app source read-only audit.")
    parser.add_argument("repo_root", nargs="?", help="Target Sealos app repository root.")
    parser.add_argument("--deploy-dir", action="append", help="User-confirmed deploy directory. Repeat or comma-separate for multiple directories.")
    parser.add_argument("--app-type", choices=["app", "sealos-core"], help="User-confirmed app type.")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    return parser.parse_args(argv)


def resolve_repo_root(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    if not sys.stdin.isatty():
        raise ValueError("必须提供目标仓库路径：请传 repo_root 参数。")
    while True:
        raw = input("请输入要检测的 Sealos 应用仓库路径: ").strip()
        if raw:
            return Path(raw).expanduser().resolve()


def resolve_app_type(value: str | None) -> str:
    if value:
        return value
    if not sys.stdin.isatty():
        raise ValueError("必须由用户明确确认应用类型：请传 --app-type app 或 --app-type sealos-core。")
    while True:
        raw = input("请输入应用类型 app 或 sealos-core: ").strip().lower()
        if raw in {"app", "sealos-core"}:
            return raw


def resolve_deploy_dirs(root: Path, values: list[str] | None) -> list[Path]:
    if not values:
        if not sys.stdin.isatty():
            raise ValueError("必须由用户明确确认 deploy 检测目录：请传 --deploy-dir deploy。")
        values = [input("请确认 deploy 检测目录（默认 deploy）: ").strip() or "deploy"]
    dirs = []
    for raw in values:
        for part in raw.split(","):
            item = part.strip()
            if not item:
                continue
            path = Path(item).expanduser()
            if not path.is_absolute():
                path = root / path
            path = path.resolve()
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"deploy 检测目录必须位于目标仓库内：{path}") from exc
            dirs.append(path)
    if not dirs:
        raise ValueError("必须提供至少一个 deploy 检测目录。")
    return dirs


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        root = resolve_repo_root(args.repo_root)
        app_type = resolve_app_type(args.app_type)
        deploy_dirs = resolve_deploy_dirs(root, args.deploy_dir)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"仓库根目录不存在或不是目录：{root}", file=sys.stderr)
        return 2
    results = []
    for deploy_dir in deploy_dirs:
        checker = Checker(root, deploy_dir, app_type)
        results.append(AuditResult(deploy_dir, checker.run()))
    if args.format == "json":
        print(
            json.dumps(
                {
                    "target": str(root),
                    "app_type": app_type,
                    "results": [
                        {"deploy_dir": str(result.deploy_dir), "findings": [asdict(item) for item in result.findings]}
                        for result in results
                    ],
                    "findings": [asdict(item) for result in results for item in result.findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(render_markdown(root, results, app_type))
    return 1 if any(item.level == "FAIL" for result in results for item in result.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
