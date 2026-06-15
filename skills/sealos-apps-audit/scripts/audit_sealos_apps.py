#!/usr/bin/env python3
"""Read-only Sealos app source audit."""

from __future__ import annotations

import argparse
import json
import re
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
    ("Runtime/Cluster 镜像分离", ["WORKFLOW_IMAGE_SPLIT", "WORKFLOW_IMAGE_CACHE"]),
    ("双架构", ["WORKFLOW_MULTI_ARCH"]),
    ("OSS 推送", ["WORKFLOW_OSS_SYNC"]),
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
    r"NODE_TLS_REJECT_UNAUTHORIZED|frontend\s*:|frontend\.(?:enabled|image|env)|node_modules|npm\s+(?:run|start|build)|pnpm\s+(?:run|start|build)|yarn\s+(?:run|start|build)|next\s+(?:start|build)",
    re.IGNORECASE,
)
SIZE_PATTERN = re.compile(
    r"docker\s+image\s+inspect|docker\s+images\b|docker\s+image\s+ls\b|docker\s+buildx\s+imagetools\s+inspect\b|du\s+-[A-Za-z]*h|ls\s+-[A-Za-z]*h|stat\s+(?:-c%s|-f%z)|wc\s+-c",
    re.IGNORECASE,
)
DOMESTIC_DB_PATTERN = re.compile(
    r"databaseMongodbURI|databasePostgresqlURL|global\.featureConfigs\.database\.components|components:\s*(?:\n|\r\n)\s+(?:postgresql|mongodb):|cockroachdb|opengauss|kingbase|dameng|gaussdb|tidb|oceanbase|polardb",
    re.IGNORECASE,
)
TOOLS_CAPABILITY_RULES = [
    ("ConfigMap 读写", {"get_cm_value", "set_cm_value", "ensure_cm_value", "fetch_configmap_data_key"}, [r"\bkubectl\s+get\s+configmap\b", r"\bkubectl\s+patch\s+configmap\b"], "FAIL"),
    ("runtime global.yaml 读取", {"read_yaml_file_path"}, [r"/root/\.sealos/cloud/values/global\.yaml", r"\bglobal\.featureConfigs\b", r"\byq\s+e\b"], "FAIL"),
    ("global.http URL/协议/端口", {"global_http_disable_https", "global_http_external_url"}, [r"\bdisableHttps\b", r"\bSEALOS_DISABLE_HTTPS\b", r"\bSEALOS_HTTP_PORT\b", r"\bhttps://", r":443\b"], "FAIL"),
    ("证书模式/Node TLS", {"read_cert_tls_reject_unauthorized"}, [r"\bCERT_MODE\b", r"\bcert-config\b", r"\bNODE_TLS_REJECT_UNAUTHORIZED\b"], "FAIL"),
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
        runtime = re.search(r"RUNTIME_IMAGE|runtime image|frontend|backend|ghcr\.io/.+", combined, re.IGNORECASE)
        cluster = re.search(r"CLUSTER_IMAGE|SEALOS_IMAGE|cluster image|sealos image|-cluster", combined, re.IGNORECASE)
        if runtime and cluster:
            path, line = match_location(self.workflow_files, cluster)
            self.add("WORKFLOW_IMAGE_SPLIT", "PASS", "流水线区分 runtime image 与 cluster image。", "无需整改。", path, line)
        else:
            self.add("WORKFLOW_IMAGE_SPLIT", "FAIL", "流水线未明确区分 runtime image 与 cluster image。", "分别定义并构建 runtime image 与 cluster image。", self.workflow_files[0])
        has_amd64 = "linux/amd64" in combined or re.search(r"\bamd64\b", combined)
        has_arm64 = "linux/arm64" in combined or re.search(r"\barm64\b", combined)
        has_manifest = re.search(r"docker\s+(?:buildx\s+imagetools|manifest)\s+create|platforms?\s*:", combined, re.IGNORECASE)
        if has_amd64 and has_arm64 and has_manifest:
            path, line = first_match(self.workflow_files, re.compile(r"amd64|arm64|imagetools|manifest|platforms?", re.IGNORECASE))
            self.add("WORKFLOW_MULTI_ARCH", "PASS", "双架构检查通过：检测到 amd64/arm64 和 manifest/buildx 多架构入口。", "无需整改。", path, line)
        else:
            self.add("WORKFLOW_MULTI_ARCH", "FAIL", "未确认双架构产物：需要 amd64/arm64，并使用 manifest 或 buildx 覆盖多架构。", "增加 linux/amd64、linux/arm64 构建，并使用 docker manifest/buildx imagetools 或 buildx 多平台构建发布。", self.workflow_files[0])
        cache = re.search(r"sealos\s+build\b|sealos\s+registry\s+save[\s\S]{0,320}--registry-dir[=\s\"']*registry|\bsreg\s+save\b", combined, re.IGNORECASE)
        if cache:
            path, line = match_location(self.workflow_files, cache)
            self.add("WORKFLOW_IMAGE_CACHE", "PASS", "workflow 包含 cluster image 镜像缓存/构建入口。", "无需整改。", path, line)
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
        files = list(self.deploy_text_files())
        if not files:
            return
        text = "\n".join(read_text(path) for path in files)
        needed = ["cloudDomain", "cloudPort", "httpPort", "disableHttps", "certSecretName"]
        missing = [name for name in needed if name not in text and "global_http_" not in text]
        if missing:
            self.add("GLOBAL_HTTP_CONFIG", "FAIL", "未完整读取/声明 global.http 参数：" + ", ".join(missing) + "。", "读取 cloudDomain、cloudPort、httpPort、disableHttps、certSecretName，或使用 global_http_* helper。", files[0])
        else:
            path, line = first_match(files, re.compile(r"disableHttps|global_http_|cloudDomain|httpPort"))
            self.add("GLOBAL_HTTP_CONFIG", "PASS", "已读取/声明 global.http 相关参数。", "无需整改。", path, line)
        hardcoded = []
        for path in self.template_files():
            for line_no, line in iter_lines(path):
                lower = line.lower()
                if ("https://" in lower or re.search(r":443\b", lower)) and ".svc" not in lower and "github.com" not in lower and "sealos.run" not in lower:
                    hardcoded.append((path, line_no))
        if hardcoded:
            path, line = hardcoded[0]
            self.add("GLOBAL_HTTP_HARDCODED_EXTERNAL_URL", "FAIL", "模板存在硬编码外部 https:// 或 :443。", "根据 disableHttps 切换协议、端口和 Ingress TLS。", path, line)
        else:
            self.add("GLOBAL_HTTP_HARDCODED_EXTERNAL_URL", "PASS", "未发现模板硬编码外部 https:// 或 :443。", "无需整改。", self.chart_dirs[0] if self.chart_dirs else self.deploy_dir)

    def check_node_tls(self) -> None:
        files = list(self.deploy_text_files())
        signal = search_paths(files, NODE_SIGNAL_PATTERN)
        if not signal:
            self.add("NODE_TLS_REJECT_UNAUTHORIZED", "N/A", "未检测到 Node/前端运行环境特征，跳过 Node TLS 检查。", "无需整改。")
            return
        text = "\n".join(read_text(path) for path in files)
        missing = []
        if "NODE_TLS_REJECT_UNAUTHORIZED" not in text:
            missing.append("NODE_TLS_REJECT_UNAUTHORIZED")
        if "tlsRejectUnauthorized" not in text:
            missing.append("platform.tlsRejectUnauthorized")
        uses_tls_helper = "read_cert_tls_reject_unauthorized" in text
        if not uses_tls_helper and ("CERT_MODE" not in text or "cert-config" not in text):
            missing.append("从 cert-config 读取 CERT_MODE")
        if "--set-string" not in text or "platform.tlsRejectUnauthorized" not in text:
            missing.append("Helm --set-string platform.tlsRejectUnauthorized")
        path, line, _ = signal[0]
        if missing:
            self.add("NODE_TLS_REJECT_UNAUTHORIZED", "FAIL", "检测到 Node/前端运行环境，但 Node TLS 支持不完整：缺少 " + "、".join(missing) + "。", "从 sealos-system/cert-config 读取 CERT_MODE，https/acme 时传 0，其它模式传 1，并注入 NODE_TLS_REJECT_UNAUTHORIZED。", path, line)
        else:
            self.add("NODE_TLS_REJECT_UNAUTHORIZED", "PASS", "Node/前端运行环境已按证书模式支持 NODE_TLS_REJECT_UNAUTHORIZED。", "无需整改。", path, line)

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
