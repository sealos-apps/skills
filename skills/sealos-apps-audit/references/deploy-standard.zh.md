# Sealos 应用公开 Deploy 标准

本标准用于公开 `sealos-apps` 生态中的应用源码仓库审计。检测器只读取目标项目并输出报告和整改建议，不修改项目文件，不执行部署、构建、推送或集群写操作。

## 适用范围

适用于公开 Sealos 应用仓库：

- 根目录可以有 runtime `Dockerfile`。
- `deploy/Dockerfile`、`deploy/Kubefile` 或 `deploy/Sealfile` 构建 Sealos cluster image。
- `deploy/charts/<name>/` 存放 Helm chart。
- GitHub Actions 负责 runtime image、cluster image、tar 包、md5 和 OSS 同步。

检测前必须由用户明确确认 deploy 检测目录和应用类型。deploy 检测目录默认可建议为 `deploy`，但必须经用户确认。普通应用传 `--app-type app`，SealosCore 模块传 `--app-type sealos-core`。

## 只读边界

审计只能做静态读取和本地只读渲染：

- 可以读取源码、workflow、chart、脚本和 values。
- 可以在本机执行 `helm template` 做模板渲染检查。
- 禁止执行部署、构建、镜像推送、registry 写入、OSS 写入或集群写操作。
- 禁止依赖私有仓库路径、私有发布目录、记忆或历史会话作为公开报告依据。

## 必须项总表

| 分类 | 标准 | 不合规级别 |
| --- | --- | --- |
| Deploy 结构 | 存在用户确认的 deploy 目录，存在 `Dockerfile`、`Kubefile`、`Sealfile` 任意一个，以及 `charts/<name>/Chart.yaml` | FAIL |
| Helm 部署 | 主部署入口使用 `helm upgrade -i` 或 `helm upgrade --install`，并包含 `--create-namespace`；Helm 模板禁止自行创建 `kind: Namespace` | FAIL |
| Cluster image | 构建文件打包 `registry`、`charts`、entrypoint/install 脚本 | FAIL |
| Runtime/cluster 分离 | runtime image 与 cluster image 分别构建和标记，且 workflow 使用可区分的公开 GHCR 命名 | FAIL |
| 镜像缓存 | cluster image 构建前使用 `sealos build`、`sealos registry save --registry-dir=registry --arch <arch> .` 或 `sreg save` 任一入口 | FAIL |
| 镜像大小 | 流水线输出可审计的镜像或 tar 包大小信息 | FAIL |
| 双架构 | 支持 `linux/amd64` 和 `linux/arm64`，并能区分 runtime 与 cluster 的多架构产物 | FAIL |
| OSS | 流水线上传 cluster image tar/tar.gz 和 md5 到 OSS | FAIL |
| Values 读取策略 | chart 内存在 `values.yaml`、`templates/`、精确的 `<name>-values.yaml`；部署入口从 `/root/.sealos/cloud/values/<scope>/<name>/` 稳定读取 `*-values.yaml` | FAIL/WARN |
| Tools 函数依赖 | 使用 ConfigMap、runtime global.yaml、global.http、证书模式、feature flag 等平台能力时，复用 `/root/.sealos/cloud/scripts/tools.sh` | FAIL/WARN |
| global.http | entrypoint、values、模板和本地渲染同时支持 HTTP/HTTPS 双模式，不能硬编码外部 HTTPS/TLS | FAIL/WARN |
| Node TLS | Node/前端运行环境必须支持 `NODE_TLS_REJECT_UNAUTHORIZED`，按 `cert-config` 的 `CERT_MODE` 注入 | FAIL |
| 数据库 | 使用 KB/KubeBlocks/内置数据库时读取 `global.featureConfigs.database.kubeblocksVersion`，默认 `"0.8.2"` | FAIL |
| 国产数据库 | 可选；仅在检测到 components 映射或国产数据库连接配置特征时检查 | FAIL/N/A |

## Deploy 结构

公开应用仓库应把部署相关内容集中在用户确认的 deploy 目录中：

- `deploy/Dockerfile`、`deploy/Kubefile`、`deploy/Sealfile` 至少存在一个。
- `deploy/charts/<name>/Chart.yaml` 必须存在。
- `deploy/charts/<name>/values.yaml` 必须存在。
- `deploy/charts/<name>/templates/` 必须存在。
- chart 同级默认 values 文件必须精确命名为 `<name>-values.yaml`。

cluster image 构建文件必须包含以下内容或等价复制：

- `registry`，用于离线镜像缓存。
- `charts`，用于 Helm 部署。
- entrypoint 或 install 脚本，用于实际执行 Helm 安装升级。

## Helm 部署入口

主部署入口必须满足：

- 使用 `helm upgrade -i` 或 `helm upgrade --install`。
- 包含 `--create-namespace`。
- 通过 `-f` 或 `--values` 加载最终 values 文件。
- 需要读取平台配置时，优先复用 `/root/.sealos/cloud/scripts/tools.sh` 中的公开 helper。

Helm 模板禁止自行创建 `kind: Namespace`。命名空间由部署入口和 Sealos 运行环境负责，chart 模板内重复创建命名空间会造成升级和权限边界不稳定。

## Workflow 镜像命名

runtime image 与 cluster image 必须拆分，且 GHCR 命名必须能被人工和检测器明确区分。

推荐格式：

```text
ghcr.io/${{ github.repository }}/${{ github.repository }}:${{ matrix.arch }}
ghcr.io/${{ github.repository }}/${{ github.repository }}-cluster:${{ matrix.arch }}
```

禁止格式：

```text
ghcr.io/${{ github.repository }}
ghcr.io/${{ github.repository }}-cluster
```

禁止原因：

- runtime 与 cluster 的包名缺少独立层级，容易在 GHCR 包列表中混淆。
- 后续 manifest、tar 包和 OSS 同步难以稳定识别对应产物。
- 多仓库复用 workflow 时，旧格式更容易把 runtime 和 cluster 标签写到同一包名空间下。

合规 workflow 至少需要出现：

- runtime image 构建或推送证据。
- cluster image 构建或推送证据。
- 二者的镜像名、tag 或 manifest 上下文可区分。

## 镜像缓存与大小输出

cluster image 构建前必须有离线镜像缓存入口。合规方式包括：

- `sealos build`。
- `sealos registry save --registry-dir=registry --arch <arch> .`。
- `sreg save`。

如果使用 `sealos registry save`，必须同时体现 `--registry-dir registry` 和 `--arch`，避免生成目录或架构不明确。

workflow 必须输出可审计的镜像或产物大小信息，便于发布前判断体积异常。合规证据包括：

- `docker image inspect`。
- `docker images`。
- `docker buildx imagetools inspect`。
- `du -h`、`ls -lh`、`stat`、`wc -c` 等产物大小输出。

## 双架构发布

公开发布必须覆盖：

```text
linux/amd64
linux/arm64
```

合规路径有两类。

第一类是 buildx 多平台构建：

- workflow 使用 `docker/setup-buildx-action` 或 `docker buildx build`。
- `platforms` 或命令参数同时包含 `linux/amd64` 和 `linux/arm64`。
- runtime 与 cluster 的构建上下文或镜像名可以区分。

第二类是分架构构建后再合并 manifest：

- amd64 与 arm64 分别构建、打 tag、推送。
- 使用 `docker manifest create`、`docker buildx imagetools create` 或等价命令合并。
- manifest 命令上下文必须能分别识别 runtime 产物和 cluster 产物。

仅出现 `amd64`、`arm64` 字样不代表合规。报告需要说明多架构证据来自 buildx 多平台构建，还是来自 runtime/cluster 两组 manifest 合并。

## Values 读取策略

普通应用必须支持：

```text
/root/.sealos/cloud/values/apps/<name>/*-values.yaml
```

SealosCore 模块必须支持：

```text
/root/.sealos/cloud/values/core/<name>/*-values.yaml
```

要求：

- 目录不存在时输出 WARN，并复制 chart 内默认 `*-values.yaml` 到该目录。
- 使用时按稳定顺序读取该目录内所有 `*-values.yaml`。
- 每个文件追加为 Helm `-f` 或 `--values` 参数。
- 不直接把 chart 默认 `*-values.yaml` 当作最终 Helm values 覆盖文件。
- 普通应用使用 `apps/<name>` scope，SealosCore 模块使用 `core/<name>` scope。

## Tools 函数依赖

当部署脚本或模板使用平台配置能力时，应复用 `/root/.sealos/cloud/scripts/tools.sh` 的公开 helper，而不是在每个应用中重新拼接复杂读取逻辑。

触发检查的典型能力包括：

- ConfigMap 与 `sealos-config`。
- runtime `global.yaml`。
- `global.http`。
- 证书模式与 Node TLS。
- feature flag。
- 数据库组件映射。

报告需要区分两种情况：

- 检测到能力特征且已引用 helper：`PASS`。
- 检测到能力特征但未引用 helper：`FAIL` 或 `WARN`，并给出应复用的 helper 能力。

## global.http HTTP/HTTPS 双模式

`global.http` 检查按 entrypoint、values、模板静态扫描、本地 Helm 渲染四层判断。

entrypoint 必须读取或传入以下参数：

```text
cloudDomain
cloudPort
httpPort
disableHttps
certSecretName
```

可以直接从 `sealos-config` 读取，也可以复用公开 helper，例如：

- `global_http_disable_https`
- `global_http_external_url`

chart `values.yaml` 必须声明上述参数的默认值。默认值可以为空字符串或安全占位值，但字段必须存在，保证 Helm `--set-string` 覆盖路径稳定。

模板必须满足：

- 不能硬编码外部访问 `https://`。
- 不能硬编码外部访问 `:443`。
- HTTP 模式下不能渲染 Ingress `tls`。
- HTTPS 模式下如果需要 Ingress TLS，`secretName` 必须来自 `.Values.certSecretName`。
- TLS 相关模板必须受 `disableHttps` 或 `certSecretName` 条件控制。

检测器在本机安装 `helm` 时，会对 HTTP 模式执行只读渲染验证。HTTP 模式渲染必须满足：

- 不残留外部 `https://`。
- 不残留外部 `:443`。
- 不生成 Ingress TLS。
- 不生成 TLS `secretName`。

如果本机未安装 `helm`，报告输出 `WARN`，提示安装后复验；静态检查结果仍然有效。

## Node TLS

当仓库呈现 Node 或前端运行环境特征时，必须支持 `NODE_TLS_REJECT_UNAUTHORIZED`。

触发特征包括：

- `package.json`。
- `next.config.*`、`vite.config.*`。
- `node`、`npm`、`pnpm`、`yarn`、`bun` 等构建或运行命令。
- `nodejs`、`frontend`、`web` 等服务命名特征。

chart `values.yaml` 必须提供默认值：

```yaml
platform:
  tlsRejectUnauthorized: "1"
```

容器模板必须注入：

```yaml
- name: NODE_TLS_REJECT_UNAUTHORIZED
  value: {{ .Values.platform.tlsRejectUnauthorized | quote }}
```

部署入口必须从 `sealos-system/cert-config` 读取 `CERT_MODE`，并按以下规则传给 Helm：

```text
CERT_MODE=https 或 CERT_MODE=acme -> platform.tlsRejectUnauthorized=0
其它模式或读取失败 -> platform.tlsRejectUnauthorized=1
```

也可以复用公开 helper：

```text
read_cert_tls_reject_unauthorized
```

报告必须能说明四类证据是否完整：

- Node/前端环境触发证据。
- values 默认值。
- 容器环境变量。
- entrypoint 中 `CERT_MODE` 到 `platform.tlsRejectUnauthorized` 的传递链路。

## OSS 同步

OSS 同步是公开发布强制项。流水线必须：

1. 导出 cluster image tar 或 tar.gz。
2. 生成 md5。
3. 使用 `ossutil cp` 上传 tar/tar.gz 和 md5 到 OSS。

报告需要同时说明 tar/tar.gz、md5、OSS 上传三类证据。只上传镜像、不上传 md5，或只生成 md5、不上传，均不合规。

## 数据库与 KubeBlocks

当仓库使用 KB、KubeBlocks 或内置数据库时，必须读取：

```text
global.featureConfigs.database.kubeblocksVersion
```

默认值要求为：

```text
"0.8.2"
```

报告需要指出数据库能力是未触发、已合规，还是缺少版本读取。

## 国产数据库

国产数据库兼容是可选项。未检测到相关特征时输出 `N/A`。检测到以下任一特征时才触发：

- `databaseMongodbURI`
- `databasePostgresqlURL`
- `global.featureConfigs.database.components`
- `cockroachdb`、`opengauss`、`kingbase`、`dameng`、`gaussdb`、`tidb`、`oceanbase`、`polardb`

触发后要求读取 components 映射和 `sealos-config` 中的数据库连接配置。报告需要给出映射读取证据和连接配置来源。

## 报告信息量要求

人工 Markdown 报告不得只贴 finding 表。必须按业务维度解释：

- 当前维度结论：`PASS`、`FAIL`、`WARN` 或 `N/A`。
- 关键证据：文件、行号、命令片段或字段名。
- 影响说明：为什么会影响发布、升级或 HTTP/HTTPS 模式。
- 整改建议：给到可执行的改法，而不是只说“不符合规范”。
- 复验方式：说明重新运行检测器或本地 `helm template` 的验证点。

报告结尾必须说明本次审计未执行线上集群写操作、未构建镜像、未推送镜像、未上传 OSS。
