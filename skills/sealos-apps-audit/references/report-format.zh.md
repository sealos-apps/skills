# 审计报告格式

默认 Markdown 报告必须包含：

1. `总体结论`：按业务维度聚合为表格，至少包含 Deploy 结构、Helm 部署、Runtime/Cluster 镜像分离、双架构、OSS 推送、Values 读取策略、Tools 函数依赖、Node TLS、`global.http` HTTP 模式、数据库、国产数据库。
2. `主要问题`：只列 `FAIL` 和 `WARN`，每条包含位置、问题说明和整改建议。
3. `通过项依据`：列出代表性 `PASS` 项，尽量包含文件和行号。
4. 结尾说明未执行线上集群写操作。

`--format json` 用于机器处理或调试，保留逐条 finding。

## 总体结论

总体结论表不应只展示原始 rule id。建议列：

| 维度 | 结论 | 关键依据 | 风险说明 |
| --- | --- | --- | --- |
| Runtime/Cluster 镜像分离 | PASS/FAIL | workflow 文件与镜像名 | 是否会混淆 runtime 和 cluster 产物 |
| 双架构 | PASS/FAIL | buildx 或 manifest 证据 | 是否同时覆盖 runtime 与 cluster |
| `global.http` HTTP 模式 | PASS/FAIL/WARN | entrypoint、values、模板、helm template | HTTP 模式是否仍残留 HTTPS/TLS |
| Node TLS | PASS/FAIL/N/A | Node 特征、values、env、CERT_MODE | 前端容器是否能适配自签/可信证书模式 |

结论聚合规则：

- 任一 `FAIL` 使该维度为 `FAIL`。
- 无 `FAIL` 但存在 `WARN` 时为 `WARN`。
- 全部通过时为 `PASS`。
- 规则未触发时为 `N/A`。

## 主要问题

每条问题必须包含：

- 规则编号，例如 `WORKFLOW_IMAGE_SPLIT`、`GLOBAL_HTTP_INGRESS_TLS`。
- 严重级别：`FAIL` 或 `WARN`。
- 位置：文件路径和行号；确实无行号时给出目录或文件。
- 问题说明：说明缺少的检测点或不合规行为。
- 影响说明：说明对发布、升级、HTTP/HTTPS 切换或多架构产物的影响。
- 整改建议：给到可执行动作。

推荐写法：

```text
- [FAIL] GLOBAL_HTTP_INGRESS_TLS
  - 位置：deploy/charts/example/templates/ingress.yaml:12
  - 问题：Ingress TLS 未受 disableHttps/certSecretName 条件控制。
  - 影响：HTTP 模式仍可能渲染 tls，导致无证书或端口不匹配。
  - 建议：disableHttps=true 时不生成 tls；HTTPS 模式下 secretName 使用 .Values.certSecretName。
```

## 公开版重点检测点

报告要对以下检测点给出足够信息量，不能只写“缺少支持”：

### Workflow 镜像命名

需要明确是否出现禁止格式：

```text
ghcr.io/${{ github.repository }}
ghcr.io/${{ github.repository }}-cluster
```

整改建议应指向推荐格式：

```text
ghcr.io/${{ github.repository }}/${{ github.repository }}
ghcr.io/${{ github.repository }}/${{ github.repository }}-cluster
```

### 双架构

需要说明证据来源属于哪类：

- `docker buildx build --platform linux/amd64,linux/arm64`。
- `docker manifest create` 或 `docker buildx imagetools create`。

使用 manifest 时，需要分别说明 runtime manifest 和 cluster manifest 是否都存在；只发现其中一个时必须在报告中点名缺失侧。

### `global.http`

需要分别说明：

- entrypoint 是否读取 `cloudDomain`、`cloudPort`、`httpPort`、`disableHttps`、`certSecretName`。
- `values.yaml` 是否声明上述字段。
- 模板是否硬编码外部 `https://` 或 `:443`。
- Ingress TLS 是否受条件控制。
- 本机有 `helm` 时，HTTP 模式渲染是否仍残留 HTTPS/TLS。

### Node TLS

需要分别说明：

- 是否检测到 Node/前端特征。
- `values.yaml` 是否声明 `platform.tlsRejectUnauthorized: "1"`。
- 容器是否注入 `NODE_TLS_REJECT_UNAUTHORIZED`。
- entrypoint 是否从 `CERT_MODE` 推导 `platform.tlsRejectUnauthorized`，或是否复用 `read_cert_tls_reject_unauthorized`。

## 通过项依据

通过项不需要贴全量 finding，但要覆盖有代表性的维度：

- Deploy 结构和 Helm 部署入口。
- runtime/cluster 镜像分离和多架构。
- OSS tar/md5 上传。
- Values 读取策略。
- `global.http` 与 Node TLS。
- 数据库或国产数据库触发状态。

## 结尾声明

报告结尾必须保留只读边界声明：

```text
本次审计只进行了源码静态检查和本地只读渲染验证；未执行线上集群写操作，未构建或推送镜像，未上传 OSS。
```
