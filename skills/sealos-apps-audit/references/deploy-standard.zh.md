# Sealos 应用公开 Deploy 标准

本标准用于公开 `sealos-apps` 生态中的应用源码仓库审计。检测器只读取目标项目并输出报告和整改建议，不修改项目文件，不执行部署、构建、推送或集群写操作。

## 适用范围

适用于公开 Sealos 应用仓库：

- 根目录可以有 runtime `Dockerfile`。
- `deploy/Dockerfile`、`deploy/Kubefile` 或 `deploy/Sealfile` 构建 Sealos cluster image。
- `deploy/charts/<name>/` 存放 Helm chart。
- GitHub Actions 负责 runtime image、cluster image、tar 包、md5 和 OSS 同步。

检测前必须由用户明确确认 deploy 检测目录和应用类型。deploy 检测目录默认可建议为 `deploy`，但必须经用户确认。普通应用传 `--app-type app`，SealosCore 模块传 `--app-type sealos-core`。

## 必须项总表

| 分类 | 标准 | 不合规级别 |
| --- | --- | --- |
| Deploy 结构 | 存在用户确认的 deploy 目录，存在 `Dockerfile`、`Kubefile`、`Sealfile` 任意一个，以及 `charts/<name>/Chart.yaml` | FAIL |
| Helm 部署 | 主部署入口使用 `helm upgrade -i` 或 `helm upgrade --install`，并包含 `--create-namespace`；Helm 模板禁止自行创建 `kind: Namespace` | FAIL |
| Cluster image | 构建文件打包 `registry`、`charts`、entrypoint/install 脚本 | FAIL |
| Runtime/cluster 分离 | runtime image 与 cluster image 分别构建和标记 | FAIL |
| 镜像缓存 | cluster image 构建前使用 `sealos build`、`sealos registry save --registry-dir=registry --arch <arch> .` 或 `sreg save` 任一入口 | FAIL |
| 镜像大小 | 流水线输出可审计的镜像或 tar 包大小信息 | FAIL |
| 双架构 | 支持 `linux/amd64` 和 `linux/arm64`，并使用 manifest 或 buildx 覆盖多架构 | FAIL |
| OSS | 流水线上传 cluster image tar/tar.gz 和 md5 到 OSS | FAIL |
| Values 读取策略 | chart 内存在 `values.yaml`、`templates/`、精确的 `<name>-values.yaml`；部署入口从 `/root/.sealos/cloud/values/<scope>/<name>/` 稳定读取 `*-values.yaml` | FAIL/WARN |
| Tools 函数依赖 | 使用 ConfigMap、runtime global.yaml、global.http、证书模式、feature flag 等平台能力时，复用 `/root/.sealos/cloud/scripts/tools.sh` | FAIL/WARN |
| global.http | 支持 HTTP/HTTPS 双模式，不能硬编码外部 HTTPS/TLS | FAIL |
| Node TLS | Node/前端运行环境必须支持 `NODE_TLS_REJECT_UNAUTHORIZED`，按 `cert-config` 的 `CERT_MODE` 注入 | FAIL |
| 数据库 | 使用 KB/KubeBlocks/内置数据库时读取 `global.featureConfigs.database.kubeblocksVersion`，默认 `"0.8.2"` | FAIL |
| 国产数据库 | 可选；仅在检测到 components 映射或国产数据库连接配置特征时检查 | FAIL/N/A |

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

## OSS 同步

OSS 同步是公开发布强制项。流水线必须：

1. 导出 cluster image tar 或 tar.gz。
2. 生成 md5。
3. 使用 `ossutil cp` 上传 tar/tar.gz 和 md5 到 OSS。

## 国产数据库

国产数据库兼容是可选项。未检测到相关特征时输出 `N/A`。检测到以下任一特征时才触发：

- `databaseMongodbURI`
- `databasePostgresqlURL`
- `global.featureConfigs.database.components`
- `cockroachdb`、`opengauss`、`kingbase`、`dameng`、`gaussdb`、`tidb`、`oceanbase`、`polardb`

触发后要求读取 components 映射和 `sealos-config` 中的数据库连接配置。

