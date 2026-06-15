# 审计报告格式

默认 Markdown 报告必须包含：

1. `总体结论`：按业务维度聚合为表格，至少包含 Deploy 结构、Helm 部署、Runtime/Cluster 镜像分离、双架构、OSS 推送、Values 读取策略、Tools 函数依赖、Node TLS、`global.http` HTTP 模式、数据库、国产数据库。
2. `主要问题`：只列 `FAIL` 和 `WARN`，每条包含位置、问题说明和整改建议。
3. `通过项依据`：列出代表性 `PASS` 项，尽量包含文件和行号。
4. 结尾说明未执行线上集群写操作。

`--format json` 用于机器处理或调试，保留逐条 finding。

