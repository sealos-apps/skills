# 新增审计规则

新增规则时按这个顺序处理：

1. 在 `skills/sealos-apps-audit/references/deploy-standard.zh.md` 描述规则、触发条件、级别和整改方向。
2. 在 `skills/sealos-apps-audit/scripts/audit_sealos_apps.py` 增加检测逻辑。
3. 在 `tests/fixtures/` 增加一个最小通过或失败样例。
4. 在 `tests/test_audit_sealos_apps.py` 增加断言，覆盖规则 ID 和级别。
5. 运行公开风险反扫，确保没有内部路径、内部示例名或版本目录进入公开仓库。

规则默认应只读。需要外部服务、账号、集群或写操作的规则不能进入默认审计流程。

