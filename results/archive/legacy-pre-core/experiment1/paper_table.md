# 实验 1：真实证明的本地协作实验

后端：Groth16 + MiMC。每格为拦截率 / 误报率。每类 50 组攻击，正常／历史审计对照单独计数。

| 攻击 | 仅签名 B0 | 成员存在 B1 | 完整查询、不验传承 B2 | RC-PEH（真实 Π） |
|---|---:|---:|---:|---:|
| 隐瞒不报 P1 | 0% / 0% | 0% / 0% | 100% / 0% | 100% / 0% |
| 拿旧当新 P2 | 0% / 0% | 0% / 0% | 100% / 0% | 100% / 0% |
| 同源刷票 P3 | 0% / 0% | 0% / 0% | 0% / 0% | 100% / 0% |

实际生成 300 个 Groth16 证明；独立 Agent C 进程验证通过 300 个。正常 DENY 证明也计入验证成功，只有 ALLOW 授权行动。遗漏 witness 在生成阶段被电路拒绝。public/ 包含实际 proof/public/message、CLI 验证输出和 C 的结果。

配置范围：Bounded 3-source/4-event/8-node MiMC joint proof. State is recomputed from complete source-authenticated event vectors in this Groth16 circuit; this is not the final split Nova IVC architecture or its full-depth tree profile.

当前运行状态：PASS。这些小样本结果不代表普适安全证明；独立 Nova IVC 尚未实现。
