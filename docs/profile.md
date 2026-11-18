# 真实证明实验配置 RCPEH_REAL_MIMC_3S4E8N_V2

## 验收口径

协作主体、消息与攻击在同一台机器上模拟；Π 是实际 Circom/snarkjs Groth16 证明，B/C 运行独立进程验签并进行真实配对验证。接收方只根据真实证明的验证结果处理交接，不接受提交方自报的有效位。

本配置是有界密码学原型，不是最终文档 profile_id=1 的实现完成声明：它把完整小日志到当前记录的投影、查询、用途、登记闭包与去重关系合并到一个 Groth16 电路。尚未实现独立 Nova IVC Ψ、32/48层目录路径、文档完整二进制 schema 的电路编码、增量状态复用或组合形式化证明。

## 容量与编码

- 固定3来源、每来源最多4个事件、8个登记节点、每节点4个父引用。
- 事件序号是固定前缀位置+1；来源身份是固定来源位置+1。
- 事件字向量：op, record_id, version, created_at, updated_at, valid_from, valid_until, lifecycle, assessment, risk_score, purpose_mask, object_id, evidence_type, slot_index, record_salt[8]。
- 节点字向量：active, kind, operation, root_source, root_record_id, root_version, parent[4], content_commit[8], salt[8]。认证祖先图按原登记序号拓扑排序并重编号，R 签署这份固定图快照；图外未使用节点不混入支持材料。
- 所有字都在电路内约束为u32。时间只支持本实验虚拟秒范围；用途位固定0。源端运行连续日志/版本/不可变字段检查，再认证完整事件向量。该小电路从整个认证前缀选择每记录的最后版本，不使用不可信维护者自报的 current 状态。
- 缺省零填充、活动前缀、精确索引排列、精确查询选择、父引用早于子节点、完整可达性、逐节点根集合 OR、原始根到历史事件的身份/版本绑定均进入约束。
- 认证时间索引：R_time=MiMC(kind=3, source_id, count, [record_id, created_at, occupied]×4)。电路从日志计算当前逻辑记录、验证完整排列及时间/ID严格排序，再重算R_time。左边界等于时间窗之前的位置数，右边界等于时间窗结束前的位置数+1，并约束 `left + returned_count + 1 == right`，不能通过删除晚到记录闭合邻界。
- 认证生命周期索引：R_life=MiMC(kind=4, source_id, count, [version,lifecycle,updated_at,valid_from,valid_until]×4)，逻辑ID是槽位位置+1。它始终是最新前沿，不随历史审计改回旧版本；审计用途另外从同一完整历史日志投影出audit_time版本。
- 记录数按来源+逻辑ID去重，来源组按接收方配置去重；不以记忆段落或签名数量计票。

## MiMC 与公开输入

circomlib MiMCSponge，BN254，220轮，key=0。吸收序列固定为 `[1380141125, kind, word_count, ...words]`。kind=1用于来源事件向量，kind=2用于登记图和最终交接绑定，kind=3/4分别为时间/生命周期索引。输出两个原生域元素；它们不是SHA-256的两个128位limb，禁止混用。

来源公钥和R公钥由接收方信任配置固定，签名覆盖profile、任务摘要、nonce、接收者及对应MiMC根。签名摘要仍采用规范域分离SHA-256，MiMC用于电路中的私有数据承诺。原始附件与公开payload摘要仍可以使用SHA-256，它们与MiMC根有明确不同的类型/域。

公开信号顺序由 src/proof.js 的 publicSignals 固定：logRoot[3][2], timeRoot[3][2], lifeRoot[3][2], registryRoot[2], nonce[8], handoffCommit[8], mode, evaluationTime, auditTime, deadline, createdFrom, createdUntil, maxRisk, minRecords, minIssuers, groups[3], objectId, evidenceType, requiredSources[3], requireEach, decision, reason，共56个。C 从本地Task、验签后的检查点和payload重构整条序列，再验证Groth16；不信任A自报的public.json含义。

## 跑法

```bash
npm run setup              # 编译、校验参数摘要、生成并验证新zkey/vkey
npm run experiment:1 -- --trials 1
```

参数使用snarkjs官方README公布的power19预处理文件，其BLAKE2b摘要固定在setup脚本中。电路第二阶段只有本地研究贡献；这不是生产多方仪式。证明后端没有CPU/算法模拟替代路径。

生成的数据：public/<case>/A-to-B-message.json、B-to-C-message.json、proof.json、public.json、C-verification.json，以及verification_key.json、validation.json、paper_table.md和full_run.log。私有输入位于private/且被gitignore排除。B转发的消息与A原始消息逐字节比较；C的实际输出及snarkjs CLI的OK!被保存。

对P2/P3额外让R签署A自报的ALLOW候选，再由真实电路拒绝其witness。R不预审业务决策。各合法proof另做真实public input篡改和proof点篡改验证。

实验统计只计算实际证明生成和验证的试次。源端、登记与对照基线使用的签名/正文摘要仍为SHA-256；它们与电路内MiMC承诺用途不同，并非备用证明方案。
