# 偏好对审计报告

本报告由流水线基于授权语料生成（逻辑时刻起点 2026-10-26T00:00:00Z，步长 30s）。所有正文均已脱敏；未授权来源在闸门处被拒绝，不进入任何产物。

## 一、漏斗

| 阶段/筛选规则 | 计数 | 说明 |
|---|---|---|
| 输入 prompt | 16 | 读入的候选生成文件条数 |
| 候选回答 | 40 | 全部候选（未筛选） |
| 产出偏好对 | 8 | 通过的偏好对条数 |
| 被拒记录 | 2 | 整条 prompt 被拒绝的条数 |
| 去重命中 | 1 | 去重键冲突的候选对 |

### 逐条筛选规则的拦截数

| 错误码 | 拦截数 | 说明 |
|---|---|---|
| PAIR_AXIS_NOT_DECISIVE | 1 | 没有任何对比轴达到决定性分差 |
| PAIR_CROSS_AXIS_REVERSAL | 1 | 非决定性轴上被反向超越 |
| PAIR_DUPLICATE | 1 | 去重键已被占用 |
| PAIR_IDENTICAL_TEXT | 1 | 两条候选规范化后相同 |
| PAIR_LENGTH_IMBALANCE | 1 | 两条候选长度比过大 |
| PAIR_LOW_MARGIN | 1 | 总分差不足 |
| PAIR_NO_CANDIDATE | 1 | 候选数不足 2 条 |
| PAIR_SCHEMA_INVALID | 1 | 候选字段不符合规范 |
| PAIR_SCORE_TOO_LOW | 1 | 候选质量分过低 |

## 二、对比轴分布

| 对比轴 | 作为决定性轴的条数 | 占比 |
|---|---|---|
| evidence_citation | 7 | 87.5% |
| policy_compliance | 1 | 12.5% |
| redaction_safety | 0 | 0.0% |
| instruction_following | 0 | 0.0% |

口径：每条偏好对必须有一个**唯一决定性轴**，该轴分差 >= 0.100000；其它轴反向超越不得超过 0.150000。平均决定性分差 0.512500，平均总分差 0.426250。

## 三、授权来源

登记表条目 6 个，覆盖 6 个来源、2 种许可；本次语料通过 6 条。

| 来源 | 版本 | 许可 | 授权编号 | 生效日期 | 内容指纹（前 16 位） | 标题 |
|---|---|---|---|---|---|---|
| SRC-KB-001 | v3 | customer-authorized | AUTH-2026-0041 | 2026-08-15 | 975ae4146e599e7c | 客户工单分级与升级规范 |
| SRC-KB-002 | v2 | internal-approved | AUTH-2026-0042 | 2026-08-15 | 7b84eeb8ddf1c355 | 退款与补偿审批口径 |
| SRC-KB-003 | v1 | customer-authorized | AUTH-2026-0043 | 2026-09-01 | 54a0ee9ec5db2efe | 数据脱敏与外发规范 |
| SRC-KB-004 | v5 | internal-approved | AUTH-2026-0044 | 2026-09-10 | dc13f30df0168abc | 产品故障排查手册 |
| SRC-KB-005 | v1 | customer-authorized | AUTH-2026-0045 | 2026-09-20 | 89fbca27c801b30b | 客服话术与合规禁区 |
| SRC-LEGAL-006 | v2 | internal-approved | AUTH-2026-0046 | 2026-09-28 | ca109be7eb6ef15b | 合同交付条款摘要 |

## 四、未授权/不合规来源（负样例）

本次语料中没有未授权来源（负样例由 `samples/sources_unauthorized.jsonl` 单独驱动）。

补充负向对照：hash_mismatch = 拦截；invalid_traces = 拦截；residual_pii = 拦截；unauthorized_generations = 拦截；version_mismatch = 拦截；未授权候选生成 = 3。

## 五、匿名化摘要

| 项目 | 值 |
|---|---|
| 脱敏规则数 | 9 |
| 残留检测模式数 | 8 |
| 残留处置策略 | block |
| 本次伪名映射条数 | 3 |
| 映射表摘要（sha256，前 16 位） | 8e864f9fb5a76705 |

映射表只留在 `var/`（发布时跳过），产物里只有摘要；伪名由 salt 派生，同一原文稳定同一伪名。

## 六、样例偏好对

### pair_170f4284d44ebca0

| 字段 | 值 |
|---|---|
| prompt | 单笔 30000 元的补偿需要走什么审批？ |
| 决定性轴 | evidence_citation（分差 0.540000） |
| chosen | 依据《退款与补偿审批口径》（引用 SRC-KB-002@v2）：超过 5000 元须二级审批，… |
| rejected | 建议尽快处理：这种金额走普通审批即可，财务那边不会细究。具体处置动作与依据按规范留痕，便于后续… |
| 来源 | SRC-KB-002@v2 |
| 逻辑时刻 | 2026-10-26T00:00:00Z |

### pair_382aa6c131a23f66

| 字段 | 值 |
|---|---|
| prompt | 客户要求承诺合同之外的能力和时限，应该怎么回复？ |
| 决定性轴 | evidence_citation（分差 0.540000） |
| chosen | 依据《客服话术与合规禁区》（引用 SRC-KB-005@v1）：不得承诺未写入合同的能力与时限… |
| rejected | 建议尽快处理：先答应客户，后续再补合同就行，服务体验优先。具体处置动作与依据按规范留痕，便于后… |
| 来源 | SRC-KB-005@v1 |
| 逻辑时刻 | 2026-10-26T00:00:30Z |

### pair_4df4e5a3d06c663a

| 字段 | 值 |
|---|---|
| prompt | 把 P1 工单升级为 P0 时需要写清哪些内容？对接人信息怎么记？ |
| 决定性轴 | policy_compliance（分差 0.320000） |
| chosen | 升级前把影响面写一下，对接人信息按惯例记录。具体处置动作与依据按规范留痕，便于后续复核。具体处… |
| rejected | 建议尽快处理：升级时和对接人打个招呼就行，具体情况口头同步。具体处置动作与依据按规范留痕，便于… |
| 来源 | SRC-KB-001@v3 |
| 逻辑时刻 | 2026-10-26T00:01:00Z |

## 七、判据与复跑

判据全部来自 `config/pipeline_config.json` 的 `pairs` 段与 `config/source_registry.json`；改阈值只改配置。复跑：`python -m dpo_policy pairs`。
