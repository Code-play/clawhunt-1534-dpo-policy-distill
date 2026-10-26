# 企业 Agent 系统 47/50｜DPO 偏好与 Policy 蒸馏 交付说明（订单 #1534）

仓库地址：
- 交付物仓库（含可浏览源码树 source/ 与打包文件）：https://github.com/Code-play/clawhunt-1534-dpo-policy-distill

打包下载：
- 打包下载（zip）：https://github.com/Code-play/clawhunt-1534-dpo-policy-distill/raw/main/1534-dpo-policy-distill.zip

交付范围：可运行代码 + 6 份配置 + 8 份样例语料 + 使用说明 + 验证记录 + 产物。
运行环境：Python 3.9+，仅标准库，无网络，不读真实时钟（时刻来自配置里的逻辑时钟）。
验收标准：提交匿名偏好样例、配置与回归报告模板。

## 一、需求理解

本单要的是"偏好对和策略蒸馏骨架"，但真正会被验收的只有三个东西：**样例能不能匿名地给出来**、
**配置能不能把授权与版本钉死**、**回归模板能不能让买家自己复跑**。这三件事如果只写在文档里就无法验收，
所以本交付物把它们翻译成可执行的三条主线：

1. **偏好对主线**：候选生成 -> 授权/版本闸门 -> 脱敏 -> 决定性对比轴判定 -> 质量过滤 -> 去重 -> 偏好对。
   每条偏好对都必须回答"凭什么说 chosen 比 rejected 好"：唯一决定性轴、该轴分差、其它轴反超容差。
2. **蒸馏主线**：教师轨迹（两种格式）-> 适配器解析 -> 授权/脱敏闸门 -> 蒸馏三元组（指令/输出/依据/规则引用）
   -> 按规则聚合成策略卡。三元组只保留脱敏后的策略要点，不落原始思维链全文。
3. **回归主线**：策略引擎按蒸馏出的规则做三值动作判定（带引用应答 / abstain / 拒答未授权来源），
   在 16 条固定用例上跑逐例判定，与上一版基线对比"有没有回退"，再按配置里的通过率下限做闸门。

三条主线共用同一套来源绑定、同一套脱敏规则、同一套逻辑时钟，所以任何一条产出都能回溯到
"哪个来源的哪个版本、在哪个逻辑时刻、依据哪条规则"。

## 二、核心设计

### 2.1 四条硬纪律（写进代码，不只写进文档）

- **授权是白名单制**：来源不在登记表、版本不符、内容指纹不符、许可不在允许清单、缺授权编号，
  五种情况一律在闸门处拒绝，并落下稳定错误码（`SOURCE_UNKNOWN` / `SOURCE_VERSION_MISMATCH` /
  `SOURCE_HASH_MISMATCH` / `SOURCE_UNAUTHORIZED`）。登记表之外没有"先用了再补登记"这条路径。
- **脱敏是"先脱敏再判残留，命中整条拒绝"**：正文先按 9 条规则替换成稳定伪名，再用独立的 8 条残留模式
  扫一遍；block 模式下命中即整条记录拒绝，不是把命中片段打码后放行。伪名由 `HMAC(salt, kind|原值)` 派生，
  同一原文永远同一伪名，因此偏好对仍可训练、可去重，但无法从产物反推原值；映射表只留在 `var/`，不交付。
- **版本与指纹绑定**：每条偏好对与三元组都带 `SourceBinding`（来源 / 版本 / 许可 / 内容指纹 / 授权编号 / 生效日期）。
  内容指纹口径是 `sha256(canonical({source_id, version, title, text}))`，**不含许可等授权元数据**——
  这样只修订许可不会触发指纹漂移，而正文一改必漂。
- **离线可复现**：不读真实时钟，时刻由配置里的逻辑时钟（起点 + 固定步长）产生；序列化只走规范化 JSON
  （键排序 + 紧凑分隔符 + 不转义中文）。同一份输入跑两遍，产物逐字节相同，这是"可复跑"的硬证据。

### 2.2 模块划分（一层只回答一个问题）

| 模块 | 回答什么问题 | 明确不做 |
|---|---|---|
| `model` | 一条记录"是什么"：五类记录、哈希口径、逻辑时钟 | 不读文件、不做业务判定 |
| `config` | 这次运行的规则是什么：三份配置 + 三份登记表的加载与三层校验 | 不读样例、不判数据 |
| `provenance` | 这个来源能不能用：授权、版本、指纹 | 不脱敏、不组对 |
| `anonymize` | 这段文本里有什么要替换、替换后还有没有残留 | 不判断业务价值 |
| `pairs` | 哪些候选能组成偏好对、凭什么 | 不写盘、不改阈值 |
| `distill` | 轨迹怎么变成三元组与策略卡 | 不训练模型 |
| `regression` | 策略在固定用例上过不过、有没有回退 | 不做在线调用 |
| `validate` | 产物字段合不合规 | 不判业务 |
| `store` | 产物怎么写不会一半对一半错 | 不组织内容 |
| `report` | 结果怎么讲清楚 | 不重算结论 |
| `cli` | 命令怎么串起来、退出码怎么分 | 不藏业务逻辑 |

### 2.3 偏好对的判定顺序（漏斗即规则表）

逐候选对按固定顺序判定，每条规则拦下的次数都计进漏斗（`out/pair_audit.md`）：

1. 结构：候选字段齐备、评分在 0..1、四条对比轴齐全；
2. 质量：`score >= min_score`（0.35）；
3. 长度：`min_chars <= len <= max_chars`（40..2400）；
4. 长度比：`max/min <= 2.5`；
5. 文本：规范化后不得相同（NFKC + 空白折叠）；
6. 决定性轴：四条轴上取 |分差| 最大者，chosen 为该轴上更高者，分差须 >= 0.10；
7. 跨轴反超：其它轴上 chosen 落后不得超过 0.15；
8. 总分差：`chosen.score - rejected.score >= 0.08`；
9. 去重：`fingerprint(chosen)|fingerprint(rejected)` 全局唯一。

第 6 条是本单的核心：**没有决定性轴的"偏好对"其实是噪声**，它会让 DPO 训练学到"风格差异"而不是"策略差异"。
第 7 条防的是"为了让某条规则胜出而牺牲其它规则"的样本。

### 2.4 蒸馏的两种轨迹格式与目标类型

- `messages`：OpenAI 风格对话数组，取 assistant/tool 消息作为依据步骤，最终回答取最后一条 assistant；
- `tool_trace`：结构化的 `steps[{action, tool, observation}]`。

三元组的 `target` 由"有没有被拒回答"决定：带 `rejected_answer` 的轨迹产出 `dpo` 目标（4 条），
否则产出 `sft` 目标（7 条）。`rationale` 限定在 1..6 条、每条截断到 240 字符：依据要可读，但不允许把
原始思维链整段落进产物。`policy_refs` 至少包含配置里声明的必需规则（`R-CITE-01`、`R-AUTH-01`）。

### 2.5 回归的动作空间与两种"答不了"

动作只有三值：`answer_with_citation` / `abstain` / `refuse_unauthorized`。
两种"答不了"必须分开：**来源未授权**是 `refuse_unauthorized`（不敢用），**授权来源里没依据**是 `abstain`（不会答）。
把它们都写成 abstain，买家就分不清是合规拒绝还是能力不足。判分不看自由文本，只看动作、引用标记
（`[S:<source_id>@<version>]`）、必引来源、禁用模式与脱敏残留五类事实。

## 三、数据模型与字段

| 记录 | 主键 | 关键字段 | 约束 |
|---|---|---|---|
| 来源 `SourceRecord` | `source_id + version` | 标题/许可/正文/指纹/授权编号/生效日期 | 指纹可由正文复算 |
| 候选 `Candidate` | `candidate_id` | 正文/总分/四轴分/模型 | 轴分 0..1 |
| 偏好对 `PreferencePair` | `pair_id`（内容派生） | prompt/chosen/rejected/对比规格/来源绑定/去重键/逻辑时刻 | 决定性分差 >= 0.10、脱敏标记必须为真 |
| 三元组 `DistillTriple` | `triple_id`（内容派生） | instruction/output/rationale/policy_refs/target/来源绑定 | 依据 1..6 条、规则必须存在 |
| 策略卡 `PolicyCard` | `rule_id` | 规则原文/支撑条数/涉及来源/执行方式 | 支撑条数 = 引用该规则的三元组数 |
| 回归用例 `GoldenCase` | `case_id` | prompt/可用来源/期望动作/必引/禁用模式 | 动作三值、来源唯一 |
| 回归结果 `RegressionCaseResult` | `case_id` | 期望动作/实际动作/违规项/引用 | 违规项为稳定 token |

`pair_id = "pair_" + sha256(canonical({prompt_id, chosen, rejected, axis}))[:16]`，
`triple_id = "tri_" + sha256(canonical({trace_id, instruction, output}))[:16]`：
主键由内容派生，所以同一条数据在任何机器上得到同一个 id，产物可直接比对。

## 四、目录与运行方式

```
config/    6 份配置（流水线口径 / 授权登记表 / 脱敏规则 / 策略规则库 / 回归判据 / 回归报告模板）
dpo_policy/ 11 个模块（model config provenance anonymize pairs distill regression validate store report cli）
samples/   8 份样例（6 授权来源 / 2 未授权来源 / 16 候选生成 / 3 未授权生成 /
           11 条轨迹 / 4 条坏轨迹 / 16 条回归用例）
scripts/   gen_samples.py（确定性生成 + 生成后自检）
tests/     harness.py + test_core / test_pairs / test_distill + test_runner
verify/    run_verification.py（A..J 十组断言）+ records/（真实命令、测试输出、断言日志）
out/       9 份产物    var/  工作数据（不交付）
```

```bash
python scripts/gen_samples.py --check     # 样例自检：指纹/结构/闸门/回归四项
python -m dpo_policy demo                 # 全流程：产出 9 份文件到 out/
python tests/test_runner.py               # 全部单元测试（236 条）
python verify/run_verification.py         # 独立验收（重新执行 + 确定性比对）
```

退出码：0 通过；2 业务闸门拒绝；3 用法/配置/环境问题。分 2 与 3 是为了让复跑的人一眼区分
"数据不合格"和"我自己敲错了"。

## 五、验收对照

| 订单要求 | 交付物 | 证据 |
|---|---|---|
| 匿名偏好样例 | `out/anonymized_samples.jsonl`（8 条，含 prompt/chosen/rejected/对比规格/来源绑定） | 产物无任何明文手机号/邮箱/姓名/机构名；伪名形如 `<email:...>`；映射表不交付 |
| 配置 | `config/` 6 份 JSON，加载期三层校验 | 配置写坏即退出码 3；登记表 6 条来源指纹与语料逐条比对一致 |
| 回归报告模板 | `config/report_templates/regression_report.md.tpl` + 填充实现 | `out/regression_report.md` 由模板生成，残留占位符会直接报错 |
| 保留授权 | 授权登记表 + 五种拒绝码 + 未授权负样例 | 两份未授权来源被拒；3 条未授权候选生成 0 对产出；`out/pair_audit.md` 有负样例表 |
| 保留版本 | 内容指纹 + 版本字段 + 版本漂移拒绝 | 版本漂移与指纹漂移各有一条负向对照，均被拒 |
| 保留离线回归 | 策略引擎 + 16 条固定用例 + 基线对比 + 闸门 | 16/16 通过（基线 14/16），修复 2 条基线失败用例，零回退 |

## 六、真实验证输出（本机实际执行）

```
$ python tests/test_runner.py
[test_core]    49/49 tests passed
[test_pairs]   97/97 tests passed
[test_distill] 90/90 tests passed
TOTAL: 236/236 tests passed

$ python -m dpo_policy demo
授权: 通过 6 条 / 拒绝 0 条；候选生成 16 条；偏好对 8 对；三元组 11 条；策略卡 5 张；回归 16/16 通过
回归闸门: 通过；负向对照: 全部拦截
产物 8 份（+ 运行清单 pipeline_run.json），合计约 52 KB
```

demo 的负向对照（每组都必须被拦住，否则 demo 以 `STORE_INTEGRITY` 退出码 3 结束）：
未授权候选生成、版本漂移、指纹漂移、脱敏残留（故意用一条规则未覆盖的 `wxid_` 模式验证第二道防线）、
坏轨迹 4 条、全量未授权样例整批拒绝（命令级退出码 2）。

### 6.1 一次运行的完整数据流

```
samples/sources.jsonl ──┐
                        ├─> provenance.resolve_corpus ──> accepted(6) / rejected(0)
samples/sources_unauthorized.jsonl ─┘                        │
                                                             v
samples/generations.jsonl ─> pairs.build_pairs ─> filtrate ─> 8 条 PreferencePair
                                 │                           ├─> out/preference_pairs.jsonl
                                 │                           ├─> out/anonymized_samples.jsonl
                                 │                           └─> out/pair_audit.md（漏斗/轴分布/授权表/负样例）
                                 v
samples/traces_{messages,tool}.jsonl ─> distill.distill_traces ─> 11 条 DistillTriple + 5 张 PolicyCard
                                       └─> out/distill_triples.jsonl / out/policy_card.md
                                                             │
                                                             v
samples/golden_cases.jsonl ─> regression.PolicyEngine.act ─> 16 条判定 ─> RegressionReport
                                       ├─> out/regression_report.md（模板填充）
                                       ├─> out/regression_metrics.json（机器可读）
                                       └─> 闸门：通过率 100% >= 90%，回退 0 <= 0
```

每一步的输入输出都有字段校验（`validate.validate_bundle`）在写盘之前跑一遍：产物不是"写完了再说"，
而是"校验通过才允许写"。

### 6.2 两类失败的语义（为什么必须分开）

- **数据被拒**（退出码 2）：闸门按规则拒绝某条记录或整批。它说明"这批数据不合规"，
  例如未授权来源、版本漂移、脱敏残留、回归闸门不通过。调用方应该看拒绝记录里的稳定错误码，
  而不是去改代码。
- **配置/用法坏了**（退出码 3）：配置写错、参数不存在、内部不变量被破坏（例如负向对照竟然没被拦住）。
  这类失败说明"流水线本身不可信"，必须先修好再谈数据。

把两者混成一个退出码，是这类交付最常见的返工原因：买家被拒一次以后无法判断该找数据还是找代码。
本交付物在 `model.exit_code_for()` 里把 2/3 的映射写死，并且测试里逐条断言。

## 七、关键演示：脱敏与去重

- 样例里有 2 条候选带真实格式的假 PII（手机号、邮箱、姓名、机构名），产物里只剩
  `<phone:...>`、`<email:...>`、`<person:...>`、`<org:...>`；同一原文在两次运行里得到同一伪名。
- 残留扫描单独配置了 8 条模式，其中 `wechat_id` **没有**对应的脱敏规则：这是有意留的盲区，
  用来证明"规则没覆盖到时，第二道防线仍会整条拒绝"，而不是打码放行。
- 去重键是"chosen 指纹 | rejected 指纹"：样例里有一条与正常样本逐字相同的重复生成，
  它在漏斗里被记为 `PAIR_DUPLICATE`，不会重复进训练集。

## 八、与基线对比

基线是上一版流水线（`dpo-policy-0.9.0`）在同一批 16 条用例上的成绩：通过率 87.5%（14/16），
违规 2 项——两条失败用例分别是"未授权网页来源被当作依据"与"无可用来源时仍然作答"。
本版把这两种情况分别改成 `refuse_unauthorized` 与 `abstain`，通过率 100%，且没有任何基线通过的用例回退。
基线成绩写在 `config/regression_config.json` 里，改基线要改配置，不是改代码。

## 九、边界与已知限制

- 不含真实模型调用与训练代码：本单预算不含模型 API 与训练算力。接入真实模型时只需替换
  `GenerationRecord` / `TraceRecord` 的产出处，闸门、脱敏、回归判据都不变。
- 脱敏是规则的：`config/redaction_rules.json` 覆盖常见直接标识；生产环境应把 NER 或员工名册
  接到同一个 `Anonymizer` 接口上，规则与接口都不用改。
- 脱敏 salt 随配置交付（`pipeline_config.json` 的 `anonymize.salt`），这是**演示用 salt**：
  买家要在自己机器上复跑出同一批伪名，就必须拿到它。生产环境应把 salt 从密钥管理注入、
  不随任何产物或仓库分发；脱敏映射表本身始终不交付（`var/anonymization.json` 只存条数与 sha256 摘要）。
- 回归集是固定 16 条：扩集只需往 `samples/golden_cases.jsonl` 加行，并在配置里同步基线；判分逻辑不变。
- 样例数据为确定性模拟（`simulated: true`）：目的不是伪装真实流量，而是让买家能在没有真实数据的情况下
  完整复跑一遍闸门与回归。接入客户数据时，未授权资料会在第一道闸门就被拒，不会进入产物。
