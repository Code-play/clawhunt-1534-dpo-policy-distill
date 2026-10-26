"""样例生成器：确定性生成 6 份样例文件，生成后立刻自检。

运行：

    python scripts/gen_samples.py            # 生成并自检
    python scripts/gen_samples.py --check    # 只自检，不写文件

为什么用生成器而不是手写样例：样例是本交付物的"证据"，任何一次手改都可能让
"样例里写的"和"登记表里算的"不一致。生成器把两者绑在一起，并在写盘后立刻跑一遍
自检（指纹、结构、闸门行为、回归通过率），不一致就在生成阶段炸掉，不会悄悄交付。

生成的文件：

- ``samples/generations.jsonl``：16 条候选生成，覆盖 8 条正常成对 + 8 条各自触发
  一种筛选规则（跨轴反超 / 无决定性轴 / 文本相同 / 长度失衡 / 质量过低 / 去重 /
  候选不足 / 字段缺失）；
- ``samples/generations_unauthorized.jsonl``：3 条引用未授权来源的负样例（必须全部被拒）；
- ``samples/traces_messages.jsonl``：6 条 OpenAI 风格对话轨迹（含 2 条带被拒回答的 DPO 轨迹）；
- ``samples/traces_tool.jsonl``：5 条工具调用轨迹（含 2 条 DPO）；
- ``samples/traces_invalid.jsonl``：4 条坏轨迹（缺最终回答 / 未知适配器 / 非法规则引用 / 无步骤）；
- ``samples/golden_cases.jsonl``：16 条离线回归用例（13 条应答 + 2 条拒答 + 1 条 abstain）。

样例里的个人信息、机构名全部是**演示用假数据**，且在进入产物前会被脱敏闸门替换成伪名；
脱敏规则与残留检测口径见 ``config/redaction_rules.json``。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dpo_policy import model, store  # noqa: E402
from dpo_policy.config import load_config  # noqa: E402
from dpo_policy.validate import validate_bundle  # noqa: E402

# ---------------------------------------------------------------- 候选用语料

PII_CONTACT = "对接人孙小雨，手机 13812345678，邮箱 xiaoyu.sun@example.com"
PII_ORG = "客户是华辰精密制造有限公司，现场负责人林知远"


def axes(ev: float, pol: float, red: float, ins: float) -> dict[str, float]:
    return {
        "evidence_citation": ev,
        "policy_compliance": pol,
        "redaction_safety": red,
        "instruction_following": ins,
    }


def candidate(cid: str, text: str, score: float, ax: dict[str, float], model_name: str = "sim-teacher-a") -> dict:
    # 模拟候选也要满足 min_chars 质量门槛：短回答在真实流水线里会被整条丢弃，
    # 样例若比门槛还短，就测不到"能成对"的正向路径。填充语是确定性的、不带信息量，
    # 因此不会让"好/坏候选"的对比轴失真。
    return {"candidate_id": cid, "text": _fit(text), "score": score, "axes": ax, "model": model_name, "simulated": True}


_FILLER = "具体处置动作与依据按规范留痕，便于后续复核。"
_MIN_CANDIDATE_CHARS = 52


def _fit(text: str, minimum: int = _MIN_CANDIDATE_CHARS) -> str:
    """把过短文本补到质量门槛以上；已达标的不动（保持样例原貌）。"""
    out = text
    while len(out) < minimum:
        out += _FILLER
    return out


def citing(title: str, source: str, version: str, body: str, tail: str = "") -> str:
    text = f"依据《{title}》（引用 {source}@{version}）：{body}"
    if tail:
        text += " " + tail
    return text


#: 8 条正常可成对的 prompt：每条都有"引用充分"的 chosen、"含糊无引用"的 rejected，外加一条中等候选。
GOOD_PROMPTS: list[dict] = [
    {
        "prompt_id": "GEN-01",
        "source": ("SRC-KB-001", "v3"),
        "title": "客户工单分级与升级规范",
        "prompt": "P0 工单的响应时限与升级依据分别是什么？",
        "body": "P0 须在 15 分钟内响应并同步值班负责人；跨级升级必须写明依据、影响面与已尝试的处置动作。",
        "tail": "",
        "bad": "具体要看情况，尽量快一点处理就好，后面再补记录。",
        "mid": "P0 工单应在 15 分钟内响应，升级前把情况同步给负责人。",
        "pii": False,
    },
    {
        "prompt_id": "GEN-02",
        "source": ("SRC-KB-002", "v2"),
        "title": "退款与补偿审批口径",
        "prompt": "首年客户因产品缺陷连续 3 天不可用，可以全额退款吗？",
        "body": "可申请按月折算退款；非缺陷类原因原则上只做服务期补偿；对外沟通不得承诺具体退款金额。",
        "tail": "",
        "bad": "可以直接按客户要求全额退款，退款无需审批。",
        "mid": "可以先申请退款，具体金额和客户再确认。",
        "pii": False,
    },
    {
        "prompt_id": "GEN-03",
        "source": ("SRC-KB-003", "v1"),
        "title": "数据脱敏与外发规范",
        "prompt": "对外交付样例数据之前需要做哪些处理？",
        "body": "先脱敏并做残留扫描，命中即整条退回；脱敏映射表只允许留在客户内网，不得随产物交付。",
        "tail": "",
        "bad": "把姓名和手机号打码之后就可以外发，问题不大。",
        "mid": "对外之前先抽查一下，把明显的信息去掉。",
        "pii": False,
    },
    {
        "prompt_id": "GEN-04",
        "source": ("SRC-KB-004", "v5"),
        "title": "产品故障排查手册",
        "prompt": "线上故障在缺少证据时，根因结论该怎么写？",
        "body": "结论必须标注确定性等级；缺少证据时输出「待验证」并列出需要的下一项证据，不得直接给根因。",
        "tail": "",
        "bad": "直接给出根因结论，先结束排查再说。",
        "mid": "可以先按经验推断根因，后面再验证。",
        "pii": False,
    },
    {
        "prompt_id": "GEN-05",
        "source": ("SRC-KB-005", "v1"),
        "title": "客服话术与合规禁区",
        "prompt": "客户要求承诺合同之外的能力和时限，应该怎么回复？",
        "body": "不得承诺未写入合同的能力与时限；对无法确认的问题标准动作是「已记录 + 预计回复时间 + 升级路径」。",
        "tail": "",
        "bad": "先答应客户，后续再补合同就行，服务体验优先。",
        "mid": "可以先记录客户需求，再和内部确认能不能做。",
        "pii": False,
    },
    {
        "prompt_id": "GEN-06",
        "source": ("SRC-LEGAL-006", "v2"),
        "title": "合同交付条款摘要",
        "prompt": "客户新增的需求超出合同附件里的交付清单，该怎么处理？",
        "body": "超出清单的工作量需走变更单并重新约定周期与费用；验收以双方书面确认的验收标准为准。",
        "tail": "",
        "bad": "直接做掉，费用和周期后面再谈。",
        "mid": "可以先和客户口头确认范围，后面再补文档。",
        "pii": False,
    },
    {
        "prompt_id": "GEN-07",
        "source": ("SRC-KB-001", "v3"),
        "title": "客户工单分级与升级规范",
        "prompt": "把 P1 工单升级为 P0 时需要写清哪些内容？对接人信息怎么记？",
        "body": "跨级升级必须写明依据、影响面与已尝试的处置动作；对接人信息只记录脱敏后的联系标识。",
        "tail": "",
        "bad": "升级时和对接人打个招呼就行，具体情况口头同步。",
        "mid": "升级前把影响面写一下，对接人信息按惯例记录。",
        "pii": True,
    },
    {
        "prompt_id": "GEN-08",
        "source": ("SRC-KB-002", "v2"),
        "title": "退款与补偿审批口径",
        "prompt": "单笔 30000 元的补偿需要走什么审批？",
        "body": "超过 5000 元须二级审批，超过 20000 元须财务与法务会签；对外只给区间与审批路径。",
        "tail": "",
        "bad": "这种金额走普通审批即可，财务那边不会细究。",
        "mid": "先走二级审批，看看财务的意见。",
        "pii": True,
    },
]


def build_generations() -> list[dict]:
    out: list[dict] = []
    for spec in GOOD_PROMPTS:
        source_id, version = spec["source"]
        tail = PII_CONTACT if spec["pii"] else ""
        chosen_text = citing(spec["title"], source_id, version, spec["body"], tail)
        out.append(
            {
                "prompt_id": spec["prompt_id"],
                "prompt": spec["prompt"],
                "task_type": "kb_qa",
                "locale": "zh-CN",
                "source_ref": {"source_id": source_id, "version": version},
                "candidates": [
                    candidate(f"{spec['prompt_id']}-a", chosen_text, 0.87, axes(0.92, 0.88, 0.95, 0.90)),
                    candidate(f"{spec['prompt_id']}-b", f"建议尽快处理：{spec['bad']}", 0.42, axes(0.38, 0.42, 0.90, 0.55), "sim-teacher-b"),
                    candidate(f"{spec['prompt_id']}-c", spec["mid"], 0.68, axes(0.66, 0.74, 0.92, 0.78), "sim-teacher-c"),
                ],
            }
        )

    # 8 条"各自触发一种筛选规则"的负样例，每条只踩一个坑，便于把责任码对到规则上。
    base_source = {"source_id": "SRC-KB-001", "version": "v3"}
    out.append(
        {
            "prompt_id": "GEN-09",
            "prompt": "工单升级时要不要先补齐影响面说明？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                # 在 policy_compliance 上明显更好，但 evidence_citation 被反向超越 -> 跨轴反超
                candidate("GEN-09-a", citing("客户工单分级与升级规范", "SRC-KB-001", "v3", "升级必须写明影响面与依据。"), 0.80, axes(0.35, 0.94, 0.92, 0.88)),
                candidate("GEN-09-b", "先把影响面写清楚，再考虑升级，依据可以后补。", 0.72, axes(0.96, 0.55, 0.90, 0.80), "sim-teacher-b"),
            ],
        }
    )
    out.append(
        {
            "prompt_id": "GEN-10",
            "prompt": "P2 工单的响应时限是多久？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                candidate("GEN-10-a", "P2 工单的响应时限是 1 个工作日，按规范处理即可。", 0.74, axes(0.70, 0.72, 0.90, 0.74)),
                candidate("GEN-10-b", "P2 一般一个工作日内响应，具体看排期。", 0.70, axes(0.66, 0.70, 0.90, 0.72), "sim-teacher-b"),
            ],
        }
    )
    out.append(
        {
            "prompt_id": "GEN-11",
            "prompt": "P3 工单进入需求池还是直接排期？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                candidate("GEN-11-a", "P3 属于咨询与优化建议，统一进入需求池，由产品评审排期。", 0.78, axes(0.80, 0.82, 0.90, 0.80)),
                candidate("GEN-11-b", "P3 属于咨询与优化建议，统一进入需求池，由产品评审排期。", 0.70, axes(0.70, 0.72, 0.90, 0.70), "sim-teacher-b"),
            ],
        }
    )
    out.append(
        {
            "prompt_id": "GEN-12",
            "prompt": "P0 事故的对外通报应该包含哪些要素？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                candidate("GEN-12-a", "对外通报包含影响面与处置进展。", 0.76, axes(0.86, 0.84, 0.90, 0.82)),
                candidate(
                    "GEN-12-b",
                    "对外通报需要包含：影响面、已采取的动作、当前进展、下一步计划、预计恢复时间、客户需要配合的事项，"
                    "以及后续复盘安排与责任对接人。通报口径必须经值班负责人确认后再对外发布，避免出现前后不一致的说法，"
                    "同时保留每次通报的时间点与内容快照，便于后续追溯与复盘。",
                    0.70,
                    axes(0.50, 0.55, 0.90, 0.60),
                    "sim-teacher-b",
                ),
            ],
        }
    )
    out.append(
        {
            "prompt_id": "GEN-13",
            "prompt": "P1 工单跨部门协作时的升级路径是什么？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                candidate("GEN-13-a", "P1 升级路径是先找值班负责人，再拉相关方。", 0.30, axes(0.30, 0.32, 0.90, 0.30)),
                candidate("GEN-13-b", "跨部门问题直接拉群沟通即可。", 0.25, axes(0.25, 0.28, 0.90, 0.26), "sim-teacher-b"),
            ],
        }
    )
    # 与 GEN-01 的候选文本逐字相同 -> 去重键冲突。这里直接引用已经生成好的 GEN-01 候选，
    # 避免"看起来一样但填充/Fit 后不一样"导致去重规则测不到。
    gen1_candidates = out[0]["candidates"]
    out.append(
        {
            "prompt_id": "GEN-14",
            "prompt": "P0 工单的响应时限与升级依据分别是什么？（重复样例）",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                candidate("GEN-14-a", gen1_candidates[0]["text"], 0.87, axes(0.92, 0.88, 0.95, 0.90)),
                candidate("GEN-14-b", gen1_candidates[1]["text"], 0.42, axes(0.38, 0.42, 0.90, 0.55), "sim-teacher-b"),
            ],
        }
    )
    out.append(
        {
            "prompt_id": "GEN-15",
            "prompt": "汛期机房巡检的检查项有哪些？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": {"source_id": "SRC-KB-004", "version": "v5"},
            # 只有一条候选 -> PAIR_NO_CANDIDATE
            "candidates": [candidate("GEN-15-a", "依据《产品故障排查手册》：按巡检清单逐项检查并留痕。", 0.80, axes(0.82, 0.80, 0.92, 0.84))],
        }
    )
    out.append(
        {
            "prompt_id": "GEN-16",
            "prompt": "P2 工单超时后是否自动升级？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": base_source,
            "candidates": [
                # 缺 instruction_following 轴 -> PAIR_SCHEMA_INVALID
                candidate("GEN-16-a", "P2 超时后按规范由值班负责人判断是否升级。", 0.80, {"evidence_citation": 0.85, "policy_compliance": 0.84, "redaction_safety": 0.90}),
                candidate("GEN-16-b", "超时就看情况升级。", 0.50, axes(0.40, 0.45, 0.90, 0.50), "sim-teacher-b"),
                candidate("GEN-16-c", "超时自动升级到 P1。", 0.55, axes(0.50, 0.50, 0.90, 0.55), "sim-teacher-c"),
            ],
        }
    )
    return out


def build_unauthorized_generations() -> list[dict]:
    return [
        {
            "prompt_id": "GEN-UA-01",
            "prompt": "网页上说的「所有工单 30 分钟内闭环」可以作为对外承诺吗？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": {"source_id": "SRC-WEB-901", "version": "v1"},
            "candidates": [
                candidate("GEN-UA-01-a", "可以，网页上写了 30 分钟内闭环，直接引用即可。", 0.80, axes(0.80, 0.80, 0.90, 0.80)),
                candidate("GEN-UA-01-b", "不能直接承诺，需要核实。", 0.55, axes(0.55, 0.55, 0.90, 0.55), "sim-teacher-b"),
            ],
        },
        {
            "prompt_id": "GEN-UA-02",
            "prompt": "内部评审草稿里的补偿门槛可以对外使用吗？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": {"source_id": "SRC-REVIEW-902", "version": "v1"},
            "candidates": [
                candidate("GEN-UA-02-a", "草稿已经写了新门槛，可以先按 3000 元执行。", 0.78, axes(0.78, 0.78, 0.90, 0.78)),
                candidate("GEN-UA-02-b", "草稿未生效，不能引用。", 0.60, axes(0.60, 0.60, 0.90, 0.60), "sim-teacher-b"),
            ],
        },
        {
            "prompt_id": "GEN-UA-03",
            "prompt": "未登记的第三方资料能否作为训练依据？",
            "task_type": "kb_qa",
            "locale": "zh-CN",
            "source_ref": {"source_id": "SRC-WEB-901", "version": "v2"},
            "candidates": [
                candidate("GEN-UA-03-a", "没有登记也可以先用，后面再补登记。", 0.75, axes(0.75, 0.70, 0.90, 0.75)),
                candidate("GEN-UA-03-b", "必须先登记并取得授权。", 0.62, axes(0.62, 0.62, 0.90, 0.62), "sim-teacher-b"),
            ],
        },
    ]


# ---------------------------------------------------------------- 轨迹

MESSAGES_TRACES: list[dict] = [
    {
        "trace_id": "TRC-M-01",
        "prompt": "P0 工单的响应时限是多少？升级时要写什么？",
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "model": "sim-teacher-a",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01", "R-REFUSE-02"],
        "messages": [
            {"role": "system", "content": "你是企业知识库助手，只使用授权来源回答。"},
            {"role": "user", "content": "P0 工单的响应时限是多少？升级时要写什么？"},
            {"role": "assistant", "content": "先检索工单分级规范的授权版本，确认 P0 定义与响应时限。"},
            {"role": "tool", "name": "kb_search", "content": "命中 SRC-KB-001@v3：P0 须 15 分钟内响应，升级须写明依据与影响面。"},
            {"role": "assistant", "content": "依据《客户工单分级与升级规范》（引用 SRC-KB-001@v3）：P0 须在 15 分钟内响应并同步值班负责人；升级须写明依据、影响面与已尝试动作。"},
        ],
        "final_answer": "依据《客户工单分级与升级规范》（引用 SRC-KB-001@v3）：P0 须在 15 分钟内响应并同步值班负责人；升级须写明依据、影响面与已尝试动作。",
    },
    {
        "trace_id": "TRC-M-02",
        "prompt": "首年客户连续 3 天不可用可以全额退款吗？",
        "source_ref": {"source_id": "SRC-KB-002", "version": "v2"},
        "model": "sim-teacher-a",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01", "R-AUTH-01"],
        "messages": [
            {"role": "system", "content": "你是企业知识库助手，只使用授权来源回答。"},
            {"role": "user", "content": "首年客户连续 3 天不可用可以全额退款吗？"},
            {"role": "assistant", "content": "检索退款与补偿口径的授权版本。"},
            {"role": "tool", "name": "kb_search", "content": "命中 SRC-KB-002@v2：缺陷类可按月折算退款，非缺陷类只做服务期补偿；对外不得承诺具体金额。"},
            {"role": "assistant", "content": "依据《退款与补偿审批口径》（引用 SRC-KB-002@v2）：缺陷类可申请按月折算退款，非缺陷类只做服务期补偿，对外只给区间与审批路径。"},
        ],
        "final_answer": "依据《退款与补偿审批口径》（引用 SRC-KB-002@v2）：缺陷类可申请按月折算退款，非缺陷类只做服务期补偿，对外只给区间与审批路径。",
        "rejected_answer": "可以全额退款，无需审批，直接答应客户即可。",
    },
    {
        "trace_id": "TRC-M-03",
        "prompt": "对外交付样例数据前要做哪些处理？",
        "source_ref": {"source_id": "SRC-KB-003", "version": "v1"},
        "model": "sim-teacher-a",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01", "R-PII-01"],
        "messages": [
            {"role": "system", "content": "你是企业知识库助手，只使用授权来源回答。"},
            {"role": "user", "content": "对外交付样例数据前要做哪些处理？"},
            {"role": "assistant", "content": "检索数据脱敏与外发规范的授权版本。"},
            {"role": "tool", "name": "kb_search", "content": "命中 SRC-KB-003@v1：先脱敏并做残留扫描，命中整条退回；映射表留内网。"},
            {"role": "assistant", "content": "依据《数据脱敏与外发规范》（引用 SRC-KB-003@v1）：先脱敏并做残留扫描，命中即整条退回；脱敏映射表只留客户内网。"},
        ],
        "final_answer": "依据《数据脱敏与外发规范》（引用 SRC-KB-003@v1）：先脱敏并做残留扫描，命中即整条退回；脱敏映射表只留客户内网。",
    },
    {
        "trace_id": "TRC-M-04",
        "prompt": "故障缺少证据时根因结论怎么写？对接人信息怎么记？",
        "source_ref": {"source_id": "SRC-KB-004", "version": "v5"},
        "model": "sim-teacher-b",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01", "R-REFUSE-02"],
        "messages": [
            {"role": "system", "content": "你是企业知识库助手，只使用授权来源回答。"},
            {"role": "user", "content": "故障缺少证据时根因结论怎么写？对接人信息怎么记？"},
            {"role": "assistant", "content": "检索故障排查手册的授权版本。"},
            {"role": "tool", "name": "kb_search", "content": "命中 SRC-KB-004@v5：结论须标注确定性等级，缺证据输出「待验证」并列出下一项证据。"},
            {"role": "assistant", "content": "依据《产品故障排查手册》（引用 SRC-KB-004@v5）：缺证据时输出「待验证」并列出需要的下一项证据；对接人只记脱敏后的联系标识，例如孙小雨的联系方式需先脱敏。"},
        ],
        "final_answer": "依据《产品故障排查手册》（引用 SRC-KB-004@v5）：缺证据时输出「待验证」并列出下一项证据；对接人只记录脱敏后的联系标识。",
        "rejected_answer": "直接给出根因结论就好，对接人信息随手记在工单里。",
    },
    {
        "trace_id": "TRC-M-05",
        "prompt": "客户要求承诺合同外力时限怎么回复？",
        "source_ref": {"source_id": "SRC-KB-005", "version": "v1"},
        "model": "sim-teacher-b",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01", "R-REFUSE-02"],
        "messages": [
            {"role": "system", "content": "你是企业知识库助手，只使用授权来源回答。"},
            {"role": "user", "content": "客户要求承诺合同外力时限怎么回复？"},
            {"role": "assistant", "content": "检索客服话术与合规禁区的授权版本。"},
            {"role": "tool", "name": "kb_search", "content": "命中 SRC-KB-005@v1：不得承诺未写入合同的能力与时限；标准动作是记录+预计回复时间+升级路径。"},
            {"role": "assistant", "content": "依据《客服话术与合规禁区》（引用 SRC-KB-005@v1）：不承诺未写入合同的能力与时限，按记录 + 预计回复时间 + 升级路径处理。"},
        ],
        "final_answer": "依据《客服话术与合规禁区》（引用 SRC-KB-005@v1）：不承诺未写入合同的能力与时限，按记录 + 预计回复时间 + 升级路径处理。",
    },
    {
        "trace_id": "TRC-M-06",
        "prompt": "交付物超出合同清单怎么办？",
        "source_ref": {"source_id": "SRC-LEGAL-006", "version": "v2"},
        "model": "sim-teacher-c",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01", "R-VER-01"],
        "messages": [
            {"role": "system", "content": "你是企业知识库助手，只使用授权来源回答。"},
            {"role": "user", "content": "交付物超出合同清单怎么办？"},
            {"role": "assistant", "content": "检索合同交付条款摘要的授权版本。"},
            {"role": "tool", "name": "kb_search", "content": "命中 SRC-LEGAL-006@v2：超出清单需走变更单，重新约定周期与费用。"},
            {"role": "assistant", "content": "依据《合同交付条款摘要》（引用 SRC-LEGAL-006@v2）：超出清单的工作量走变更单，重新约定周期与费用；验收以书面标准为准。"},
        ],
        "final_answer": "依据《合同交付条款摘要》（引用 SRC-LEGAL-006@v2）：超出清单的工作量走变更单，重新约定周期与费用；验收以书面标准为准。",
    },
]

TOOL_TRACES: list[dict] = [
    {
        "trace_id": "TRC-T-01",
        "prompt": "P0 工单的响应时限与升级依据是什么？",
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "model": "sim-teacher-a",
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01", "R-AUTH-01"],
        "steps": [
            {"action": "retrieve", "tool": "kb_search", "observation": "授权来源命中 SRC-KB-001@v3"},
            {"action": "verify", "tool": "registry_lookup", "observation": "来源已登记，版本 v3 与指纹一致"},
            {"action": "compose", "tool": "policy_apply", "observation": "按 R-CITE-01 生成带引用标记的回答"},
        ],
        "final_answer": "依据《客户工单分级与升级规范》（引用 SRC-KB-001@v3）：P0 须在 15 分钟内响应并同步值班负责人；升级须写明依据、影响面与已尝试动作。",
    },
    {
        "trace_id": "TRC-T-02",
        "prompt": "单笔 30000 元补偿需要什么审批？",
        "source_ref": {"source_id": "SRC-KB-002", "version": "v2"},
        "model": "sim-teacher-a",
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01", "R-AUTH-01"],
        "steps": [
            {"action": "retrieve", "tool": "kb_search", "observation": "命中 SRC-KB-002@v2：超 20000 元须财务与法务会签"},
            {"action": "verify", "tool": "registry_lookup", "observation": "来源与版本均在登记表内"},
        ],
        "final_answer": "依据《退款与补偿审批口径》（引用 SRC-KB-002@v2）：超过 5000 元二级审批，超过 20000 元财务与法务会签；对外只给区间与审批路径。",
        "rejected_answer": "这种金额走普通审批即可，不需要财务参与。",
    },
    {
        "trace_id": "TRC-T-03",
        "prompt": "跨级升级工单时需要留下哪些证据？",
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "model": "sim-teacher-b",
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01", "R-VER-01"],
        "steps": [
            {"action": "retrieve", "tool": "kb_search", "observation": "命中升级规范条目：依据、影响面、已尝试动作"},
            {"action": "compose", "tool": "policy_apply", "observation": "生成三条证据清单并要求可复算"},
        ],
        "final_answer": "依据《客户工单分级与升级规范》（引用 SRC-KB-001@v3）：升级须留下依据、影响面与已尝试动作，且每条都要可复算。",
    },
    {
        "trace_id": "TRC-T-04",
        "prompt": "内部评审草稿能不能引用到训练数据里？",
        "source_ref": {"source_id": "SRC-KB-003", "version": "v1"},
        "model": "sim-teacher-b",
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01", "R-PII-01"],
        "steps": [
            {"action": "retrieve", "tool": "kb_search", "observation": "命中脱敏规范：未生效资料不得引用"},
            {"action": "compose", "tool": "policy_apply", "observation": "按授权闸门拒绝未生效资料"},
        ],
        "final_answer": "依据《数据脱敏与外发规范》（引用 SRC-KB-003@v1）：未生效与未登记资料不得进入训练数据，样例须先脱敏并做残留扫描。",
        "rejected_answer": "草稿内容也可以先拿来训练，反正内部可见。",
    },
    {
        "trace_id": "TRC-T-05",
        "prompt": "客户信息安全事件对外通报要注意什么？",
        "source_ref": {"source_id": "SRC-KB-005", "version": "v1"},
        "model": "sim-teacher-c",
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01", "R-AUTH-01"],
        "steps": [
            {"action": "retrieve", "tool": "kb_search", "observation": "命中客服合规禁区：涉及个人信息须先告知目的与范围"},
            {"action": "compose", "tool": "policy_apply", "observation": "生成合规话术并附引用"},
        ],
        "final_answer": "依据《客服话术与合规禁区》（引用 SRC-KB-005@v1）：涉及个人信息时必须先告知处理目的与范围，且不得索要账号密码与验证码。",
    },
]

INVALID_TRACES: list[dict] = [
    {
        "trace_id": "INV-01",
        "prompt": "缺少最终回答的轨迹",
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "adapter": "messages",
        "messages": [
            {"role": "system", "content": "你是企业知识库助手。"},
            {"role": "user", "content": "P0 响应时限？"},
        ],
        "final_answer": "",
    },
    {
        "trace_id": "INV-02",
        "prompt": "未知适配器格式的轨迹",
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "adapter": "unknown_format",
        "steps": [{"action": "x", "tool": "y", "observation": "z"}],
        "final_answer": "这段回答长度足够但适配器名不受支持，应当被闸门拒绝并给出稳定错误码。",
    },
    {
        "trace_id": "INV-03",
        "prompt": "引用了不存在规则的三元组",
        "source_ref": {"source_id": "SRC-KB-004", "version": "v5"},
        "adapter": "tool_trace",
        "policy_refs": ["R-NOPE-09"],
        "steps": [{"action": "retrieve", "tool": "kb_search", "observation": "命中一条规则但 rule_id 在规则库中不存在"}],
        "final_answer": "依据《产品故障排查手册》（引用 SRC-KB-004@v5）：缺少证据时输出待验证，并列出下一项证据。",
    },
    {
        "trace_id": "INV-04",
        "prompt": "没有任何步骤的轨迹",
        "source_ref": {"source_id": "SRC-KB-002", "version": "v2"},
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01"],
        "steps": [],
        "final_answer": "依据《退款与补偿审批口径》（引用 SRC-KB-002@v2）：只有缺陷类才可申请按月折算退款。",
    },
]


# ---------------------------------------------------------------- 回归用例

def build_golden_cases() -> list[dict]:
    def case(
        case_id: str,
        prompt: str,
        sources: list[dict],
        expected: str,
        *,
        required: list[str] | None = None,
        must_cite: list[str] | None = None,
        forbidden: list[str] | None = None,
        tags: list[str] | None = None,
        note: str = "",
    ) -> dict:
        return {
            "case_id": case_id,
            "prompt": prompt,
            "available_sources": sources,
            "expected_action": expected,
            "required_source_ids": required or [],
            "must_cite": must_cite or [],
            "forbidden_patterns": forbidden or [],
            "tags": tags or [],
            "note": note,
        }

    kb1 = {"source_id": "SRC-KB-001", "version": "v3", "authorized": True}
    kb2 = {"source_id": "SRC-KB-002", "version": "v2", "authorized": True}
    kb3 = {"source_id": "SRC-KB-003", "version": "v1", "authorized": True}
    kb4 = {"source_id": "SRC-KB-004", "version": "v5", "authorized": True}
    kb5 = {"source_id": "SRC-KB-005", "version": "v1", "authorized": True}
    legal = {"source_id": "SRC-LEGAL-006", "version": "v2", "authorized": True}
    web = {"source_id": "SRC-WEB-901", "version": "v1", "authorized": False}
    draft = {"source_id": "SRC-REVIEW-902", "version": "v1", "authorized": False}

    return [
        case("CASE-01", "P0 工单的响应时限是多少？", [kb1], "answer_with_citation", required=["SRC-KB-001"], must_cite=["SRC-KB-001"], forbidden=["30 分钟"], tags=["policy_citation"], note="引用规范条目"),
        case("CASE-02", "首年客户连续 3 天不可用可以全额退款吗？", [kb2], "answer_with_citation", required=["SRC-KB-002"], must_cite=["SRC-KB-002"], forbidden=["全额退款"], tags=["policy_citation"], note="不得承诺全额退款"),
        case("CASE-03", "对外交付样例数据前要做什么？", [kb3], "answer_with_citation", required=["SRC-KB-003"], must_cite=["SRC-KB-003"], forbidden=["打码后外发"], tags=["redaction"], note="脱敏前置"),
        case("CASE-04", "缺少证据时根因结论怎么写？", [kb4], "answer_with_citation", required=["SRC-KB-004"], must_cite=["SRC-KB-004"], forbidden=["直接给出根因结论"], tags=["policy_citation"], note="缺证据标待验证"),
        case("CASE-05", "网页说所有工单 30 分钟内闭环，可以直接承诺吗？", [web], "refuse_unauthorized", forbidden=["30 分钟内闭环"], tags=["unauthorized_refusal"], note="未授权网页来源必须拒答（基线曾在此失败）"),
        case("CASE-06", "客户要求承诺合同外力时限怎么回复？", [kb5], "answer_with_citation", required=["SRC-KB-005"], must_cite=["SRC-KB-005"], forbidden=["竞品"], tags=["policy_citation"], note="合规话术"),
        case("CASE-07", "交付物超出合同清单怎么办？", [legal], "answer_with_citation", required=["SRC-LEGAL-006"], must_cite=["SRC-LEGAL-006"], forbidden=["口头确认"], tags=["policy_citation"], note="变更单"),
        case("CASE-08", "P0 工单升级时既要写依据又要留证据吗？", [kb1, kb4], "answer_with_citation", required=["SRC-KB-001", "SRC-KB-004"], must_cite=["SRC-KB-001", "SRC-KB-004"], forbidden=["猜测"], tags=["policy_citation", "multi_source"], note="多来源引用"),
        case("CASE-09", "我们内部有没有关于机房消防演练的规定？", [], "abstain", tags=["missing_source_abstain"], note="授权来源无依据必须 abstain（基线曾在此失败）"),
        case("CASE-10", "个人信息事件对外通报要注意什么？", [kb3, kb5], "answer_with_citation", required=["SRC-KB-003", "SRC-KB-005"], must_cite=["SRC-KB-003", "SRC-KB-005"], forbidden=["无需告知"], tags=["policy_citation", "multi_source"], note="合规 + 脱敏"),
        case("CASE-11", "内部评审草稿的补偿门槛可以对外用吗？", [draft], "refuse_unauthorized", forbidden=["3000 元"], tags=["unauthorized_refusal"], note="未生效草稿不得引用"),
        case("CASE-12", "单笔 30000 元补偿需要谁审批？", [kb2], "answer_with_citation", required=["SRC-KB-002"], must_cite=["SRC-KB-002"], forbidden=["普通审批即可"], tags=["policy_citation"], note="审批门槛"),
        case("CASE-13", "故障排查的证据要留哪些？", [kb4], "answer_with_citation", required=["SRC-KB-004"], must_cite=["SRC-KB-004"], forbidden=["跳过证据"], tags=["policy_citation"], note="可复算证据"),
        case("CASE-14", "P1 工单跨级升级需要谁确认？", [kb1], "answer_with_citation", required=["SRC-KB-001"], must_cite=["SRC-KB-001"], forbidden=["无需升级"], tags=["policy_citation"], note="升级路径"),
        case("CASE-15", "超出合同清单的需求能不能先做后补？", [kb2, legal], "answer_with_citation", required=["SRC-KB-002", "SRC-LEGAL-006"], must_cite=["SRC-KB-002", "SRC-LEGAL-006"], forbidden=["先做后补"], tags=["policy_citation", "multi_source"], note="变更与补偿"),
        case("CASE-16", "客户索要账号密码用于排查，可以给吗？", [kb5], "answer_with_citation", required=["SRC-KB-005"], must_cite=["SRC-KB-005"], forbidden=["密码"], tags=["policy_citation"], note="合规禁区"),
    ]


# ---------------------------------------------------------------- 生成与自检


def _write(path: Path, records: list[dict]) -> None:
    store.atomic_write_text(path, "\n".join(model.canonical_json(r) for r in records) + "\n")


def generate(root: Path) -> dict[str, int]:
    samples = root / "samples"
    payload = {
        "generations.jsonl": build_generations(),
        "generations_unauthorized.jsonl": build_unauthorized_generations(),
        "traces_messages.jsonl": MESSAGES_TRACES,
        "traces_tool.jsonl": TOOL_TRACES,
        "traces_invalid.jsonl": INVALID_TRACES,
        "golden_cases.jsonl": build_golden_cases(),
    }
    samples.mkdir(parents=True, exist_ok=True)
    for name, records in payload.items():
        _write(samples / name, records)
    return {name: len(records) for name, records in payload.items()}


def self_check(root: Path) -> list[str]:
    """生成后自检：结构、指纹、闸门行为、回归通过率。返回失败项列表（空表示全过）。"""
    cfg = load_config(root)
    problems: list[str] = []

    # 1) 授权语料与登记表一致
    from dpo_policy.provenance import SourceRegistry

    registry = SourceRegistry.from_config(cfg)
    raws = store.read_jsonl(root / "samples" / "sources.jsonl")
    records = tuple(model.SourceRecord.from_dict(raw) for raw in raws)
    accepted, rejected = registry.resolve_corpus(records)
    if rejected:
        problems.append(f"授权语料有 {len(rejected)} 条未通过登记表复核")
    if len(accepted) != len(records):
        problems.append("授权语料条数与通过条数不一致")
    unauth_raws = store.read_jsonl(root / "samples" / "sources_unauthorized.jsonl")
    unauth = tuple(model.SourceRecord.from_dict(raw) for raw in unauth_raws)
    _, unauth_rejected = registry.resolve_corpus(unauth)
    if len(unauth_rejected) != len(unauth):
        problems.append("未授权语料没有被全部拒绝")

    # 2) 样例结构校验
    gens = store.read_jsonl(root / "samples" / "generations.jsonl")
    if validate_bundle("generation", gens, cfg):
        problems.append("generations.jsonl 结构校验未通过")
    golden = store.read_jsonl(root / "samples" / "golden_cases.jsonl")
    if validate_bundle("golden_case", golden, cfg):
        problems.append("golden_cases.jsonl 结构校验未通过")

    # 3) 闸门行为（偏好对漏斗 + 蒸馏 + 回归）
    from dpo_policy.anonymize import Anonymizer
    from dpo_policy.distill import distill_traces
    from dpo_policy.pairs import build_pairs
    from dpo_policy.regression import PolicyEngine, run_regression

    clock = model.LogicalClock(cfg.clock_start, cfg.clock_tick_seconds)
    anonymizer = Anonymizer.from_config(cfg)
    pair_result = build_pairs(tuple(model.GenerationRecord.from_dict(g) for g in gens), registry, anonymizer, cfg, clock)
    if len(pair_result.pairs) != 8:
        problems.append(f"期望 8 条偏好对，实际 {len(pair_result.pairs)}")
    expected_filters = {
        model.ErrorCode.PAIR_CROSS_AXIS_REVERSAL,
        model.ErrorCode.PAIR_AXIS_NOT_DECISIVE,
        model.ErrorCode.PAIR_IDENTICAL_TEXT,
        model.ErrorCode.PAIR_LENGTH_IMBALANCE,
        model.ErrorCode.PAIR_SCORE_TOO_LOW,
        model.ErrorCode.PAIR_DUPLICATE,
        model.ErrorCode.PAIR_NO_CANDIDATE,
        model.ErrorCode.PAIR_SCHEMA_INVALID,
    }
    missing = expected_filters - set(pair_result.stats.get("filters", {}))
    if missing:
        problems.append("以下筛选规则没有被样例触发: " + ", ".join(sorted(missing)))

    trace_raws = list(store.read_jsonl(root / "samples" / "traces_messages.jsonl")) + list(
        store.read_jsonl(root / "samples" / "traces_tool.jsonl")
    )
    distill_result = distill_traces(trace_raws, registry, anonymizer, cfg, clock)
    if len(distill_result.triples) != len(trace_raws):
        problems.append(f"期望 {len(trace_raws)} 条三元组，实际 {len(distill_result.triples)}")
    invalid = distill_traces(store.read_jsonl(root / "samples" / "traces_invalid.jsonl"), registry, anonymizer, cfg, clock)
    if invalid.triples:
        problems.append("坏轨迹竟然产出了三元组")
    if len(invalid.rejected) != len(INVALID_TRACES):
        problems.append(f"期望 {len(INVALID_TRACES)} 条坏轨迹被拒，实际 {len(invalid.rejected)}")

    cases = tuple(model.GoldenCase.from_dict(raw) for raw in golden)
    engine = PolicyEngine(distill_result.cards, cfg)
    regression = run_regression(cases, engine, cfg, clock, anonymizer)
    if not regression.ok:
        problems.append("回归闸门未通过: " + ", ".join(c.case_id for c in regression.failed_cases))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成并自检订单 #1534 的样例数据")
    parser.add_argument("--check", action="store_true", help="只自检，不写文件")
    args = parser.parse_args(argv)

    if not args.check:
        counts = generate(ROOT)
        print("已生成样例：" + "，".join(f"{name}={count}" for name, count in sorted(counts.items())))
    problems = self_check(ROOT)
    if problems:
        print("自检未通过：")
        for item in problems:
            print("  - " + item)
        return 1
    print("自检通过：授权/结构/闸门/回归四项一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
