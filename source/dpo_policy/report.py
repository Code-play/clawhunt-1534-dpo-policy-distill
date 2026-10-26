"""报告渲染：把流水线结果写成买家与评审都能直接读的 Markdown。

本模块回答一个问题："结果怎么讲清楚"。它不重算业务结论，只做排版与措辞；
所有数字都来自上游返回的 stats/metrics，报告里不出现任何未脱敏原文。

三类报告：

- ``render_pair_audit``：偏好对审计——漏斗（每条筛选规则拦了多少）、对比轴分布、
  授权来源表、未授权来源拒绝表、匿名化摘要（只给映射摘要与条数，绝不给映射内容）、样例对；
- ``render_policy_card``：策略卡——由三元组聚合出的规则、支撑计数、涉及的授权来源、
  蒸馏统计与脱敏样例；
- ``render_regression_report``：离线回归报告——按 ``config/report_templates/regression_report.md.tpl``
  模板填充，模板里留占位符，本模块负责填并与断言"没有残留占位符"。

统一纪律：表格里的数字四舍五入到 6 位；时间一律标"逻辑时刻"；示例正文截断到固定长度。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import model
from .anonymize import Anonymizer
from .config import Config
from .model import PipelineError, ErrorCode, PreferencePair, DistillTriple, PolicyCard, RegressionReport
from .pairs import PairBuildResult

__all__ = [
    "REASON_LABELS",
    "render_pair_audit",
    "render_policy_card",
    "render_regression_report",
    "render_anonymized_samples",
    "fill_template",
]

#: 拒绝码 -> 中文说明。报告里给人看的措辞集中在这里，不外散。
REASON_LABELS: Mapping[str, str] = {
    model.ErrorCode.SOURCE_UNKNOWN: "来源不在授权登记表内",
    model.ErrorCode.SOURCE_VERSION_MISMATCH: "来源版本与登记表不符",
    model.ErrorCode.SOURCE_HASH_MISMATCH: "来源内容指纹与登记表不符",
    model.ErrorCode.SOURCE_UNAUTHORIZED: "许可不在允许清单内或缺少授权编号",
    model.ErrorCode.SOURCE_SCHEMA_INVALID: "来源引用字段不完整",
    model.ErrorCode.PAIR_SCHEMA_INVALID: "候选字段不符合规范",
    model.ErrorCode.PAIR_NO_CANDIDATE: "候选数不足 2 条",
    model.ErrorCode.PAIR_LOW_MARGIN: "总分差不足",
    model.ErrorCode.PAIR_AXIS_NOT_DECISIVE: "没有任何对比轴达到决定性分差",
    model.ErrorCode.PAIR_CROSS_AXIS_REVERSAL: "非决定性轴上被反向超越",
    model.ErrorCode.PAIR_SCORE_TOO_LOW: "候选质量分过低",
    model.ErrorCode.PAIR_LENGTH_OUT_OF_BOUNDS: "正文长度越界",
    model.ErrorCode.PAIR_LENGTH_IMBALANCE: "两条候选长度比过大",
    model.ErrorCode.PAIR_IDENTICAL_TEXT: "两条候选规范化后相同",
    model.ErrorCode.PAIR_DUPLICATE: "去重键已被占用",
    model.ErrorCode.PAIR_UNAUTHORIZED_SOURCE: "来源未授权",
    model.ErrorCode.ANON_LEAK: "脱敏后仍检出残留标识",
    model.ErrorCode.TRACE_INVALID: "轨迹内容不完整",
    model.ErrorCode.TRACE_ADAPTER_INVALID: "轨迹格式或适配器不受支持",
    model.ErrorCode.DISTILL_SCHEMA_INVALID: "蒸馏字段不符合规范",
    model.ErrorCode.DISTILL_DUPLICATE: "指令与输出组合重复",
    model.ErrorCode.DISTILL_EMPTY: "没有任何可蒸馏的轨迹",
}


def _cell(value: Any, limit: int = 48) -> str:
    """表格单元：压成单行、截断、转义竖线。"""
    text = str(value if value is not None else "")
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.replace("|", "\\|")


def _pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return str(value)


def _round(value: Any, digits: int = 6) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(item) for item in row) + " |")
    return "\n".join(lines)


def render_pair_audit(
    result: PairBuildResult,
    cfg: Config,
    *,
    source_accepted: Sequence[model.SourceRecord] = (),
    source_rejected: Sequence[Mapping[str, Any]] = (),
    registry_stats: Mapping[str, Any] | None = None,
    anonymizer: Anonymizer | None = None,
    negative: Mapping[str, Any] | None = None,
) -> str:
    """偏好对审计报告。"""
    stats = dict(result.stats)
    filters: Mapping[str, int] = dict(stats.get("filters", {}))
    axes: Mapping[str, int] = dict(stats.get("axes", {}))
    parts: list[str] = []
    parts.append("# 偏好对审计报告")
    parts.append(
        "本报告由流水线基于授权语料生成（逻辑时刻起点 "
        f"{cfg.clock_start}，步长 {cfg.clock_tick_seconds}s）。所有正文均已脱敏；"
        "未授权来源在闸门处被拒绝，不进入任何产物。"
    )

    parts.append("## 一、漏斗")
    parts.append(
        _table(
            ["阶段/筛选规则", "计数", "说明"],
            [
                ["输入 prompt", stats.get("generations", 0), "读入的候选生成文件条数"],
                ["候选回答", stats.get("candidates", 0), "全部候选（未筛选）"],
                ["产出偏好对", stats.get("emitted", 0), "通过的偏好对条数"],
                ["被拒记录", stats.get("rejected_records", 0), "整条 prompt 被拒绝的条数"],
                ["去重命中", stats.get("duplicates", 0), "去重键冲突的候选对"],
            ],
        )
    )
    if filters:
        rows = [[code, count, REASON_LABELS.get(code, "—")] for code, count in sorted(filters.items())]
        parts.append("### 逐条筛选规则的拦截数")
        parts.append(_table(["错误码", "拦截数", "说明"], rows))

    parts.append("## 二、对比轴分布")
    rows = [[axis, axes.get(axis, 0), _pct(axes.get(axis, 0) / max(1, int(stats.get("emitted", 0))))] for axis in cfg.axes]
    parts.append(_table(["对比轴", "作为决定性轴的条数", "占比"], rows))
    parts.append(
        "口径：每条偏好对必须有一个**唯一决定性轴**，该轴分差 >= "
        f"{_round(cfg.pairs['required_axis_delta'])}；其它轴反向超越不得超过 "
        f"{_round(cfg.pairs['cross_axis_tolerance'])}。平均决定性分差 {_round(stats.get('avg_axis_margin', 0))}，"
        f"平均总分差 {_round(stats.get('avg_score_margin', 0))}。"
    )

    parts.append("## 三、授权来源")
    reg = dict(registry_stats or {})
    parts.append(
        f"登记表条目 {reg.get('registered', len(cfg.registry))} 个，覆盖 {reg.get('sources', len(cfg.registry))} 个来源、"
        f"{len(dict(reg.get('licenses', {})))} 种许可；本次语料通过 {len(source_accepted)} 条。"
    )
    if source_accepted:
        parts.append(
            _table(
                ["来源", "版本", "许可", "授权编号", "生效日期", "内容指纹（前 16 位）", "标题"],
                [
                    [
                        src.source_id,
                        src.version,
                        src.license,
                        _registry_ref(cfg, src.source_id, src.version),
                        _registry_effective(cfg, src.source_id, src.version),
                        src.content_sha256()[:16],
                        src.title,
                    ]
                    for src in source_accepted
                ],
            )
        )
    parts.append("## 四、未授权/不合规来源（负样例）")
    if source_rejected:
        parts.append(
            _table(
                ["来源", "版本", "错误码", "说明"],
                [
                    [
                        item.get("source_id", "—"),
                        item.get("version", "—"),
                        item.get("code", "—"),
                        REASON_LABELS.get(str(item.get("code", "")), item.get("message", "")),
                    ]
                    for item in source_rejected
                ],
            )
        )
    else:
        parts.append("本次语料中没有未授权来源（负样例由 `samples/sources_unauthorized.jsonl` 单独驱动）。")
    if negative:
        parts.append(
            "补充负向对照：" + "；".join(f"{k} = {v}" for k, v in sorted(negative.items())) + "。"
        )

    if anonymizer is not None:
        parts.append("## 五、匿名化摘要")
        parts.append(
            _table(
                ["项目", "值"],
                [
                    ["脱敏规则数", len(cfg.redaction_rules)],
                    ["残留检测模式数", len(cfg.leak_patterns)],
                    ["残留处置策略", cfg.leak_policy],
                    ["本次伪名映射条数", anonymizer.mapping_size()],
                    ["映射表摘要（sha256，前 16 位）", anonymizer.mapping_digest()[:16]],
                ],
            )
        )
        parts.append("映射表只留在 `var/`（发布时跳过），产物里只有摘要；伪名由 salt 派生，同一原文稳定同一伪名。")

    parts.append("## 六、样例偏好对")
    samples = list(result.pairs)[:3]
    if samples:
        for pair in samples:
            parts.append(f"### {pair.pair_id}")
            parts.append(
                _table(
                    ["字段", "值"],
                    [
                        ["prompt", _cell(pair.prompt, 120)],
                        ["决定性轴", f"{pair.contrast.axis}（分差 {_round(pair.contrast.margin)}）"],
                        ["chosen", _cell(pair.chosen.text, 200)],
                        ["rejected", _cell(pair.rejected.text, 200)],
                        ["来源", f"{pair.source.source_id}@{pair.source.version}"],
                        ["逻辑时刻", pair.created_at],
                    ],
                )
            )
    else:
        parts.append("本次运行没有产出偏好对（详见上面的漏斗）。")

    parts.append("## 七、判据与复跑")
    parts.append(
        "判据全部来自 `config/pipeline_config.json` 的 `pairs` 段与 `config/source_registry.json`；"
        "改阈值只改配置。复跑：`python -m dpo_policy pairs`。"
    )
    return "\n\n".join(parts) + "\n"


def _registry_ref(cfg: Config, source_id: str, version: str) -> str:
    for entry in cfg.registry:
        if entry.source_id == source_id and entry.version == version:
            return entry.authorization_ref
    return "—"


def _registry_effective(cfg: Config, source_id: str, version: str) -> str:
    for entry in cfg.registry:
        if entry.source_id == source_id and entry.version == version:
            return entry.effective_at
    return "—"


def render_policy_card(
    cards: Sequence[PolicyCard],
    triples: Sequence[DistillTriple],
    cfg: Config,
    *,
    distill_stats: Mapping[str, Any] | None = None,
    anonymizer: Anonymizer | None = None,
) -> str:
    """策略卡报告：规则、支撑计数、涉及的来源与样本节选。"""
    stats = dict(distill_stats or {})
    rules = cfg.policy_rule_index()
    parts: list[str] = []
    parts.append("# 策略卡（由蒸馏三元组聚合）")
    parts.append(
        f"规则库共 {len(cfg.policy_rules)} 条，本次被三元组引用的 {len(cards)} 条。"
        "每张卡的支撑计数是引用该规则的脱敏三元组条数；规则原文只在配置里维护，报告不复制出第二个真相。"
    )

    parts.append("## 一、蒸馏统计")
    parts.append(
        _table(
            ["项目", "值"],
            [
                ["输入轨迹", stats.get("traces", 0)],
                ["产出三元组", stats.get("accepted", 0)],
                ["被拒记录", stats.get("rejected", 0)],
                ["SFT 目标", dict(stats.get("targets", {})).get("sft", 0)],
                ["DPO 目标", dict(stats.get("targets", {})).get("dpo", 0)],
                ["平均依据条数", _round(stats.get("rationale_steps_avg", 0), 2)],
                ["重复三元组", stats.get("duplicates", 0)],
            ],
        )
    )
    adapters = dict(stats.get("adapters", {}))
    if adapters:
        parts.append("### 轨迹适配器使用情况")
        parts.append(_table(["适配器", "轨迹数"], [[name, count] for name, count in sorted(adapters.items())]))

    parts.append("## 二、策略卡")
    if cards:
        parts.append(
            _table(
                ["规则", "标题", "支撑条数", "涉及来源", "执行方式"],
                [
                    [card.rule_id, card.title, card.support, "、".join(card.source_ids) or "—", card.enforced_by]
                    for card in cards
                ],
            )
        )
    else:
        parts.append("本次没有三元组支撑任何规则。")

    parts.append("## 三、规则原文（来自 config/policy_rules.json）")
    rows = []
    for card in cards:
        rule = rules.get(card.rule_id)
        if rule is None:  # pragma: no cover - 配置校验保证存在
            continue
        rows.append([rule.rule_id, rule.title, _cell(rule.statement, 160)])
    if rows:
        parts.append(_table(["规则", "标题", "规则原文"], rows))

    parts.append("## 四、脱敏三元组节选")
    for triple in list(triples)[:2]:
        parts.append(f"### {triple.triple_id}（{triple.target} / {triple.adapter}）")
        parts.append(
            _table(
                ["字段", "值"],
                [
                    ["instruction", _cell(triple.instruction, 160)],
                    ["output", _cell(triple.output, 200)],
                    ["rationale", "；".join(_cell(r, 80) for r in triple.rationale)],
                    ["policy_refs", "、".join(triple.policy_refs)],
                    ["来源", f"{triple.source.source_id}@{triple.source.version}"],
                    ["逻辑时刻", triple.created_at],
                ],
            )
        )

    if anonymizer is not None:
        parts.append("## 五、脱敏与授权")
        parts.append(
            f"本节全部正文来自脱敏闸门之后的文本；伪名映射 {anonymizer.mapping_size()} 条，"
            f"摘要 {anonymizer.mapping_digest()[:16]}。三元组只接受授权登记表内的来源，"
            "未授权轨迹在闸门处被拒（见 `out/pair_audit.md` 的负样例表）。"
        )
    return "\n\n".join(parts) + "\n"


def fill_template(template_text: str, values: Mapping[str, Any]) -> str:
    """用 ``{{key}}`` 占位符填充模板；残留占位符直接报错（不许静默输出半个模板）。"""
    out = template_text
    for key, value in values.items():
        out = out.replace("{{" + key + "}}", str(value))
    leftover = _unfilled(out)
    if leftover:
        raise PipelineError(
            ErrorCode.SCHEMA_INVALID,
            "回归报告模板存在未填充的占位符",
            detail=leftover,
        )
    return out


def _unfilled(text: str) -> list[str]:
    found: list[str] = []
    start = 0
    while True:
        left = text.find("{{", start)
        if left < 0:
            break
        right = text.find("}}", left)
        if right < 0:
            found.append(text[left : left + 40])
            break
        found.append(text[left : right + 2])
        start = right + 2
    return found


def render_regression_report(report: RegressionReport, cfg: Config, *, template_path: Path | None = None) -> str:
    """按模板渲染离线回归报告。"""
    path = template_path or (cfg.path("config") / "report_templates" / "regression_report.md.tpl")
    try:
        template = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PipelineError(ErrorCode.CONFIG_MISSING, f"缺少回归报告模板: {Path(path).name}") from exc

    metrics = dict(report.metrics)
    gate = dict(report.gate)
    baseline = dict(report.baseline)
    deltas = dict(report.deltas)
    cases = list(report.cases)
    failed = [c for c in cases if not c.passed]

    case_rows = [
        [
            c.case_id,
            c.expected_action,
            c.actual_action,
            "通过" if c.passed else "失败",
            "；".join(c.violations) if c.violations else "—",
            "、".join(c.citations) if c.citations else "—",
        ]
        for c in cases
    ]
    table_cases = _table(["用例", "期望动作", "实际动作", "结果", "违规项", "引用来源"], case_rows)
    failed_rows = [
        [c.case_id, "；".join(c.violations) or "—", "；".join(c.notes) or "—"]
        for c in failed
    ]
    table_failed = _table(["用例", "违规项", "补充说明"], failed_rows) if failed_rows else "本次没有失败用例。"

    values = {
        "pipeline_version": cfg.pipeline_version,
        "generated_at": report.generated_at,
        "gate_status": "通过" if report.ok else "不通过",
        "pass_rate": _pct(metrics.get("pass_rate")),
        "min_pass_rate": _pct(gate.get("min_pass_rate")),
        "cases_total": metrics.get("cases", 0),
        "regression_count": gate.get("regression_count", len(deltas.get("regressions", ()))),
        "max_regressions": gate.get("max_regressions", cfg.regression["thresholds"]["max_regressions"]),
        "violations": metrics.get("violations", 0),
        "failed_cases": "、".join(c.case_id for c in failed) or "无",
        "table_cases": table_cases,
        "baseline_version": baseline.get("pipeline_version", "—"),
        "baseline_pass_rate": _pct(baseline.get("pass_rate")),
        "baseline_cases": baseline.get("cases", "—"),
        "baseline_violations": baseline.get("violations", "—"),
        "pass_rate_delta": _format_delta(deltas.get("pass_rate", 0)),
        "fixes": "、".join(deltas.get("fixes", ())) or "无",
        "regressions": "、".join(deltas.get("regressions", ())) or "无",
        "violations_delta": _format_delta(deltas.get("violations_delta", 0)),
        "table_failed": table_failed,
    }
    return fill_template(template, values)


def _format_delta(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if abs(number) < 1e-12:
        return "0（与基线持平）"
    sign = "+" if number > 0 else ""
    if abs(number) <= 1:
        return f"{sign}{number * 100:.1f} 个百分点"
    return f"{sign}{number:.6f}"


def render_anonymized_samples(pairs: Sequence[PreferencePair], *, limit: int = 8) -> tuple[dict[str, Any], ...]:
    """把偏好对压成买家可读的「匿名偏好样例」（JSONL 一批）。"""
    out: list[dict[str, Any]] = []
    for pair in list(pairs)[:limit]:
        out.append(
            {
                "sample_id": pair.pair_id,
                "prompt": pair.prompt,
                "chosen": {"candidate_id": pair.chosen.candidate_id, "text": pair.chosen.text, "score": round(pair.chosen.score, 6)},
                "rejected": {
                    "candidate_id": pair.rejected.candidate_id,
                    "text": pair.rejected.text,
                    "score": round(pair.rejected.score, 6),
                },
                "contrast": pair.contrast.to_dict(),
                "source": pair.source.to_dict(),
                "anonymized": True,
                "created_at": pair.created_at,
            }
        )
    return tuple(out)
