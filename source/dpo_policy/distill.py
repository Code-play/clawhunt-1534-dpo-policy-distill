"""蒸馏层：教师轨迹 -> 蒸馏三元组 -> 策略卡。

本模块回答一个问题：一条教师轨迹能不能变成可训练的蒸馏样本，以及它由哪些策略规则支撑。
它明确不做的事：

- 不判来源是否授权（那是 :mod:`dpo_policy.provenance` 的闸门，本模块只调用并透传错误码）；
- 不实现脱敏算法（那是 :mod:`dpo_policy.anonymize` 的职责，本模块只要求"进产物前必须过一遍"）；
- 不读文件、不读真实时钟（轨迹由调用方喂进来，时刻由 ``LogicalClock`` 提供）；
- 不写产物（落盘是 :mod:`dpo_policy.store` 的事）。

为什么把"适配器"和"蒸馏判定"分成两层：轨迹格式会随教师模型与采集脚本变化，而"什么样的轨迹算
合格"不应该跟着变。``BaseTraceAdapter`` 只负责翻译（字段类型不对就抛错），``distill_traces`` 只负责
判定（长度、步数、策略引用、去重）。新增一种格式只需加一个适配器 + 改配置 + 加测试，判定口径不动。

错误码分工（验收只认码不认文本）：

- ``TRACE_ADAPTER_INVALID``：适配器名不受支持，或轨迹的整体形状与声明的适配器对不上
  （例如 messages 轨迹缺 ``messages`` 数组）；
- ``TRACE_INVALID``：轨迹内容不合法（字段类型错、步骤为空、回答过短、步数低于下限）；
- ``DISTILL_SCHEMA_INVALID``：能读出结构，但引用不在策略规则库/配置目标集合内；
- ``DISTILL_DUPLICATE``：与已接受轨迹的 (指令, 输出) 指纹相同；
- ``DISTILL_EMPTY``：整批没有任何可用三元组（这是"配置/用法问题"，抛异常而不是返回空结果，
  否则调用方会把"样例全被拒"当成"跑通了"）。

拒绝纪律：单条轨迹的数据问题落进 ``rejected``（带稳定错误码，``detail`` 不含原文），整批继续。

确定性：输入按 ``trace_id`` 排序处理，``triples`` 按 ``triple_id`` 排序、``cards`` 按 ``rule_id`` 排序，
所有聚合都按显式排序输出，不依赖 dict/set 的迭代顺序。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .model import (
    TARGET_DPO,
    TARGET_SFT,
    DistillTriple,
    ErrorCode,
    LogicalClock,
    PipelineError,
    PolicyCard,
    SourceBinding,
    TraceRecord,
    TraceStep,
    make_triple_id,
    text_fingerprint,
)

if TYPE_CHECKING:  # pragma: no cover - 只给类型检查用，运行时不 import（并行实现中）
    from .anonymize import Anonymizer
    from .config import Config
    from .provenance import SourceRegistry

__all__ = [
    "BaseTraceAdapter",
    "MessagesAdapter",
    "ToolTraceAdapter",
    "DistillResult",
    "build_policy_cards",
    "distill_traces",
    "get_adapter",
]

#: 缺省适配器：轨迹没写 ``adapter`` 字段时按 OpenAI 风格对话解析。
DEFAULT_ADAPTER = "messages"

#: messages 适配器接受的 role 全集；只有 assistant/tool 会变成步骤。
MESSAGE_ROLES: tuple[str, ...] = ("system", "user", "assistant", "tool")
STEP_ROLES: tuple[str, ...] = ("assistant", "tool")

#: 步骤被截断时的省略号（半角…不是 emoji，属于标点）。
RATIONALE_ELLIPSIS = "…"


# ---------------------------------------------------------------- 适配器


class BaseTraceAdapter:
    """轨迹适配器基类：把一种外部轨迹格式翻译成 :class:`TraceRecord`。

    子类只允许做"翻译 + 结构校验"，不要在 ``parse`` 里做业务判定（长度、策略引用、去重）——
    那些判定必须对所有适配器一致，因此只写在 :func:`distill_traces` 里。
    """

    #: 适配器名，必须与配置 ``distill.adapters`` 里的取值一致。
    name: str = ""

    def parse(self, raw: Mapping[str, Any]) -> TraceRecord:
        raise NotImplementedError

    # -- 公共校验 -------------------------------------------------------

    def _check_shape(self, raw: Any) -> Mapping[str, Any]:
        """校验"整体形状"：必须是对象，且声明的 adapter 与自己的名字一致。"""
        if not isinstance(raw, Mapping):
            raise PipelineError(
                ErrorCode.TRACE_ADAPTER_INVALID,
                "轨迹必须是 JSON 对象（顶层不能是数组或标量）",
            )
        declared = raw.get("adapter", self.name)
        if not isinstance(declared, str):
            raise PipelineError(ErrorCode.TRACE_ADAPTER_INVALID, "adapter 字段必须是字符串")
        if declared.strip() != self.name:
            raise PipelineError(
                ErrorCode.TRACE_ADAPTER_INVALID,
                "声明的 adapter 与解析器不一致（轨迹格式不受支持）",
                detail={"declared": declared.strip(), "expected": self.name},
            )
        return raw


def _require_non_empty_text(raw: Mapping[str, Any], key: str, *, label: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PipelineError(ErrorCode.TRACE_INVALID, f"{label} 必须是非空字符串")
    return value.strip()


def _optional_text(raw: Mapping[str, Any], key: str, *, label: str, default: str = "") -> str:
    value = raw.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise PipelineError(ErrorCode.TRACE_INVALID, f"{label} 必须是字符串")
    return value


def _source_ref(raw: Mapping[str, Any]) -> dict[str, str]:
    """取 source_ref，只保留字符串键值；缺失当空对象（交给授权闸门去拒绝）。"""
    value = raw.get("source_ref")
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise PipelineError(ErrorCode.TRACE_INVALID, "source_ref 必须是对象")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise PipelineError(ErrorCode.TRACE_INVALID, "source_ref 的键和值都必须声明为字符串")
        out[key] = item
    return out


def _policy_refs(raw: Mapping[str, Any]) -> tuple[str, ...]:
    """取 policy_refs：排序去重，便于后续集合运算与稳定输出。"""
    value = raw.get("policy_refs")
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise PipelineError(ErrorCode.DISTILL_SCHEMA_INVALID, "policy_refs 必须是字符串数组")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PipelineError(ErrorCode.DISTILL_SCHEMA_INVALID, "policy_refs 里每一项都必须是非空字符串")
        refs.append(item.strip())
    return tuple(sorted(set(refs)))


def _rejected_answer(raw: Mapping[str, Any]) -> str | None:
    """取 rejected_answer；空白字符串按"没有"处理（避免空串被误判成 dpo 目标）。"""
    value = raw.get("rejected_answer")
    if value is None:
        return None
    if not isinstance(value, str):
        raise PipelineError(ErrorCode.TRACE_INVALID, "rejected_answer 必须是字符串（或省略）")
    return value if value.strip() else None


def _build_record(
    raw: Mapping[str, Any],
    *,
    adapter_name: str,
    steps: Iterable[TraceStep],
    final_answer: str,
) -> TraceRecord:
    return TraceRecord(
        trace_id=_require_non_empty_text(raw, "trace_id", label="trace_id"),
        prompt=_require_non_empty_text(raw, "prompt", label="prompt"),
        steps=tuple(steps),
        final_answer=final_answer,
        source_ref=_source_ref(raw),
        model=_optional_text(raw, "model", label="model", default="sim-teacher").strip() or "sim-teacher",
        rejected_answer=_rejected_answer(raw),
        adapter=adapter_name,
        policy_refs=_policy_refs(raw),
    )


class MessagesAdapter(BaseTraceAdapter):
    """OpenAI 风格对话轨迹：``messages`` 数组 + 可选 ``final_answer``。

    步骤的取法：role 属于 {assistant, tool} 且**不是最终回答那条**的 message。
    为什么排除最终回答那条：最终回答是训练目标（output），把它同时塞进 rationale 会让模型
    在"依据"里看到答案本身，等于教它抄结论。
    """

    name = DEFAULT_ADAPTER

    def parse(self, raw: Mapping[str, Any]) -> TraceRecord:
        raw = self._check_shape(raw)
        messages = raw.get("messages")
        if not isinstance(messages, (list, tuple)) or not messages:
            raise PipelineError(ErrorCode.TRACE_ADAPTER_INVALID, "messages 轨迹要求非空的 messages 数组")

        parsed: list[tuple[str, str, str]] = []
        for index, item in enumerate(messages):
            if not isinstance(item, Mapping):
                raise PipelineError(ErrorCode.TRACE_INVALID, f"messages[{index}] 必须是对象")
            role = item.get("role")
            if not isinstance(role, str) or role.strip() not in MESSAGE_ROLES:
                raise PipelineError(
                    ErrorCode.TRACE_INVALID,
                    f"messages[{index}].role 必须是 {'/'.join(MESSAGE_ROLES)} 之一",
                )
            content = item.get("content")
            if not isinstance(content, str):
                raise PipelineError(ErrorCode.TRACE_INVALID, f"messages[{index}].content 必须是字符串")
            name = item.get("name") or ""
            if not isinstance(name, str):
                raise PipelineError(ErrorCode.TRACE_INVALID, f"messages[{index}].name 必须是字符串")
            parsed.append((role.strip(), content, name.strip()))

        final_answer: str
        explicit = raw.get("final_answer")
        if explicit is not None:
            if not isinstance(explicit, str):
                raise PipelineError(ErrorCode.TRACE_INVALID, "final_answer 必须是字符串")
            final_answer = explicit
        else:
            assistants = [content for role, content, _ in parsed if role == "assistant"]
            if not assistants:
                raise PipelineError(ErrorCode.TRACE_INVALID, "messages 里没有 assistant 回答，无法确定 final_answer")
            final_answer = assistants[-1]

        # 最终回答那条 = 最后一条 assistant；它不进入步骤，只作为 output。
        final_index = -1
        for index in range(len(parsed) - 1, -1, -1):
            if parsed[index][0] == "assistant":
                final_index = index
                break

        steps: list[TraceStep] = []
        for index, (role, content, name) in enumerate(parsed):
            if role not in STEP_ROLES or index == final_index:
                continue
            if role == "tool":
                action = f"tool:{name}" if name else "tool"
                tool = name
            else:
                action = role
                tool = ""
            steps.append(
                TraceStep(index=len(steps) + 1, action=action, observation=content, tool=tool)
            )

        return _build_record(raw, adapter_name=self.name, steps=steps, final_answer=final_answer)


class ToolTraceAdapter(BaseTraceAdapter):
    """工具调用轨迹：``steps`` 直接映射成 :class:`TraceStep`（index 从 1 递增）。"""

    name = "tool_trace"

    def parse(self, raw: Mapping[str, Any]) -> TraceRecord:
        raw = self._check_shape(raw)
        steps_raw = raw.get("steps")
        if not isinstance(steps_raw, (list, tuple)) or not steps_raw:
            raise PipelineError(ErrorCode.TRACE_ADAPTER_INVALID, "tool_trace 轨迹要求非空的 steps 数组")
        final_answer = raw.get("final_answer")
        if not isinstance(final_answer, str):
            raise PipelineError(ErrorCode.TRACE_ADAPTER_INVALID, "tool_trace 轨迹要求 final_answer 字符串")

        steps: list[TraceStep] = []
        for index, item in enumerate(steps_raw):
            if not isinstance(item, Mapping):
                raise PipelineError(ErrorCode.TRACE_INVALID, f"steps[{index}] 必须是对象")
            action = item.get("action")
            if not isinstance(action, str) or not action.strip():
                raise PipelineError(ErrorCode.TRACE_INVALID, f"steps[{index}].action 必须是非空字符串")
            observation = item.get("observation", "")
            if observation is None:
                observation = ""
            if not isinstance(observation, str):
                raise PipelineError(ErrorCode.TRACE_INVALID, f"steps[{index}].observation 必须是字符串")
            tool = item.get("tool", "")
            if tool is None:
                tool = ""
            if not isinstance(tool, str):
                raise PipelineError(ErrorCode.TRACE_INVALID, f"steps[{index}].tool 必须是字符串")
            steps.append(
                TraceStep(
                    index=len(steps) + 1,
                    action=action.strip(),
                    observation=observation,
                    tool=tool.strip(),
                )
            )

        return _build_record(raw, adapter_name=self.name, steps=steps, final_answer=final_answer)


#: 适配器注册表：名字 -> 单例。新增格式要同时改这里、``config.SUPPORTED_ADAPTERS`` 与配置。
_ADAPTERS: dict[str, BaseTraceAdapter] = {
    MessagesAdapter.name: MessagesAdapter(),
    ToolTraceAdapter.name: ToolTraceAdapter(),
}


def get_adapter(name: str) -> BaseTraceAdapter:
    """按名字取适配器；未实现的格式抛 ``TRACE_ADAPTER_INVALID``（不是返回 None）。"""
    key = str(name or "").strip()
    adapter = _ADAPTERS.get(key)
    if adapter is None:
        raise PipelineError(
            ErrorCode.TRACE_ADAPTER_INVALID,
            "未实现的轨迹适配器（格式不受支持）",
            detail={"requested": key, "supported": sorted(_ADAPTERS)},
        )
    return adapter


# ---------------------------------------------------------------- 结果类型


@dataclass(frozen=True)
class DistillResult:
    """一批轨迹的蒸馏结果：三元组 + 策略卡 + 统计 + 被拒明细。"""

    triples: tuple[DistillTriple, ...]
    cards: tuple[PolicyCard, ...]
    stats: Mapping[str, Any]
    rejected: tuple[Mapping[str, Any], ...]


# ---------------------------------------------------------------- 蒸馏主流程


def _order_traces(traces_raw: Iterable[Mapping[str, Any]]) -> list[tuple[str, Any]]:
    """按 (trace_id, 原始下标) 排序：同一批输入无论以什么顺序喂进来，产物都一致。"""
    if traces_raw is None:
        return []
    items: list[tuple[str, int, Any]] = []
    for index, raw in enumerate(traces_raw):
        trace_id = ""
        if isinstance(raw, Mapping):
            value = raw.get("trace_id")
            if isinstance(value, str):
                trace_id = value.strip()
        items.append((trace_id, index, raw))
    items.sort(key=lambda item: (item[0], item[1]))
    return [(trace_id, raw) for trace_id, _, raw in items]


def _rejection_detail(anonymizer: "Anonymizer", exc: PipelineError, *, limit: int = 200) -> str:
    """把异常消息压成可进 ``rejected[*].detail`` 的文本：脱敏后再自检，仍未清净就只留错误码。

    为什么这么绕：``detail`` 必须"不含原文"，但拒绝原因又必须可读。让脱敏器当裁判是唯一
    既安全又不丢信息的做法；脱敏器自己出问题时退回错误码，绝不把未脱敏文本写进产物。
    """
    code = str(getattr(exc, "code", "") or "")
    message = str(getattr(exc, "message", "") or "").strip()
    if not message:
        return code
    try:
        cleaned = anonymizer.redact_text(message)
        if anonymizer.scan(cleaned):
            return code
    except Exception:  # noqa: BLE001 - 脱敏器异常时保守回退，不能因此打断整批
        return code
    return cleaned[:limit]


def _distill_one(
    raw: Any,
    *,
    registry: "SourceRegistry",
    anonymizer: "Anonymizer",
    cfg: "Config",
    clock: LogicalClock,
    allowed_adapters: tuple[str, ...],
    allowed_targets: tuple[str, ...],
    min_steps: int,
    max_steps: int,
    min_answer_chars: int,
    max_rationale_chars: int,
    required_refs: tuple[str, ...],
    rule_index: Mapping[str, Any],
    seen: dict[str, str],
) -> DistillTriple:
    """处理单条轨迹。任何数据问题都以 ``PipelineError`` 抛出，由调用方落进 rejected。"""
    if not isinstance(raw, Mapping):
        raise PipelineError(ErrorCode.TRACE_INVALID, "轨迹必须是 JSON 对象")

    declared = raw.get("adapter", DEFAULT_ADAPTER)
    if not isinstance(declared, str):
        raise PipelineError(ErrorCode.TRACE_ADAPTER_INVALID, "adapter 字段必须是字符串")
    adapter_name = declared.strip() or DEFAULT_ADAPTER
    if adapter_name not in allowed_adapters:
        raise PipelineError(
            ErrorCode.TRACE_ADAPTER_INVALID,
            "适配器不在配置允许的集合内（格式不受支持）",
            detail={"requested": adapter_name, "allowed": list(allowed_adapters)},
        )
    adapter = get_adapter(adapter_name)

    trace = adapter.parse(raw)

    # -- 语义校验（对所有适配器一致）
    if not trace.trace_id.strip():
        raise PipelineError(ErrorCode.TRACE_INVALID, "trace_id 不能为空")
    if not trace.prompt.strip():
        raise PipelineError(ErrorCode.TRACE_INVALID, "prompt 不能为空")
    if not trace.steps:
        raise PipelineError(ErrorCode.TRACE_INVALID, "轨迹没有任何可用步骤（steps 为空）")
    if len(trace.final_answer.strip()) < min_answer_chars:
        raise PipelineError(
            ErrorCode.TRACE_INVALID,
            f"final_answer 长度不足下限（{len(trace.final_answer.strip())} < {min_answer_chars}）",
        )
    unknown_refs = [ref for ref in trace.policy_refs if ref not in rule_index]
    if unknown_refs:
        raise PipelineError(
            ErrorCode.DISTILL_SCHEMA_INVALID,
            "policy_refs 引用了策略规则库之外的规则",
            detail={"unknown": unknown_refs},
        )

    # -- 授权与版本（错误码由授权闸门决定，这里只透传）
    binding: SourceBinding = registry.resolve(trace.source_ref, record_id=trace.trace_id)

    # -- 脱敏：进产物前每个文本字段都过一遍（prompt/步骤/回答/被拒回答一个都不能漏）
    instruction = anonymizer.redact_text(trace.prompt)
    output = anonymizer.redact_text(trace.final_answer)
    redacted_steps = tuple(
        TraceStep(
            index=step.index,
            action=anonymizer.redact_text(step.action),
            observation=anonymizer.redact_text(step.observation),
            tool=anonymizer.redact_text(step.tool),
        )
        for step in trace.steps
    )
    # 被拒回答只保留在内部记录里、只用于目标判定与计数，绝不进三元组正文。
    rejected_answer = None
    if trace.rejected_answer is not None:
        rejected_answer = anonymizer.redact_text(trace.rejected_answer)

    # 残留自检：命中即整条拒绝（与 redaction_rules.leak_scan.policy=block 的口径一致）
    anonymizer.assert_clean(instruction, record_id=trace.trace_id)
    anonymizer.assert_clean(output, record_id=trace.trace_id)

    # -- 目标：有被拒回答才是 dpo（偏好对需要正反两侧），否则是 sft
    target = TARGET_DPO if rejected_answer is not None else TARGET_SFT
    if target not in allowed_targets:
        raise PipelineError(
            ErrorCode.DISTILL_SCHEMA_INVALID,
            "推导出的 target 不在配置允许的目标集合内",
            detail={"target": target, "allowed": list(allowed_targets)},
        )

    # -- 依据：从步骤派生，逐条截断；步数超出上限时取前 N 条并标注省略
    if len(redacted_steps) < min_steps:
        raise PipelineError(
            ErrorCode.TRACE_INVALID,
            f"可用步骤数不足下限（{len(redacted_steps)} < {min_steps}）",
        )
    selected = redacted_steps[:max_steps]
    rationale: list[str] = []
    for step in selected:
        line = f"步骤{step.index}[{step.action}] {step.observation}"
        rationale.append(line[:max_rationale_chars])
    if len(redacted_steps) > max_steps and rationale:
        # 先截到 max-1 再加省略号，保证"截断到 max_rationale_chars 字符"这条不因省略号被破坏
        last = rationale[-1]
        if len(last) >= max_rationale_chars:
            last = last[: max(max_rationale_chars - 1, 0)] + RATIONALE_ELLIPSIS
        else:
            last = last + RATIONALE_ELLIPSIS
        rationale[-1] = last
    for line in rationale:
        anonymizer.assert_clean(line, record_id=trace.trace_id)

    # -- 策略引用：样本自己声明的 + 配置强制要求注入的，排序去重
    policy_refs = tuple(sorted(set(trace.policy_refs) | set(required_refs)))

    # -- 去重键：只看 (指令, 输出) 的规范化指纹，不看来源与 rationale
    dedupe_key = text_fingerprint(instruction) + "|" + text_fingerprint(output)
    if dedupe_key in seen:
        raise PipelineError(
            ErrorCode.DISTILL_DUPLICATE,
            "与已接受轨迹的 (instruction, output) 重复",
            detail={"first_trace_id": seen[dedupe_key]},
        )

    triple = DistillTriple(
        triple_id=make_triple_id(trace.trace_id, instruction, output),
        trace_id=trace.trace_id,
        instruction=instruction,
        output=output,
        rationale=tuple(rationale),
        policy_refs=policy_refs,
        target=target,
        source=binding,
        pipeline_version=cfg.pipeline_version,
        created_at=clock.now(),
        dedupe_key=dedupe_key,
        adapter=adapter_name,
    )
    seen[dedupe_key] = trace.trace_id
    return triple


def distill_traces(
    traces_raw: Iterable[Mapping[str, Any]],
    registry: "SourceRegistry",
    anonymizer: "Anonymizer",
    cfg: "Config",
    clock: LogicalClock,
) -> DistillResult:
    """把一批原始轨迹蒸馏成三元组与策略卡。

    语义边界（调用方靠它区分"输入是空的"和"输入不空但全被拒"）：

    - **输入本身为空**（一条轨迹都没有）-> 抛 ``DISTILL_EMPTY``，这是调用方配置/路径问题；
    - **输入非空但每条都被拒** -> 正常返回 ``DistillResult``，``triples`` 为空、``rejected``
      里逐条带原因码。负向对照就是要这种返回值来判断"闸门真的拦住了"，而不是靠异常。
    """
    distill_cfg = cfg.distill
    allowed_adapters = tuple(str(item) for item in distill_cfg["adapters"])
    allowed_targets = tuple(str(item) for item in distill_cfg["targets"])
    min_steps = int(distill_cfg["min_rationale_steps"])
    max_steps = int(distill_cfg["max_rationale_steps"])
    min_answer_chars = int(distill_cfg["min_answer_chars"])
    max_rationale_chars = int(distill_cfg["max_rationale_chars"])
    required_refs = tuple(sorted({str(item) for item in (distill_cfg.get("required_policy_refs") or ())}))
    rule_index = cfg.policy_rule_index()

    ordered = _order_traces(traces_raw)
    triples: list[DistillTriple] = []
    rejected: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    target_counts: dict[str, int] = {TARGET_SFT: 0, TARGET_DPO: 0}
    adapter_counts: dict[str, int] = {name: 0 for name in allowed_adapters}
    rule_counts: dict[str, int] = {}
    rejected_by_reason: dict[str, int] = {}

    for trace_id, raw in ordered:
        try:
            triple = _distill_one(
                raw,
                registry=registry,
                anonymizer=anonymizer,
                cfg=cfg,
                clock=clock,
                allowed_adapters=allowed_adapters,
                allowed_targets=allowed_targets,
                min_steps=min_steps,
                max_steps=max_steps,
                min_answer_chars=min_answer_chars,
                max_rationale_chars=max_rationale_chars,
                required_refs=required_refs,
                rule_index=rule_index,
                seen=seen,
            )
        except PipelineError as exc:
            code = str(exc.code)
            rejected.append(
                {
                    "trace_id": trace_id,
                    "reason": code,
                    "detail": _rejection_detail(anonymizer, exc),
                }
            )
            rejected_by_reason[code] = rejected_by_reason.get(code, 0) + 1
            continue
        triples.append(triple)
        target_counts[triple.target] = target_counts.get(triple.target, 0) + 1
        adapter_counts[triple.adapter] = adapter_counts.get(triple.adapter, 0) + 1
        for ref in triple.policy_refs:
            rule_counts[ref] = rule_counts.get(ref, 0) + 1

    if not ordered:
        raise PipelineError(
            ErrorCode.DISTILL_EMPTY,
            "没有输入任何轨迹（空批次）",
            detail={"traces": 0, "rejected": 0},
        )

    cards = build_policy_cards(triples, cfg)

    covered = {ref for triple in triples for ref in triple.policy_refs}
    missing_required = sorted(ref for ref in required_refs if ref not in covered)
    steps_total = sum(len(triple.rationale) for triple in triples)
    stats: dict[str, Any] = {
        "traces": len(ordered),
        "accepted": len(triples),
        "rejected": len(rejected),
        "targets": dict(sorted(target_counts.items())),
        "adapters": dict(sorted(adapter_counts.items())),
        "policy_rules": dict(sorted(rule_counts.items())),
        "duplicates": rejected_by_reason.get(ErrorCode.DISTILL_DUPLICATE, 0),
        "rationale_steps_avg": round(steps_total / len(triples), 4) if triples else 0.0,
        "missing_required_refs": missing_required,
        "rejected_by_reason": dict(sorted(rejected_by_reason.items())),
    }

    ordered_triples = tuple(sorted(triples, key=lambda item: item.triple_id))
    return DistillResult(
        triples=ordered_triples,
        cards=cards,
        stats=stats,
        rejected=tuple(rejected),
    )


# ---------------------------------------------------------------- 策略卡


def build_policy_cards(triples: Iterable[DistillTriple], cfg: "Config") -> tuple[PolicyCard, ...]:
    """按三元组里 ``policy_refs`` 的出现次数聚合出策略卡。

    - 只为"至少被一条三元组引用"的规则产卡：没有支撑的卡会把支持度做成 0，读起来像"有规则但没用上"；
    - ``support`` 记的是**引用该规则的三元组条数**（同一三元组内重复引用只算一次），
      因为审核的人关心的是"有多少样本撑着这条规则"，不是"字符串出现几次"；
    - 规则库里不存在的引用直接跳过：``distill_traces`` 已在入口拒绝这类轨迹，这里只防御直接调用。
    """
    rule_index = cfg.policy_rule_index()
    support: dict[str, int] = {}
    source_ids: dict[str, set[str]] = {}
    for triple in triples:
        counted: set[str] = set()
        for ref in triple.policy_refs:
            if ref in counted:
                continue
            counted.add(ref)
            support[ref] = support.get(ref, 0) + 1
            bucket = source_ids.setdefault(ref, set())
            source_id = getattr(triple.source, "source_id", "")
            if source_id:
                bucket.add(str(source_id))

    cards: list[PolicyCard] = []
    for rule_id in sorted(support):
        rule = rule_index.get(rule_id)
        if rule is None:
            continue
        cards.append(
            PolicyCard(
                rule_id=rule.rule_id,
                title=rule.title,
                statement=rule.statement,
                policy_refs=(rule.rule_id,),
                support=support[rule_id],
                source_ids=tuple(sorted(source_ids.get(rule_id, set()))),
                enforced_by=rule.enforcement,
            )
        )
    return tuple(cards)
