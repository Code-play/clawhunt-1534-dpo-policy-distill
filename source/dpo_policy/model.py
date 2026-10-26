"""领域模型：偏好对、蒸馏三元组、回归用例与策略卡。

本模块只回答一个问题：一条记录"是什么"。它不读文件、不读时钟、不做业务判定，
因此可以被单独导入、单独测试；上层任何模块都不允许绕开这里的类型手工拼 dict。

硬约束（可被静态扫描与断言直接检验）：

- 不出现任何真实时钟调用；时刻一律来自配置里写死的逻辑时钟（``LogicalClock``）；
- 序列化只走 :func:`canonical_json`（``sort_keys=True`` + ``ensure_ascii=False`` +
  紧凑分隔符），同一内容在不同机器、不同进程上得到逐字节相同的字符串；
- 所有记录都是 ``frozen=True`` 的 dataclass，构造后不可改写；主键由内容派生。

哈希口径（与 ``config/pipeline_config.json`` 的 ``hash`` 段一一对应）：

- ``text_fingerprint(text) = sha256(normalize_text(text))``：去重与比较用；
- ``content_hash(obj) = sha256(canonical_json(obj))``：登记表与产物校验用；
- ``pair_id = "pair_" + sha256(canonical({prompt_id, chosen.text, rejected.text, axis}))[:16]``；
- ``triple_id = "tri_" + sha256(canonical({trace_id, instruction, output}))[:16]``。

时间纪律：``LogicalClock(start, tick_seconds)`` 从配置起点开始，每取一次时刻前进一个
tick。同一份输入、同一份配置跑两遍，得到的时间戳序列完全相同，这是「离线可复现」
的前提；真实墙上时间不参与任何业务判定。
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "PIPELINE_VERSION",
    "ErrorCode",
    "PipelineError",
    "TARGET_SFT",
    "TARGET_DPO",
    "TARGETS",
    "ACTION_ANSWER",
    "ACTION_ABSTAIN",
    "ACTION_REFUSE",
    "ACTIONS",
    "ContrastSpec",
    "Candidate",
    "GenerationRecord",
    "PreferencePair",
    "SourceBinding",
    "SourceRecord",
    "TraceStep",
    "TraceRecord",
    "DistillTriple",
    "PolicyCard",
    "GoldenCase",
    "RegressionCaseResult",
    "RegressionReport",
    "LogicalClock",
    "canonical_json",
    "content_hash",
    "format_ts",
    "is_hash_hex",
    "normalize_text",
    "parse_ts",
    "sha256_text",
    "short_hash",
    "text_fingerprint",
    "coerce_text",
    "as_float",
    "as_int",
]

# ---------------------------------------------------------------- 常量

PIPELINE_VERSION = "dpo-policy-1.0.0"

HASH_HEX_LEN = 64
ID_PREFIX_PAIR = "pair_"
ID_PREFIX_TRIPLE = "tri_"

TARGET_SFT = "sft"
TARGET_DPO = "dpo"
TARGETS: tuple[str, ...] = (TARGET_SFT, TARGET_DPO)

ACTION_ANSWER = "answer_with_citation"
ACTION_ABSTAIN = "abstain"
ACTION_REFUSE = "refuse_unauthorized"
ACTIONS: tuple[str, ...] = (ACTION_ANSWER, ACTION_ABSTAIN, ACTION_REFUSE)


class ErrorCode:
    """稳定错误码。

    验收断言只认码不认文本：拒绝原因必须可枚举，不允许把业务结论写成自由文本。
    分组见 :data:`ERROR_GROUPS`，CLI 据此决定退出码。
    """

    # 配置 / 环境（用法或环境问题 -> 退出码 3）
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_MISSING = "CONFIG_MISSING"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    USAGE_ERROR = "USAGE_ERROR"
    STORE_CONFLICT = "STORE_CONFLICT"
    STORE_INTEGRITY = "STORE_INTEGRITY"

    # 授权与版本（业务闸门 -> 退出码 2）
    SOURCE_UNKNOWN = "SOURCE_UNKNOWN"
    SOURCE_UNAUTHORIZED = "SOURCE_UNAUTHORIZED"
    SOURCE_VERSION_MISMATCH = "SOURCE_VERSION_MISMATCH"
    SOURCE_HASH_MISMATCH = "SOURCE_HASH_MISMATCH"
    SOURCE_SCHEMA_INVALID = "SOURCE_SCHEMA_INVALID"

    # 偏好对（业务闸门）
    PAIR_SCHEMA_INVALID = "PAIR_SCHEMA_INVALID"
    PAIR_NO_CANDIDATE = "PAIR_NO_CANDIDATE"
    PAIR_LOW_MARGIN = "PAIR_LOW_MARGIN"
    PAIR_AXIS_NOT_DECISIVE = "PAIR_AXIS_NOT_DECISIVE"
    PAIR_CROSS_AXIS_REVERSAL = "PAIR_CROSS_AXIS_REVERSAL"
    PAIR_SCORE_TOO_LOW = "PAIR_SCORE_TOO_LOW"
    PAIR_LENGTH_OUT_OF_BOUNDS = "PAIR_LENGTH_OUT_OF_BOUNDS"
    PAIR_LENGTH_IMBALANCE = "PAIR_LENGTH_IMBALANCE"
    PAIR_IDENTICAL_TEXT = "PAIR_IDENTICAL_TEXT"
    PAIR_DUPLICATE = "PAIR_DUPLICATE"
    PAIR_UNAUTHORIZED_SOURCE = "PAIR_UNAUTHORIZED_SOURCE"

    # 脱敏（业务闸门）
    ANON_LEAK = "ANON_LEAK"
    ANON_SCHEMA_INVALID = "ANON_SCHEMA_INVALID"

    # 轨迹与蒸馏（业务闸门）
    TRACE_INVALID = "TRACE_INVALID"
    TRACE_ADAPTER_INVALID = "TRACE_ADAPTER_INVALID"
    DISTILL_EMPTY = "DISTILL_EMPTY"
    DISTILL_SCHEMA_INVALID = "DISTILL_SCHEMA_INVALID"
    DISTILL_DUPLICATE = "DISTILL_DUPLICATE"

    # 离线回归（业务闸门）
    REGRESSION_GATE_FAILED = "REGRESSION_GATE_FAILED"
    REGRESSION_CASE_INVALID = "REGRESSION_CASE_INVALID"


#: 错误码分组：``config`` 类算环境/用法问题（退出码 3），其余算业务拒绝（退出码 2）。
ERROR_GROUPS: Mapping[str, str] = {
    ErrorCode.CONFIG_INVALID: "config",
    ErrorCode.CONFIG_MISSING: "config",
    ErrorCode.SCHEMA_INVALID: "config",
    ErrorCode.USAGE_ERROR: "config",
    ErrorCode.STORE_CONFLICT: "config",
    ErrorCode.STORE_INTEGRITY: "config",
}

#: CLI 退出码：0 通过，2 业务闸门拒绝，3 用法/环境问题。
EXIT_OK = 0
EXIT_GATE_REJECTED = 2
EXIT_USAGE = 3


def exit_code_for(code: str) -> int:
    """把错误码映射成退出码。

    故意让 argparse 的用法错误退回 3：平台的 2 表示"业务被拒"，
    把"参数写错了"混进 2 会让复跑的人把环境问题当成业务结论。
    """
    return EXIT_USAGE if ERROR_GROUPS.get(code) == "config" else EXIT_GATE_REJECTED


class PipelineError(Exception):
    """流水线唯一的异常类型。

    ``code`` 是稳定错误码，``record_id`` 指向出问题的记录（可能为 None），
    ``detail`` 是给人看的补充信息（不得包含未脱敏原文）。
    """

    def __init__(self, code: str, message: str, *, record_id: str | None = None, detail: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.record_id = record_id
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "record_id": self.record_id,
            "detail": self.detail,
        }

    def __str__(self) -> str:  # pragma: no cover - 只影响日志可读性
        where = f" [{self.record_id}]" if self.record_id else ""
        return f"{self.code}: {self.message}{where}"


# ---------------------------------------------------------------- 文本与哈希


def canonical_json(obj: Any) -> str:
    """规范化 JSON：键排序、紧凑分隔符、不转义非 ASCII。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_hash(obj: Any) -> str:
    """对象的内容摘要：canonical_json 后取 sha256。"""
    return sha256_text(canonical_json(obj))


def short_hash(h: str, n: int = 16) -> str:
    return h[:n]


def is_hash_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == HASH_HEX_LEN and all(c in "0123456789abcdef" for c in value)


_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """比较用规范化：NFKC + 空白折叠 + 去首尾空白。

    只用于去重与指纹，不用于展示：偏好对正文保持脱敏后的原样。
    """
    if not isinstance(text, str):
        raise TypeError(f"normalize_text expects str, got {type(text).__name__}")
    norm = unicodedata.normalize("NFKC", text)
    return _WS_RE.sub(" ", norm).strip()


def text_fingerprint(text: str) -> str:
    return sha256_text(normalize_text(text))


def coerce_text(value: Any, *, limit: int | None = None) -> str:
    """把任意标量转成单行文本；超长截断（用于字段校验前的防御）。"""
    if value is None:
        return ""
    if isinstance(value, str):
        out = value
    elif isinstance(value, (int, float, bool)):
        out = str(value)
    else:
        out = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return out[:limit] if limit else out


def as_float(value: Any, default: float | None = None) -> float | None:
    try:
        if isinstance(value, bool):
            return default
        out = float(value)
    except (TypeError, ValueError):
        return default
    return out


def as_int(value: Any, default: int | None = None) -> int | None:
    try:
        if isinstance(value, bool):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- 逻辑时刻

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def parse_ts(value: str) -> datetime:
    """解析配置里的 UTC 时刻字符串（``YYYY-MM-DDTHH:MM:SSZ``）。"""
    if not isinstance(value, str) or not _TS_RE.match(value):
        raise PipelineError(ErrorCode.CONFIG_INVALID, f"非法时刻字符串: {value!r}")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def format_ts(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogicalClock:
    """逻辑时钟：从配置起点开始，每次 ``tick()`` 前进固定步长。

    这样 demo 与回归报告里的时刻是可复现的常量序列，而不是"跑的时候几点"。
    """

    def __init__(self, start: str, tick_seconds: int = 30) -> None:
        if tick_seconds <= 0:
            raise PipelineError(ErrorCode.CONFIG_INVALID, "tick_seconds 必须为正整数")
        self._origin = parse_ts(start)
        self._tick = timedelta(seconds=int(tick_seconds))
        self._step = 0

    @property
    def start(self) -> str:
        return format_ts(self._origin)

    @property
    def step(self) -> int:
        return self._step

    def now(self) -> str:
        """取当前逻辑时刻并前进一格。"""
        return self.at(self._step, advance=True)

    def peek(self) -> str:
        """查看下一格时刻但不前进（用于给同一批记录打同一时刻）。"""
        return self.at(self._step)

    def at(self, step: int, *, advance: bool = False) -> str:
        if step < 0:
            raise PipelineError(ErrorCode.CONFIG_INVALID, "step 不能为负")
        moment = self._origin + self._tick * step
        if advance:
            self._step = step + 1
        return format_ts(moment)

    def reset(self) -> None:
        self._step = 0


# ---------------------------------------------------------------- 授权与来源


@dataclass(frozen=True)
class SourceBinding:
    """一个来源在某次使用时的绑定：身份 + 版本 + 许可 + 内容指纹。

    偏好对与蒸馏三元组都必须带上它，而且只能由 :mod:`dpo_policy.provenance`
    的授权闸门产出 —— 其它模块不允许自己 new 一个"看起来对"的绑定。
    """

    source_id: str
    version: str
    license: str
    content_sha256: str
    authorization_ref: str = ""
    effective_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "version": self.version,
            "license": self.license,
            "content_sha256": self.content_sha256,
            "authorization_ref": self.authorization_ref,
            "effective_at": self.effective_at,
        }


@dataclass(frozen=True)
class SourceRecord:
    """授权来源语料里的一条资料（samples/sources.jsonl 的一行）。"""

    source_id: str
    version: str
    license: str
    title: str
    text: str
    uri: str = ""
    owner_zone: str = "enterprise-kb"
    tags: tuple[str, ...] = ()

    def content_sha256(self) -> str:
        # 指纹只覆盖"内容"本身（身份/版本/标题/正文），不含 license 等授权元数据。
        # 这样登记表里的 license 可以被修订而不触发内容指纹漂移，反之正文一改必漂。
        return content_hash(
            {
                "source_id": self.source_id,
                "version": self.version,
                "title": self.title,
                "text": self.text,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "version": self.version,
            "license": self.license,
            "title": self.title,
            "text": self.text,
            "uri": self.uri,
            "owner_zone": self.owner_zone,
            "tags": list(self.tags),
            "content_sha256": self.content_sha256(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SourceRecord":
        return cls(
            source_id=str(raw.get("source_id", "")).strip(),
            version=str(raw.get("version", "")).strip(),
            license=str(raw.get("license", "")).strip(),
            title=str(raw.get("title", "")).strip(),
            text=str(raw.get("text", "")),
            uri=str(raw.get("uri", "")),
            owner_zone=str(raw.get("owner_zone", "enterprise-kb")),
            tags=tuple(str(t) for t in (raw.get("tags") or ())),
        )


# ---------------------------------------------------------------- 候选与偏好对


@dataclass(frozen=True)
class ContrastSpec:
    """一条偏好对的对比规格：凭什么说 chosen 比 rejected 好。

    ``axis`` 是本次对比的唯一决定性维度；``margin`` 是该轴上的分差；
    ``axis_deltas`` 是全部轴的分差快照，用来做"其它轴不许反超"的检查。
    """

    axis: str
    margin: float
    axis_deltas: Mapping[str, float] = field(default_factory=dict)
    rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "axis": self.axis,
            "margin": round(float(self.margin), 6),
            "axis_deltas": {k: round(float(v), 6) for k, v in sorted(self.axis_deltas.items())},
            "rule": self.rule,
        }


@dataclass(frozen=True)
class Candidate:
    """一次候选生成（模型对同一 prompt 的一条回答）。"""

    candidate_id: str
    text: str
    score: float
    axes: Mapping[str, float] = field(default_factory=dict)
    model: str = "sim-teacher"
    simulated: bool = True

    def axis(self, name: str) -> float:
        return float(self.axes.get(name, 0.0))

    def to_dict(self, *, text_key: str = "text") -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            text_key: self.text,
            "score": round(float(self.score), 6),
            "axes": {k: round(float(v), 6) for k, v in sorted(self.axes.items())},
            "model": self.model,
            "simulated": self.simulated,
            "text_fingerprint": text_fingerprint(self.text),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Candidate":
        axes_raw = raw.get("axes") or {}
        return cls(
            candidate_id=str(raw.get("candidate_id", "")).strip(),
            text=str(raw.get("text", "")),
            score=float(as_float(raw.get("score"), 0.0) or 0.0),
            axes={str(k): float(as_float(v, 0.0) or 0.0) for k, v in dict(axes_raw).items()},
            model=str(raw.get("model", "sim-teacher")),
            simulated=bool(raw.get("simulated", True)),
        )


@dataclass(frozen=True)
class GenerationRecord:
    """一条 prompt 的全部候选（samples/generations.jsonl 的一行）。"""

    prompt_id: str
    prompt: str
    source_ref: Mapping[str, str]
    candidates: tuple[Candidate, ...]
    task_type: str = "kb_qa"
    locale: str = "zh-CN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_id": self.prompt_id,
            "prompt": self.prompt,
            "source_ref": dict(self.source_ref),
            "task_type": self.task_type,
            "locale": self.locale,
            "candidates": [c.to_dict() for c in self.candidates],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "GenerationRecord":
        ref = raw.get("source_ref") or {}
        return cls(
            prompt_id=str(raw.get("prompt_id", "")).strip(),
            prompt=str(raw.get("prompt", "")),
            source_ref={str(k): str(v) for k, v in dict(ref).items()},
            candidates=tuple(Candidate.from_dict(c) for c in (raw.get("candidates") or ()) if isinstance(c, Mapping)),
            task_type=str(raw.get("task_type", "kb_qa")),
            locale=str(raw.get("locale", "zh-CN")),
        )


@dataclass(frozen=True)
class PreferencePair:
    """一条可训练的偏好对：prompt + chosen + rejected + 对比规格 + 来源绑定。"""

    pair_id: str
    prompt_id: str
    prompt: str
    chosen: Candidate
    rejected: Candidate
    contrast: ContrastSpec
    source: SourceBinding
    pipeline_version: str
    created_at: str
    dedupe_key: str
    anonymized: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "prompt_id": self.prompt_id,
            "prompt": self.prompt,
            "chosen": self.chosen.to_dict(),
            "rejected": self.rejected.to_dict(),
            "contrast": self.contrast.to_dict(),
            "source": self.source.to_dict(),
            "pipeline_version": self.pipeline_version,
            "created_at": self.created_at,
            "dedupe_key": self.dedupe_key,
            "anonymized": self.anonymized,
        }


def make_pair_id(prompt_id: str, chosen_text: str, rejected_text: str, axis: str) -> str:
    return ID_PREFIX_PAIR + short_hash(
        content_hash(
            {
                "prompt_id": prompt_id,
                "chosen": normalize_text(chosen_text),
                "rejected": normalize_text(rejected_text),
                "axis": axis,
            }
        )
    )


def make_triple_id(trace_id: str, instruction: str, output: str) -> str:
    return ID_PREFIX_TRIPLE + short_hash(
        content_hash(
            {
                "trace_id": trace_id,
                "instruction": normalize_text(instruction),
                "output": normalize_text(output),
            }
        )
    )


# ---------------------------------------------------------------- 轨迹与蒸馏


@dataclass(frozen=True)
class TraceStep:
    index: int
    action: str
    observation: str
    tool: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "action": self.action, "observation": self.observation, "tool": self.tool}


@dataclass(frozen=True)
class TraceRecord:
    """一次教师轨迹：prompt -> 若干步推理/工具调用 -> 最终回答（可带被拒回答）。"""

    trace_id: str
    prompt: str
    steps: tuple[TraceStep, ...]
    final_answer: str
    source_ref: Mapping[str, str]
    model: str = "sim-teacher"
    rejected_answer: str | None = None
    adapter: str = "messages"
    policy_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "prompt": self.prompt,
            "steps": [s.to_dict() for s in self.steps],
            "final_answer": self.final_answer,
            "source_ref": dict(self.source_ref),
            "model": self.model,
            "rejected_answer": self.rejected_answer,
            "adapter": self.adapter,
            "policy_refs": list(self.policy_refs),
        }


@dataclass(frozen=True)
class DistillTriple:
    """一条蒸馏样本：指令 + 输出 + 依据（rationale）+ 策略引用 + 来源绑定。"""

    triple_id: str
    trace_id: str
    instruction: str
    output: str
    rationale: tuple[str, ...]
    policy_refs: tuple[str, ...]
    target: str
    source: SourceBinding
    pipeline_version: str
    created_at: str
    dedupe_key: str
    adapter: str = "messages"

    def to_dict(self) -> dict[str, Any]:
        return {
            "triple_id": self.triple_id,
            "trace_id": self.trace_id,
            "instruction": self.instruction,
            "output": self.output,
            "rationale": list(self.rationale),
            "policy_refs": list(self.policy_refs),
            "target": self.target,
            "source": self.source.to_dict(),
            "pipeline_version": self.pipeline_version,
            "created_at": self.created_at,
            "dedupe_key": self.dedupe_key,
            "adapter": self.adapter,
        }


@dataclass(frozen=True)
class PolicyCard:
    """策略卡：把多条三元组里的依据聚成一条可执行规则。"""

    rule_id: str
    title: str
    statement: str
    policy_refs: tuple[str, ...]
    support: int
    source_ids: tuple[str, ...] = ()
    enforced_by: str = "offline-regression"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "statement": self.statement,
            "policy_refs": list(self.policy_refs),
            "support": self.support,
            "source_ids": list(self.source_ids),
            "enforced_by": self.enforced_by,
        }


# ---------------------------------------------------------------- 回归


@dataclass(frozen=True)
class GoldenCase:
    """一条离线回归用例。"""

    case_id: str
    prompt: str
    available_sources: tuple[Mapping[str, str], ...]
    expected_action: str
    required_source_ids: tuple[str, ...] = ()
    must_cite: tuple[str, ...] = ()
    forbidden_patterns: tuple[str, ...] = ()
    note: str = ""
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "prompt": self.prompt,
            "available_sources": [dict(s) for s in self.available_sources],
            "expected_action": self.expected_action,
            "required_source_ids": list(self.required_source_ids),
            "must_cite": list(self.must_cite),
            "forbidden_patterns": list(self.forbidden_patterns),
            "note": self.note,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "GoldenCase":
        return cls(
            case_id=str(raw.get("case_id", "")).strip(),
            prompt=str(raw.get("prompt", "")),
            available_sources=tuple(dict(s) for s in (raw.get("available_sources") or ()) if isinstance(s, Mapping)),
            expected_action=str(raw.get("expected_action", "")),
            required_source_ids=tuple(str(s) for s in (raw.get("required_source_ids") or ())),
            must_cite=tuple(str(s) for s in (raw.get("must_cite") or ())),
            forbidden_patterns=tuple(str(s) for s in (raw.get("forbidden_patterns") or ())),
            note=str(raw.get("note", "")),
            tags=tuple(str(t) for t in (raw.get("tags") or ())),
        )


@dataclass(frozen=True)
class RegressionCaseResult:
    case_id: str
    expected_action: str
    actual_action: str
    passed: bool
    violations: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "expected_action": self.expected_action,
            "actual_action": self.actual_action,
            "passed": self.passed,
            "violations": list(self.violations),
            "citations": list(self.citations),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class RegressionReport:
    """一次离线回归的结果：逐例 + 汇总指标 + 基线对比 + 闸门判定。"""

    generated_at: str
    cases: tuple[RegressionCaseResult, ...]
    metrics: Mapping[str, Any]
    baseline: Mapping[str, Any]
    deltas: Mapping[str, Any]
    gate: Mapping[str, Any]

    @property
    def ok(self) -> bool:
        return bool(self.gate.get("ok"))

    @property
    def failed_cases(self) -> tuple[RegressionCaseResult, ...]:
        return tuple(c for c in self.cases if not c.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "ok": self.ok,
            "metrics": dict(self.metrics),
            "baseline": dict(self.baseline),
            "deltas": dict(self.deltas),
            "gate": dict(self.gate),
            "cases": [c.to_dict() for c in self.cases],
            "failed_case_ids": [c.case_id for c in self.failed_cases],
        }


def ensure_target(value: str) -> str:
    """把 target 归一到 sft/dpo，并拒绝其它取值。"""
    target = str(value or "").strip().lower()
    if target not in TARGETS:
        raise PipelineError(
            ErrorCode.DISTILL_SCHEMA_INVALID,
            f"target 必须是 {', '.join(TARGETS)} 之一，收到 {value!r}",
        )
    return target


def ensure_action(value: str) -> str:
    action = str(value or "").strip()
    if action not in ACTIONS:
        raise PipelineError(
            ErrorCode.REGRESSION_CASE_INVALID,
            f"expected_action 必须是 {', '.join(ACTIONS)} 之一，收到 {value!r}",
        )
    return action
