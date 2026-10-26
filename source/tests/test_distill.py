"""distill / regression 的纯逻辑测试（不依赖第三方框架）。

约定（见 tests/harness.py）：顶层 ``run() -> int``，最后一行打印 ``N/M tests passed``，
``__main__`` 里 ``sys.exit(run())``。

关于 provenance / anonymize：这两个模块由同一交付物的另一位实现者并行提供。测试优先
import 真实模块；真实模块还没出现时退回到本文件内的轻量替身（stub），以便先验证
distill / regression 的纯逻辑。真实模块出现后无需改测试 —— import 成功即自动切换，
每轮开头会打印 ``[modules] provenance=real|stub anonymize=real|stub`` 供验收核对。
stub 只覆盖本测试用到的语义（授权白名单、稳定伪名、残留扫描），不是交付物的一部分。
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
from collections import namedtuple
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
for _path in (str(ROOT), str(TESTS_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from dpo_policy.config import Config, load_config  # noqa: E402
from dpo_policy.distill import (  # noqa: E402
    BaseTraceAdapter,
    DistillResult,
    MessagesAdapter,
    ToolTraceAdapter,
    build_policy_cards,
    distill_traces,
    get_adapter,
)
from dpo_policy.model import (  # noqa: E402
    ACTION_ABSTAIN,
    ACTION_ANSWER,
    ACTION_REFUSE,
    ACTIONS,
    DistillTriple,
    ErrorCode,
    GoldenCase,
    LogicalClock,
    PipelineError,
    PolicyCard,
    SourceBinding,
    canonical_json,
    text_fingerprint,
)
from dpo_policy.regression import (  # noqa: E402
    Decision,
    PolicyEngine,
    judge_case,
    run_regression,
)
from tests.harness import Case, expect_pipeline_error, run_cases  # noqa: E402

# ---------------------------------------------------------------- 替身（真实模块缺席时用）


_StubHit = namedtuple("_StubHit", "kind start end digest")


class _StubSourceRegistry:
    """授权白名单替身：只按登记表判 (source_id, version) 与许可。"""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._index = {entry.key(): entry for entry in cfg.registry}

    @classmethod
    def from_config(cls, cfg: Config) -> "_StubSourceRegistry":
        return cls(cfg)

    def entries(self):
        return tuple(self._cfg.registry)

    def resolve(self, source_ref: Mapping[str, str], *, record_id: str = "") -> SourceBinding:
        if not isinstance(source_ref, Mapping):
            raise PipelineError(ErrorCode.SOURCE_SCHEMA_INVALID, "source_ref 必须是对象", record_id=record_id or None)
        source_id = str(source_ref.get("source_id", "") or "").strip()
        version = str(source_ref.get("version", "") or "").strip()
        if not source_id:
            raise PipelineError(ErrorCode.SOURCE_UNKNOWN, "source_ref 缺少 source_id", record_id=record_id or None)
        entry = self._index.get((source_id, version))
        if entry is None:
            same_id = [key for key in self._index if key[0] == source_id]
            if same_id:
                raise PipelineError(
                    ErrorCode.SOURCE_VERSION_MISMATCH,
                    "登记表里没有该版本",
                    record_id=record_id or None,
                )
            raise PipelineError(ErrorCode.SOURCE_UNKNOWN, "登记表里没有该来源", record_id=record_id or None)
        if not self._cfg.license_allowed(entry.license):
            raise PipelineError(ErrorCode.SOURCE_UNAUTHORIZED, "许可不在允许清单内", record_id=record_id or None)
        return SourceBinding(
            source_id=entry.source_id,
            version=entry.version,
            license=entry.license,
            content_sha256=entry.content_sha256,
            authorization_ref=entry.authorization_ref,
            effective_at=entry.effective_at,
        )


class _StubAnonymizer:
    """脱敏替身：稳定伪名（同原文同伪名）+ 残留扫描；block 模式命中即抛 ANON_LEAK。"""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._salt = cfg.anon_salt
        self._pseudonym_len = cfg.pseudonym_len
        self._rules = [(rule.kind, rule.compile(), rule.replacement) for rule in cfg.redaction_rules]
        self._leak = [(kind, re.compile(pattern)) for kind, pattern in cfg.leak_patterns]

    @classmethod
    def from_config(cls, cfg: Config) -> "_StubAnonymizer":
        return cls(cfg)

    def _pseudonym(self, kind: str, value: str) -> str:
        digest = hashlib.sha256(f"{self._salt}|{kind}|{value}".encode("utf-8")).hexdigest()
        return digest[: self._pseudonym_len]

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError(f"redact_text expects str, got {type(text).__name__}")
        out = text
        for kind, pattern, replacement in self._rules:
            out = pattern.sub(
                lambda match, kind=kind, replacement=replacement: replacement.replace(
                    "{digest}", self._pseudonym(kind, match.group(0))
                ),
                out,
            )
        return out

    def redact_mapping(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, Mapping):
            return {key: self.redact_mapping(value) for key, value in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_mapping(value) for value in obj]
        return obj

    def scan(self, text: str):
        hits = []
        for kind, pattern in self._leak:
            for match in pattern.finditer(text):
                hits.append(_StubHit(kind=kind, start=match.start(), end=match.end(), digest="0"))
        hits.sort(key=lambda hit: (hit.start, hit.kind))
        return tuple(hits)

    def assert_clean(self, text: str, *, record_id: str = ""):
        hits = self.scan(text)
        if hits and self._cfg.leak_policy == "block":
            raise PipelineError(
                ErrorCode.ANON_LEAK,
                "脱敏后仍检出残留个人信息模式",
                record_id=record_id or None,
                detail={"kinds": sorted({hit.kind for hit in hits})},
            )
        return hits

    def mapping_digest(self) -> str:
        payload = [[kind, pattern] for kind, pattern in sorted(self._leak)]
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


try:  # pragma: no cover - 取决于并行实现进度
    from dpo_policy.provenance import SourceRegistry  # type: ignore[assignment]

    _PROVENANCE_REAL = True
except ImportError:  # pragma: no cover
    SourceRegistry = _StubSourceRegistry  # type: ignore[assignment]
    _PROVENANCE_REAL = False

try:  # pragma: no cover
    from dpo_policy.anonymize import Anonymizer  # type: ignore[assignment]

    _ANON_REAL = True
except ImportError:  # pragma: no cover
    Anonymizer = _StubAnonymizer  # type: ignore[assignment]
    _ANON_REAL = False


class _LeakyAnonymizer:
    """把脱敏关掉、但保留真实自检的包装器：用来验证"残留必须整条拒绝"这条闸门。"""

    def __init__(self, base: Any) -> None:
        self._base = base

    def redact_text(self, text: str) -> str:
        return text

    def redact_mapping(self, obj: Any) -> Any:
        return obj

    def scan(self, text: str):
        return self._base.scan(text)

    def assert_clean(self, text: str, *, record_id: str = ""):
        return self._base.assert_clean(text, record_id=record_id)

    def mapping_digest(self) -> str:
        return self._base.mapping_digest()


# ---------------------------------------------------------------- 公共夹具

MESSAGES_PROMPT = "请说明 P1 工单的响应时限，并给出依据。"
MESSAGES_ANSWER = "P1 工单响应时限为 1 小时，依据工单分级规范第 3 版。"

_BASE_CFG: Config | None = None


def _cfg() -> Config:
    global _BASE_CFG
    if _BASE_CFG is None:
        _BASE_CFG = load_config(ROOT)
    return _BASE_CFG


def _clock() -> LogicalClock:
    return LogicalClock(_cfg().clock_start, _cfg().clock_tick_seconds)


def _registry():
    return SourceRegistry.from_config(_cfg())


def _anon():
    return Anonymizer.from_config(_cfg())


def _replace_regression(**sections: Any) -> Config:
    base = _cfg()
    regression = dict(base.regression)
    regression.update(sections)
    return dataclasses.replace(base, regression=regression)


def _replace_distill(**values: Any) -> Config:
    base = _cfg()
    distill = dict(base.distill)
    distill.update(values)
    return dataclasses.replace(base, distill=distill)


def _cfg_leak_policy(policy: str) -> Config:
    leak = dict(_cfg().regression["leak_checks"])
    leak["policy"] = policy
    return _replace_regression(leak_checks=leak)


def _cfg_judge(**flags: Any) -> Config:
    judge = dict(_cfg().regression["judge"])
    judge.update(flags)
    return _replace_regression(judge=judge)


def _cfg_thresholds(*, min_pass_rate: float = 0.9, max_regressions: int = 0) -> Config:
    return _replace_regression(
        thresholds={"min_pass_rate": min_pass_rate, "max_regressions": max_regressions}
    )


def _cfg_baseline(**values: Any) -> Config:
    baseline = dict(_cfg().regression["baseline"])
    baseline.update(values)
    return _replace_regression(baseline=baseline)


def _messages_raw(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "trace_id": "TR-201",
        "prompt": MESSAGES_PROMPT,
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "model": "sim-teacher",
        "adapter": "messages",
        "policy_refs": ["R-CITE-01"],
        "messages": [
            {"role": "system", "content": "你是企业客服助手。"},
            {"role": "user", "content": MESSAGES_PROMPT},
            {"role": "assistant", "content": "先查工单分级规范确定 P1 的时限。"},
            {
                "role": "tool",
                "name": "kb_search",
                "content": "命中 SRC-KB-001 第 3 版第 2 条：P1 响应时限 1 小时。",
            },
            {"role": "assistant", "content": MESSAGES_ANSWER},
        ],
        "rejected_answer": "P1 大概一天吧，不用查资料。",
    }
    raw.update(overrides)
    return raw


def _tool_raw(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "trace_id": "TR-301",
        "prompt": "工单分级规范里 P0 的响应时限是多少？",
        "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
        "model": "sim-teacher",
        "adapter": "tool_trace",
        "policy_refs": ["R-CITE-01", "R-AUTH-01"],
        "steps": [
            {"action": "plan", "tool": "", "observation": "先定位工单分级规范这一份授权资料。"},
            {"action": "search", "tool": "kb_search", "observation": "命中 SRC-KB-001 第 3 版第 1 条。"},
            {"action": "read", "tool": "kb_read", "observation": "P0 须在 15 分钟内响应并同步值班负责人。"},
        ],
        "final_answer": "P0 工单须在 15 分钟内响应并同步值班负责人，依据工单分级规范第 3 版。",
    }
    raw.update(overrides)
    return raw


def _distill(traces: Any, *, cfg: Config | None = None, anonymizer: Any = None) -> DistillResult:
    return distill_traces(
        traces,
        _registry(),
        _anon() if anonymizer is None else anonymizer,
        _cfg() if cfg is None else cfg,
        _clock(),
    )


def _reasons(result: DistillResult) -> list[str]:
    return [str(item["reason"]) for item in result.rejected]


def _distill_payload(result: DistillResult) -> dict[str, Any]:
    return {
        "triples": [triple.to_dict() for triple in result.triples],
        "cards": [card.to_dict() for card in result.cards],
        "stats": dict(result.stats),
        "rejected": [dict(item) for item in result.rejected],
    }


def _binding(source_id: str = "SRC-KB-001", version: str = "v3") -> SourceBinding:
    return SourceBinding(
        source_id=source_id,
        version=version,
        license="customer-authorized",
        content_sha256="0" * 64,
        authorization_ref="AUTH-2026-0041",
        effective_at="2026-08-15",
    )


def _make_triple(
    policy_refs: tuple[str, ...],
    *,
    source_id: str = "SRC-KB-001",
    instruction: str = "指令",
    output: str = "输出",
    triple_id: str = "tri_0000000000000001",
) -> DistillTriple:
    return DistillTriple(
        triple_id=triple_id,
        trace_id="TR-000",
        instruction=instruction,
        output=output,
        rationale=("步骤1[assistant] 先查授权资料。",),
        policy_refs=policy_refs,
        target="sft",
        source=_binding(source_id),
        pipeline_version=_cfg().pipeline_version,
        created_at=_cfg().clock_start,
        dedupe_key="k",
        adapter="messages",
    )


def _cards() -> tuple[PolicyCard, ...]:
    index = _cfg().policy_rule_index()
    support = {"R-AUTH-01": 5, "R-CITE-01": 3, "R-REFUSE-02": 1}
    out = []
    for rule_id in sorted(support):
        rule = index[rule_id]
        out.append(
            PolicyCard(
                rule_id=rule.rule_id,
                title=rule.title,
                statement=rule.statement,
                policy_refs=(rule.rule_id,),
                support=support[rule_id],
                source_ids=("SRC-KB-001",),
                enforced_by=rule.enforcement,
            )
        )
    return tuple(out)


def _engine(cfg: Config | None = None) -> PolicyEngine:
    return PolicyEngine(_cards(), _cfg() if cfg is None else cfg)


def _case(**overrides: Any) -> GoldenCase:
    raw: dict[str, Any] = {
        "case_id": "CASE-01",
        "prompt": "P1 工单的响应时限是多少？",
        "available_sources": [{"source_id": "SRC-KB-001", "version": "v3", "authorized": True}],
        "expected_action": ACTION_ANSWER,
        "required_source_ids": ["SRC-KB-001"],
        "must_cite": ["SRC-KB-001"],
        "forbidden_patterns": [],
        "note": "",
        "tags": ["citation"],
    }
    raw.update(overrides)
    return GoldenCase.from_dict(raw)


def _decision(**overrides: Any) -> Decision:
    raw: dict[str, Any] = {
        "action": ACTION_ANSWER,
        "answer": "依据 [S:SRC-KB-001@v3] 回答：P1 响应时限 1 小时。",
        "citations": ({"source_id": "SRC-KB-001", "version": "v3"},),
        "policy_refs": ("R-CITE-01",),
        "reasons": (),
    }
    raw.update(overrides)
    return Decision(**raw)


# ---------------------------------------------------------------- 适配器用例


def t_adapter_messages_basic() -> None:
    record = get_adapter("messages").parse(_messages_raw())
    assert record.adapter == "messages"
    assert record.trace_id == "TR-201"
    assert [step.index for step in record.steps] == [1, 2], record.steps
    assert record.steps[0].action == "assistant"
    assert record.steps[1].action == "tool:kb_search"
    assert record.steps[1].tool == "kb_search"
    assert record.final_answer == MESSAGES_ANSWER
    assert record.source_ref == {"source_id": "SRC-KB-001", "version": "v3"}
    assert record.policy_refs == ("R-CITE-01",)


def t_adapter_messages_final_answer_default() -> None:
    raw = _messages_raw()
    raw.pop("final_answer", None)
    record = get_adapter("messages").parse(raw)
    assert record.final_answer == MESSAGES_ANSWER


def t_adapter_messages_explicit_final_answer() -> None:
    raw = _messages_raw(final_answer="P1 响应时限为 1 小时（依据工单分级规范第 3 版）。")
    record = get_adapter("messages").parse(raw)
    assert record.final_answer.startswith("P1 响应时限为 1 小时")
    # 最后一条 assistant 仍然被排除在步骤外，步骤数不变
    assert len(record.steps) == 2


def t_adapter_messages_missing_messages() -> None:
    raw = _messages_raw()
    raw.pop("messages")
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_not_list() -> None:
    raw = _messages_raw(messages="不是一个数组")
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_empty_list() -> None:
    raw = _messages_raw(messages=[])
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_bad_role() -> None:
    raw = _messages_raw(
        messages=[
            {"role": "user", "content": MESSAGES_PROMPT},
            {"role": "critic", "content": "看不懂的角色"},
            {"role": "assistant", "content": MESSAGES_ANSWER},
        ]
    )
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_bad_content() -> None:
    raw = _messages_raw(
        messages=[
            {"role": "user", "content": MESSAGES_PROMPT},
            {"role": "assistant", "content": 42},
            {"role": "assistant", "content": MESSAGES_ANSWER},
        ]
    )
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_missing_trace_id() -> None:
    raw = _messages_raw(trace_id="   ")
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_missing_prompt() -> None:
    raw = _messages_raw()
    raw.pop("prompt")
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_declared_mismatch() -> None:
    raw = _messages_raw(adapter="tool_trace")
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_no_assistant() -> None:
    raw = _messages_raw(
        messages=[
            {"role": "system", "content": "只做说明。"},
            {"role": "user", "content": MESSAGES_PROMPT},
        ]
    )
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_messages_bad_rejected_answer() -> None:
    raw = _messages_raw(rejected_answer=123)
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("messages").parse(raw))


def t_adapter_tool_basic() -> None:
    record = get_adapter("tool_trace").parse(_tool_raw())
    assert record.adapter == "tool_trace"
    assert [step.index for step in record.steps] == [1, 2, 3]
    assert [step.action for step in record.steps] == ["plan", "search", "read"]
    assert record.steps[1].tool == "kb_search"
    assert record.rejected_answer is None


def t_adapter_tool_missing_steps() -> None:
    raw = _tool_raw()
    raw.pop("steps")
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_tool_steps_not_list() -> None:
    raw = _tool_raw(steps="plan,search,read")
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_tool_step_not_mapping() -> None:
    raw = _tool_raw(steps=["plan", {"action": "read", "observation": "x"}])
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_tool_missing_action() -> None:
    raw = _tool_raw(steps=[{"observation": "只有观察没有动作。"}])
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_tool_bad_observation() -> None:
    raw = _tool_raw(steps=[{"action": "plan", "observation": 3}])
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_tool_missing_final_answer() -> None:
    raw = _tool_raw()
    raw.pop("final_answer")
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_tool_bad_rejected_answer() -> None:
    raw = _tool_raw(rejected_answer=["不是字符串"])
    expect_pipeline_error(ErrorCode.TRACE_INVALID, lambda: get_adapter("tool_trace").parse(raw))


def t_adapter_names() -> None:
    assert get_adapter("messages").name == "messages"
    assert get_adapter("tool_trace").name == "tool_trace"
    assert isinstance(get_adapter("messages"), BaseTraceAdapter)
    assert isinstance(get_adapter("messages"), MessagesAdapter)
    assert isinstance(get_adapter("tool_trace"), ToolTraceAdapter)


def t_adapter_unknown_name() -> None:
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter("react_agent"))
    expect_pipeline_error(ErrorCode.TRACE_ADAPTER_INVALID, lambda: get_adapter(""))


# ---------------------------------------------------------------- 蒸馏用例


def t_distill_dpo_target() -> None:
    result = _distill([_messages_raw()])
    assert len(result.triples) == 1
    triple = result.triples[0]
    assert triple.target == "dpo"
    assert triple.adapter == "messages"
    assert triple.instruction == MESSAGES_PROMPT
    assert triple.output == MESSAGES_ANSWER
    assert triple.source.source_id == "SRC-KB-001"
    assert triple.pipeline_version == _cfg().pipeline_version
    assert result.stats["targets"] == {"dpo": 1, "sft": 0}


def t_distill_sft_target() -> None:
    result = _distill([_tool_raw()])
    triple = result.triples[0]
    assert triple.target == "sft"
    assert triple.adapter == "tool_trace"
    assert result.stats["targets"] == {"dpo": 0, "sft": 1}


def t_distill_policy_refs_injected() -> None:
    result = _distill([_messages_raw(policy_refs=[]), _tool_raw(policy_refs=[])])
    required = tuple(sorted(_cfg().distill["required_policy_refs"]))
    for triple in result.triples:
        assert triple.policy_refs == required, triple.policy_refs


def t_distill_policy_refs_sorted_dedup() -> None:
    result = _distill([_tool_raw(policy_refs=["R-CITE-01", "R-PII-01", "R-CITE-01"])])
    triple = result.triples[0]
    assert triple.policy_refs == tuple(sorted({"R-CITE-01", "R-PII-01", "R-AUTH-01"}))
    assert len(set(triple.policy_refs)) == len(triple.policy_refs)


def t_distill_duplicate_rejected() -> None:
    duplicate = _messages_raw(trace_id="TR-202")
    result = _distill([_messages_raw(), duplicate])
    assert len(result.triples) == 1
    assert _reasons(result) == [ErrorCode.DISTILL_DUPLICATE]
    assert result.stats["duplicates"] == 1
    assert result.stats["accepted"] == 1 and result.stats["rejected"] == 1


def t_distill_duplicate_across_adapters() -> None:
    other = _tool_raw(trace_id="TR-302", prompt=MESSAGES_PROMPT, final_answer=MESSAGES_ANSWER)
    result = _distill([_messages_raw(), other])
    assert len(result.triples) == 1
    assert _reasons(result) == [ErrorCode.DISTILL_DUPLICATE]


def t_distill_unknown_adapter_rejected() -> None:
    bad = _messages_raw(trace_id="TR-101", adapter="react_v2")
    result = _distill([bad, _tool_raw()])
    assert _reasons(result) == [ErrorCode.TRACE_ADAPTER_INVALID]
    assert len(result.triples) == 1


def t_distill_adapter_not_allowed_by_config() -> None:
    cfg = _replace_distill(adapters=["messages"])
    result = _distill([_tool_raw(), _messages_raw()], cfg=cfg)
    assert _reasons(result) == [ErrorCode.TRACE_ADAPTER_INVALID]
    assert [triple.adapter for triple in result.triples] == ["messages"]


def t_distill_unauthorized_source_rejected() -> None:
    bad = _messages_raw(
        trace_id="TR-102",
        source_ref={"source_id": "SRC-WEB-999", "version": "v1"},
    )
    result = _distill([bad, _tool_raw()])
    assert len(result.triples) == 1
    assert _reasons(result)[0] in {
        ErrorCode.SOURCE_UNKNOWN,
        ErrorCode.SOURCE_UNAUTHORIZED,
        ErrorCode.SOURCE_SCHEMA_INVALID,
        ErrorCode.SOURCE_VERSION_MISMATCH,
    }


def t_distill_version_mismatch_rejected() -> None:
    bad = _messages_raw(trace_id="TR-103", source_ref={"source_id": "SRC-KB-001", "version": "v9"})
    result = _distill([bad, _tool_raw()])
    assert len(result.triples) == 1
    assert _reasons(result)[0] in {ErrorCode.SOURCE_VERSION_MISMATCH, ErrorCode.SOURCE_UNKNOWN}


def t_distill_short_answer_rejected() -> None:
    raw = _messages_raw(
        trace_id="TR-104",
        messages=[
            {"role": "user", "content": MESSAGES_PROMPT},
            {"role": "assistant", "content": "短答案"},
        ],
    )
    result = _distill([raw, _tool_raw()])
    assert _reasons(result) == [ErrorCode.TRACE_INVALID]
    assert len(result.triples) == 1


def t_distill_empty_steps_rejected() -> None:
    raw = _messages_raw(
        trace_id="TR-105",
        final_answer=MESSAGES_ANSWER,
        messages=[
            {"role": "system", "content": "只做说明。"},
            {"role": "user", "content": MESSAGES_PROMPT},
        ],
    )
    result = _distill([raw, _tool_raw()])
    assert _reasons(result) == [ErrorCode.TRACE_INVALID]
    assert result.stats["rejected"] == 1


def t_distill_unknown_policy_ref_rejected() -> None:
    raw = _messages_raw(trace_id="TR-106", policy_refs=["R-NOPE-99"])
    result = _distill([raw, _tool_raw()])
    assert _reasons(result) == [ErrorCode.DISTILL_SCHEMA_INVALID]


def t_distill_empty_input() -> None:
    expect_pipeline_error(ErrorCode.DISTILL_EMPTY, lambda: _distill([]))


def t_distill_all_rejected() -> None:
    """输入非空但全被拒：不抛异常，返回空三元组 + 逐条拒绝原因（负向对照依赖这个契约）。"""
    bad = _messages_raw(trace_id="TR-107", source_ref={"source_id": "SRC-WEB-999", "version": "v1"})
    result = _distill([bad])
    assert result.triples == (), "全部被拒时不应产出三元组"
    assert _reasons(result) == [ErrorCode.SOURCE_UNKNOWN], _reasons(result)
    assert result.stats["traces"] == 1 and result.stats["accepted"] == 0, result.stats


def t_distill_pii_redacted() -> None:
    prompt = "客户张三（手机 13800138000，邮箱 zhang.san@example.com）问：P1 响应时限是多少？"
    answer = "P1 响应时限 1 小时，依据 SRC-KB-001；如需回访可联系 zhang.san@example.com。"
    raw = _messages_raw(
        trace_id="TR-901",
        prompt=prompt,
        messages=[
            {"role": "user", "content": prompt},
            {
                "role": "tool",
                "name": "crm_lookup",
                "content": "客户联系人张三，手机 13800138000，所属 华辰精密。",
            },
            {"role": "assistant", "content": answer},
        ],
    )
    anonymizer = _anon()
    triple = _distill([raw], anonymizer=anonymizer).triples[0]
    blob = " ".join([triple.instruction, triple.output, *triple.rationale])
    for secret in ("13800138000", "zhang.san@example.com", "张三", "华辰精密"):
        assert secret not in blob, f"PII 未脱敏: {secret}"
    assert anonymizer.scan(triple.instruction) == ()
    assert anonymizer.scan(triple.output) == ()
    assert all(anonymizer.scan(line) == () for line in triple.rationale)


def t_distill_pii_in_rationale_redacted() -> None:
    raw = _tool_raw(
        trace_id="TR-902",
        steps=[
            {"action": "lookup", "tool": "crm", "observation": "联系人 李四 身份证 110101199003077777。"}
        ],
    )
    anonymizer = _anon()
    triple = _distill([raw], anonymizer=anonymizer).triples[0]
    assert "李四" not in triple.rationale[0]
    assert "110101199003077777" not in triple.rationale[0]
    assert anonymizer.scan(triple.rationale[0]) == ()


def t_distill_anon_leak_rejected() -> None:
    leaky = _LeakyAnonymizer(_anon())
    bad = _messages_raw(
        trace_id="TR-903",
        prompt="联系人邮箱 zhang.san@example.com 说 P1 要尽快处理。",
        messages=[
            {"role": "user", "content": "联系人邮箱 zhang.san@example.com 说 P1 要尽快处理。"},
            {"role": "tool", "name": "crm_lookup", "content": "查到联系人邮箱 zhang.san@example.com。"},
            {"role": "assistant", "content": MESSAGES_ANSWER},
        ],
    )
    result = _distill([bad, _tool_raw()], anonymizer=leaky)
    assert _reasons(result) == [ErrorCode.ANON_LEAK]
    assert result.stats["accepted"] == 1


def t_distill_rationale_min_steps() -> None:
    cfg = _replace_distill(min_rationale_steps=3)
    result = _distill([_messages_raw(), _tool_raw()], cfg=cfg)
    assert _reasons(result) == [ErrorCode.TRACE_INVALID]
    assert len(result.triples) == 1


def t_distill_rationale_max_truncation() -> None:
    cfg = _replace_distill(max_rationale_steps=2)
    triple = _distill([_tool_raw()], cfg=cfg).triples[0]
    assert len(triple.rationale) == 2
    assert triple.rationale[-1].endswith("…")


def t_distill_rationale_char_limit() -> None:
    cfg = _replace_distill(max_rationale_chars=12)
    triple = _distill([_tool_raw()], cfg=cfg).triples[0]
    assert triple.rationale
    assert all(len(line) <= 12 for line in triple.rationale), triple.rationale


def t_distill_rationale_format() -> None:
    cfg = _replace_distill(max_rationale_chars=240)
    triple = _distill([_tool_raw()], cfg=cfg).triples[0]
    assert triple.rationale[0].startswith("步骤1[plan] ")
    assert triple.rationale[1].startswith("步骤2[search] ")
    assert "kb_search" in triple.rationale[1] or "命中" in triple.rationale[1]


def t_distill_target_not_allowed() -> None:
    cfg = _replace_distill(targets=["sft"])
    result = _distill([_messages_raw(), _tool_raw()], cfg=cfg)
    assert _reasons(result) == [ErrorCode.DISTILL_SCHEMA_INVALID]
    assert [triple.target for triple in result.triples] == ["sft"]


def t_distill_stats_keys() -> None:
    result = _distill([_messages_raw(), _tool_raw()])
    for key in (
        "traces",
        "accepted",
        "rejected",
        "targets",
        "adapters",
        "policy_rules",
        "duplicates",
        "rationale_steps_avg",
        "missing_required_refs",
    ):
        assert key in result.stats, key
    assert result.stats["traces"] == 2
    assert result.stats["missing_required_refs"] == []
    assert set(result.stats["adapters"]) >= {"messages", "tool_trace"}


def t_distill_stats_counts() -> None:
    duplicate = _messages_raw(trace_id="TR-203")
    result = _distill([_messages_raw(), duplicate, _tool_raw()])
    stats = result.stats
    assert stats["traces"] == 3
    assert stats["accepted"] == 2
    assert stats["rejected"] == 1
    assert stats["duplicates"] == 1
    assert stats["targets"] == {"dpo": 1, "sft": 1}
    assert stats["adapters"] == {"messages": 1, "tool_trace": 1}
    assert stats["policy_rules"] == {"R-AUTH-01": 2, "R-CITE-01": 2}
    assert stats["rationale_steps_avg"] == 2.5


def t_distill_rejected_detail_is_clean() -> None:
    raw = _tool_raw(
        trace_id="TR-904",
        prompt="联系人邮箱 zhang.san@example.com，问 P0 时限？",
        final_answer="短",
    )
    result = _distill([raw, _tool_raw()])
    rejected = result.rejected[0]
    assert rejected["trace_id"] == "TR-904"
    assert "zhang.san@example.com" not in str(rejected["detail"])
    assert "短" not in str(rejected["detail"])


def t_distill_deterministic() -> None:
    traces = [_tool_raw(), _messages_raw()]
    first = _distill(traces)
    second = _distill(traces)
    assert canonical_json(_distill_payload(first)) == canonical_json(_distill_payload(second))


def t_distill_sorted_output() -> None:
    traces = [
        _messages_raw(trace_id="TR-310", prompt="第三个问题：P2 的响应时限是多少？"),
        _messages_raw(trace_id="TR-110", prompt="第一个问题：P1 的响应时限是多少？"),
        _messages_raw(trace_id="TR-210", prompt="第二个问题：P0 的响应时限是多少？"),
    ]
    result = _distill(traces)
    assert sorted(triple.trace_id for triple in result.triples) == ["TR-110", "TR-210", "TR-310"]
    triple_ids = [triple.triple_id for triple in result.triples]
    assert triple_ids == sorted(triple_ids)
    # 时刻按「处理顺序」（trace_id 升序）从逻辑时钟逐格发放，是固定序列而不是墙上时间
    probe = _clock()
    assert sorted(triple.created_at for triple in result.triples) == [probe.at(index) for index in range(3)]
    assert [card.rule_id for card in result.cards] == sorted(card.rule_id for card in result.cards)
    # 输入顺序打乱不改变产物：处理顺序由 trace_id 决定，与喂入顺序无关
    shuffled = _distill(list(reversed(traces)))
    assert canonical_json(_distill_payload(result)) == canonical_json(_distill_payload(shuffled))


def t_distill_cards_support() -> None:
    triples = [
        _make_triple(("R-CITE-01", "R-PII-01"), source_id="SRC-KB-001"),
        _make_triple(("R-CITE-01",), source_id="SRC-KB-002", triple_id="tri_0000000000000002"),
    ]
    cards = {card.rule_id: card for card in build_policy_cards(triples, _cfg())}
    assert sorted(cards) == ["R-CITE-01", "R-PII-01"]
    assert [card.rule_id for card in build_policy_cards(triples, _cfg())] == ["R-CITE-01", "R-PII-01"]
    assert cards["R-CITE-01"].support == 2
    assert cards["R-PII-01"].support == 1
    assert cards["R-CITE-01"].source_ids == ("SRC-KB-001", "SRC-KB-002")
    assert cards["R-PII-01"].source_ids == ("SRC-KB-001",)
    assert cards["R-PII-01"].enforced_by == _cfg().policy_rule_index()["R-PII-01"].enforcement
    assert cards["R-CITE-01"].policy_refs == ("R-CITE-01",)


def t_distill_cards_only_referenced() -> None:
    cards = build_policy_cards([_make_triple(("R-CITE-01",))], _cfg())
    assert [card.rule_id for card in cards] == ["R-CITE-01"]


def t_distill_cards_unknown_rule_skipped() -> None:
    assert build_policy_cards([_make_triple(("R-NOPE-99",))], _cfg()) == ()


def t_distill_cards_empty() -> None:
    assert build_policy_cards([], _cfg()) == ()


# ---------------------------------------------------------------- 引擎用例


def t_engine_answer() -> None:
    decision = _engine().act(_case())
    assert decision.action == ACTION_ANSWER
    assert "[S:SRC-KB-001@v3]" in decision.answer
    assert decision.citations == ({"source_id": "SRC-KB-001", "version": "v3"},)
    assert decision.policy_refs == ("R-CITE-01",)
    assert decision.reasons == ()


def t_engine_citations_sorted_dedup() -> None:
    case = _case(
        available_sources=[
            {"source_id": "SRC-KB-002", "version": "v2", "authorized": True},
            {"source_id": "SRC-KB-001", "version": "v3", "authorized": "true"},
            {"source_id": "SRC-KB-001", "version": "v3", "authorized": True},
        ],
        required_source_ids=["SRC-KB-002"],
        must_cite=["SRC-KB-002"],
    )
    decision = _engine().act(case)
    assert decision.citations == (
        {"source_id": "SRC-KB-001", "version": "v3"},
        {"source_id": "SRC-KB-002", "version": "v2"},
    )
    assert "[S:SRC-KB-002@v2]" in decision.answer


def t_engine_missing_required_source() -> None:
    case = _case(required_source_ids=["SRC-KB-999"], must_cite=[])
    decision = _engine().act(case)
    assert decision.action == ACTION_ANSWER
    assert "MISSING_SOURCE:SRC-KB-999" in decision.reasons
    assert "[S:SRC-KB-999@" not in decision.answer
    assert "[S:SRC-KB-001@v3]" in decision.answer


def t_engine_refuse_unauthorized() -> None:
    case = _case(
        available_sources=[{"source_id": "SRC-KB-001", "version": "v3", "authorized": False}],
        required_source_ids=[],
        must_cite=[],
    )
    decision = _engine().act(case)
    assert decision.action == ACTION_REFUSE
    assert decision.citations == ()
    assert "R-AUTH-01" in decision.reasons
    assert "R-AUTH-01" in decision.answer
    assert "未授权" in decision.answer


def t_engine_refuse_string_false() -> None:
    case = _case(
        available_sources=[
            {"source_id": "SRC-KB-001", "version": "v3", "authorized": "false"},
            {"source_id": "SRC-KB-002", "version": "v2", "authorized": "true"},
        ],
        required_source_ids=[],
        must_cite=[],
    )
    decision = _engine().act(case)
    assert decision.action == ACTION_REFUSE
    assert "SRC-KB-001" in decision.answer


def t_engine_abstain_missing_sources() -> None:
    case = _case(available_sources=[], required_source_ids=[], must_cite=[])
    decision = _engine().act(case)
    assert decision.action == ACTION_ABSTAIN
    assert decision.citations == ()
    assert "R-REFUSE-02" in decision.reasons
    assert "无依据" in decision.answer
    assert "[S:" not in decision.answer


def t_engine_version_and_cards() -> None:
    engine = _engine()
    assert engine.version == _cfg().pipeline_version
    assert [card.rule_id for card in engine.cards] == ["R-AUTH-01", "R-CITE-01", "R-REFUSE-02"]


def t_engine_answer_appends_top_cards() -> None:
    decision = _engine().act(_case())
    assert "R-AUTH-01" in decision.answer
    assert "R-CITE-01" in decision.answer
    # 支持度第三的规则不进要点（只取前两条）
    assert "R-REFUSE-02" not in decision.answer


def t_engine_deterministic() -> None:
    case = _case()
    first = canonical_json(_engine().act(case).to_dict())
    second = canonical_json(_engine().act(case).to_dict())
    assert first == second
    assert '"action":"answer_with_citation"' in first


# ---------------------------------------------------------------- 判定用例


def t_judge_pass() -> None:
    case = _case()
    result = judge_case(case, _engine().act(case), _cfg(), _anon())
    assert result.passed, result.violations
    assert result.violations == ()
    assert result.actual_action == ACTION_ANSWER
    assert result.citations == ("SRC-KB-001@v3",)


def t_judge_action_mismatch() -> None:
    case = _case()
    decision = _decision(action=ACTION_ABSTAIN, answer="授权来源中无依据，暂不回答。")
    result = judge_case(case, decision, _cfg(), _anon())
    assert not result.passed
    assert f"ACTION_MISMATCH(expected={ACTION_ANSWER},actual={ACTION_ABSTAIN})" in result.violations


def t_judge_missing_citation() -> None:
    case = _case(must_cite=[])
    result = judge_case(case, _decision(answer="P1 响应时限 1 小时。"), _cfg(), _anon())
    assert "MISSING_CITATION" in result.violations


def t_judge_missing_required_citation() -> None:
    case = _case(must_cite=["SRC-KB-001", "SRC-KB-002"])
    result = judge_case(case, _decision(), _cfg(), _anon())
    assert "MISSING_REQUIRED_CITATION:SRC-KB-002" in result.violations
    assert "MISSING_REQUIRED_CITATION:SRC-KB-001" not in result.violations


def t_judge_cited_source_not_visible() -> None:
    case = _case(must_cite=["SRC-KB-001"])
    decision = _decision(answer="依据 [S:SRC-KB-009@v1] 回答。")
    result = judge_case(case, decision, _cfg(), _anon())
    assert "CITED_SOURCE_NOT_VISIBLE:SRC-KB-009" in result.violations


def t_judge_forbidden_regex() -> None:
    case = _case(forbidden_patterns=["大[概约]"])
    decision = _decision(answer="依据 [S:SRC-KB-001@v3] 回答：大概一天。")
    result = judge_case(case, decision, _cfg(), _anon())
    assert "FORBIDDEN_PATTERN:大[概约]" in result.violations


def t_judge_forbidden_substring_mode() -> None:
    cfg = _cfg_judge(forbidden_patterns_are_regex=False, forbidden_match_case_sensitive=False)
    case = _case(forbidden_patterns=["大[概约]"])
    decision = _decision(answer="依据 [S:SRC-KB-001@v3] 回答：大概一天。")
    result = judge_case(case, decision, cfg, _anon())
    assert result.passed, result.violations


def t_judge_forbidden_case_insensitive() -> None:
    case = _case(forbidden_patterns=["DRAFT-ONLY"])
    decision = _decision(answer="依据 [S:SRC-KB-001@v3] 回答。 draft-only 版本。")
    result = judge_case(case, decision, _cfg(), _anon())
    assert "FORBIDDEN_PATTERN:DRAFT-ONLY" in result.violations


def t_judge_leak_block() -> None:
    case = _case(must_cite=[])
    decision = _decision(answer="依据 [S:SRC-KB-001@v3] 回答，可联系 user@example.com。")
    result = judge_case(case, decision, _cfg(), _anon())
    assert "LEAK:email" in result.violations, result.violations


def t_judge_leak_warn_only_note() -> None:
    case = _case(must_cite=[])
    decision = _decision(answer="依据 [S:SRC-KB-001@v3] 回答，可联系 user@example.com。")
    result = judge_case(case, decision, _cfg_leak_policy("warn"), _anon())
    assert not any(item.startswith("LEAK:") for item in result.violations)
    assert any(item.startswith("LEAK_WARN:") for item in result.notes), result.notes


def t_judge_unexpected_citation() -> None:
    case = _case(expected_action=ACTION_ABSTAIN, available_sources=[], must_cite=[])
    decision = _decision(action=ACTION_ABSTAIN, answer="暂不回答，但先给 [S:SRC-KB-001@v3]。")
    result = judge_case(case, decision, _cfg(), _anon())
    assert "UNEXPECTED_CITATION" in result.violations


def t_judge_refuse_without_citation_passes() -> None:
    case = _case(
        expected_action=ACTION_REFUSE,
        available_sources=[{"source_id": "SRC-KB-001", "version": "v3", "authorized": False}],
        required_source_ids=[],
        must_cite=[],
    )
    result = judge_case(case, _engine().act(case), _cfg(), _anon())
    assert result.passed, result.violations


# ---------------------------------------------------------------- 回归主流程用例


def _three_cases() -> tuple[GoldenCase, ...]:
    answer_case = _case(case_id="CASE-01", tags=["citation"])
    refuse_case = _case(
        case_id="CASE-02",
        available_sources=[{"source_id": "SRC-WEB-999", "version": "v1", "authorized": "false"}],
        expected_action=ACTION_REFUSE,
        required_source_ids=[],
        must_cite=[],
        tags=["auth"],
    )
    abstain_case = _case(
        case_id="CASE-03",
        available_sources=[],
        expected_action=ACTION_ABSTAIN,
        required_source_ids=[],
        must_cite=[],
        tags=["refusal"],
    )
    return (answer_case, refuse_case, abstain_case)


def t_run_metrics() -> None:
    report = run_regression(_three_cases(), _engine(), _cfg(), _clock(), _anon())
    metrics = report.metrics
    assert metrics["cases"] == 3
    assert metrics["passed"] == 3
    assert metrics["failed"] == 0
    assert metrics["pass_rate"] == 1.0
    assert metrics["violations"] == 0
    assert metrics["by_action"] == {
        ACTION_ABSTAIN: 1,
        ACTION_ANSWER: 1,
        ACTION_REFUSE: 1,
    }
    assert metrics["by_tag"] == {"auth": 1, "citation": 1, "refusal": 1}
    assert metrics["unauthorized_cases"] == 1
    assert metrics["abstain_cases"] == 1
    assert metrics["citation_coverage"] == 1.0
    assert report.ok


def t_run_citation_coverage_partial() -> None:
    good = _case(case_id="CASE-01")
    bad = _case(case_id="CASE-04", available_sources=[], required_source_ids=[], must_cite=[])
    report = run_regression((good, bad), _engine(), _cfg_thresholds(min_pass_rate=0.0), _clock(), _anon())
    assert report.metrics["citation_coverage"] == 0.5
    assert report.metrics["failed"] == 1


def t_run_case_invalid_duplicate() -> None:
    cases = (_case(case_id="CASE-01"), _case(case_id="CASE-01"))
    expect_pipeline_error(
        ErrorCode.REGRESSION_CASE_INVALID,
        lambda: run_regression(cases, _engine(), _cfg(), _clock(), _anon()),
        record_id="CASE-01",
    )


def t_run_case_invalid_empty_id() -> None:
    expect_pipeline_error(
        ErrorCode.REGRESSION_CASE_INVALID,
        lambda: run_regression((_case(case_id="  "),), _engine(), _cfg(), _clock(), _anon()),
    )


def t_run_case_invalid_action() -> None:
    bad = _case(expected_action="answer_from_memory")
    expect_pipeline_error(
        ErrorCode.REGRESSION_CASE_INVALID,
        lambda: run_regression((bad,), _engine(), _cfg(), _clock(), _anon()),
        record_id="CASE-01",
    )


def t_run_case_invalid_sources() -> None:
    bad = _case(available_sources=[{"source_id": "SRC-KB-001", "authorized": True}])
    expect_pipeline_error(
        ErrorCode.REGRESSION_CASE_INVALID,
        lambda: run_regression((bad,), _engine(), _cfg(), _clock(), _anon()),
        record_id="CASE-01",
    )


def t_run_gate_ok() -> None:
    report = run_regression(_three_cases(), _engine(), _cfg_thresholds(), _clock(), _anon())
    gate = report.gate
    assert gate["ok"] is True
    assert gate["min_pass_rate"] == 0.9
    assert gate["max_regressions"] == 0
    assert gate["regression_count"] == 0
    assert gate["failed_case_ids"] == []


def t_run_gate_fail_pass_rate() -> None:
    failing = _case(case_id="CASE-05", available_sources=[], required_source_ids=[], must_cite=[])
    cfg = _cfg_thresholds(min_pass_rate=1.0, max_regressions=0)
    report = run_regression((_case(case_id="CASE-01"), failing), _engine(), cfg, _clock(), _anon())
    assert report.gate["ok"] is False
    assert report.gate["pass_rate"] == 0.5
    assert report.gate["failed_case_ids"] == ["CASE-05"]
    # CASE-05 在基线里本来就是失败，因此不算"回退"
    assert report.deltas["regressions"] == []


def t_run_baseline_regression_detected() -> None:
    failing = _case(case_id="CASE-02", available_sources=[], required_source_ids=[], must_cite=[])
    cfg = _cfg_baseline(case_pass={"CASE-02": True}, pass_rate=0.9, cases=1, violations=0)
    report = run_regression((failing,), _engine(), cfg, _clock(), _anon())
    assert report.deltas["regressions"] == ["CASE-02"]
    assert report.deltas["pass_rate"] == -0.9
    assert report.deltas["violations_delta"] > 0
    assert report.gate["ok"] is False
    assert report.gate["regression_count"] == 1


def t_run_baseline_fix_detected() -> None:
    cfg = _cfg_baseline(case_pass={"CASE-01": False}, pass_rate=0.5, cases=1, violations=3)
    report = run_regression((_case(case_id="CASE-01"),), _engine(), cfg, _clock(), _anon())
    assert report.deltas["fixes"] == ["CASE-01"]
    assert report.deltas["violations_delta"] == -3
    assert report.gate["ok"] is True


def t_run_generated_at_from_clock() -> None:
    report = run_regression(_three_cases(), _engine(), _cfg(), _clock(), _anon())
    assert report.generated_at == _cfg().clock_start
    clock = _clock()
    clock.now()
    clock.now()
    later = run_regression(_three_cases(), _engine(), _cfg(), clock, _anon())
    assert later.generated_at > report.generated_at


def t_run_case_order_sorted() -> None:
    cases = (
        _case(case_id="CASE-03", tags=["third"]),
        _case(case_id="CASE-01", tags=["first"]),
        _case(case_id="CASE-02", tags=["second"]),
    )
    report = run_regression(cases, _engine(), _cfg(), _clock(), _anon())
    assert [item.case_id for item in report.cases] == ["CASE-01", "CASE-02", "CASE-03"]


def t_run_deterministic() -> None:
    cases = _three_cases()
    first = run_regression(cases, _engine(), _cfg(), _clock(), _anon())
    second = run_regression(cases, _engine(), _cfg(), _clock(), _anon())
    assert canonical_json(first.to_dict()) == canonical_json(second.to_dict())


def t_run_report_payload_shape() -> None:
    report = run_regression(_three_cases(), _engine(), _cfg(), _clock(), _anon())
    payload = report.to_dict()
    for key in ("generated_at", "ok", "metrics", "baseline", "deltas", "gate", "cases", "failed_case_ids"):
        assert key in payload, key
    assert payload["baseline"] == dict(_cfg().regression["baseline"])
    assert payload["failed_case_ids"] == []
    assert [item["case_id"] for item in payload["cases"]] == ["CASE-01", "CASE-02", "CASE-03"]


# ---------------------------------------------------------------- 汇总

CASES: list[tuple[str, Any]] = [
    ("adapter_messages_basic", t_adapter_messages_basic),
    ("adapter_messages_final_answer_default", t_adapter_messages_final_answer_default),
    ("adapter_messages_explicit_final_answer", t_adapter_messages_explicit_final_answer),
    ("adapter_messages_missing_messages", t_adapter_messages_missing_messages),
    ("adapter_messages_not_list", t_adapter_messages_not_list),
    ("adapter_messages_empty_list", t_adapter_messages_empty_list),
    ("adapter_messages_bad_role", t_adapter_messages_bad_role),
    ("adapter_messages_bad_content", t_adapter_messages_bad_content),
    ("adapter_messages_missing_trace_id", t_adapter_messages_missing_trace_id),
    ("adapter_messages_missing_prompt", t_adapter_messages_missing_prompt),
    ("adapter_messages_declared_mismatch", t_adapter_messages_declared_mismatch),
    ("adapter_messages_no_assistant", t_adapter_messages_no_assistant),
    ("adapter_messages_bad_rejected_answer", t_adapter_messages_bad_rejected_answer),
    ("adapter_tool_basic", t_adapter_tool_basic),
    ("adapter_tool_missing_steps", t_adapter_tool_missing_steps),
    ("adapter_tool_steps_not_list", t_adapter_tool_steps_not_list),
    ("adapter_tool_step_not_mapping", t_adapter_tool_step_not_mapping),
    ("adapter_tool_missing_action", t_adapter_tool_missing_action),
    ("adapter_tool_bad_observation", t_adapter_tool_bad_observation),
    ("adapter_tool_missing_final_answer", t_adapter_tool_missing_final_answer),
    ("adapter_tool_bad_rejected_answer", t_adapter_tool_bad_rejected_answer),
    ("adapter_names", t_adapter_names),
    ("adapter_unknown_name", t_adapter_unknown_name),
    ("distill_dpo_target", t_distill_dpo_target),
    ("distill_sft_target", t_distill_sft_target),
    ("distill_policy_refs_injected", t_distill_policy_refs_injected),
    ("distill_policy_refs_sorted_dedup", t_distill_policy_refs_sorted_dedup),
    ("distill_duplicate_rejected", t_distill_duplicate_rejected),
    ("distill_duplicate_across_adapters", t_distill_duplicate_across_adapters),
    ("distill_unknown_adapter_rejected", t_distill_unknown_adapter_rejected),
    ("distill_adapter_not_allowed_by_config", t_distill_adapter_not_allowed_by_config),
    ("distill_unauthorized_source_rejected", t_distill_unauthorized_source_rejected),
    ("distill_version_mismatch_rejected", t_distill_version_mismatch_rejected),
    ("distill_short_answer_rejected", t_distill_short_answer_rejected),
    ("distill_empty_steps_rejected", t_distill_empty_steps_rejected),
    ("distill_unknown_policy_ref_rejected", t_distill_unknown_policy_ref_rejected),
    ("distill_empty_input", t_distill_empty_input),
    ("distill_all_rejected", t_distill_all_rejected),
    ("distill_pii_redacted", t_distill_pii_redacted),
    ("distill_pii_in_rationale_redacted", t_distill_pii_in_rationale_redacted),
    ("distill_anon_leak_rejected", t_distill_anon_leak_rejected),
    ("distill_rationale_min_steps", t_distill_rationale_min_steps),
    ("distill_rationale_max_truncation", t_distill_rationale_max_truncation),
    ("distill_rationale_char_limit", t_distill_rationale_char_limit),
    ("distill_rationale_format", t_distill_rationale_format),
    ("distill_target_not_allowed", t_distill_target_not_allowed),
    ("distill_stats_keys", t_distill_stats_keys),
    ("distill_stats_counts", t_distill_stats_counts),
    ("distill_rejected_detail_is_clean", t_distill_rejected_detail_is_clean),
    ("distill_deterministic", t_distill_deterministic),
    ("distill_sorted_output", t_distill_sorted_output),
    ("distill_cards_support", t_distill_cards_support),
    ("distill_cards_only_referenced", t_distill_cards_only_referenced),
    ("distill_cards_unknown_rule_skipped", t_distill_cards_unknown_rule_skipped),
    ("distill_cards_empty", t_distill_cards_empty),
    ("engine_answer", t_engine_answer),
    ("engine_citations_sorted_dedup", t_engine_citations_sorted_dedup),
    ("engine_missing_required_source", t_engine_missing_required_source),
    ("engine_refuse_unauthorized", t_engine_refuse_unauthorized),
    ("engine_refuse_string_false", t_engine_refuse_string_false),
    ("engine_abstain_missing_sources", t_engine_abstain_missing_sources),
    ("engine_version_and_cards", t_engine_version_and_cards),
    ("engine_answer_appends_top_cards", t_engine_answer_appends_top_cards),
    ("engine_deterministic", t_engine_deterministic),
    ("judge_pass", t_judge_pass),
    ("judge_action_mismatch", t_judge_action_mismatch),
    ("judge_missing_citation", t_judge_missing_citation),
    ("judge_missing_required_citation", t_judge_missing_required_citation),
    ("judge_cited_source_not_visible", t_judge_cited_source_not_visible),
    ("judge_forbidden_regex", t_judge_forbidden_regex),
    ("judge_forbidden_substring_mode", t_judge_forbidden_substring_mode),
    ("judge_forbidden_case_insensitive", t_judge_forbidden_case_insensitive),
    ("judge_leak_block", t_judge_leak_block),
    ("judge_leak_warn_only_note", t_judge_leak_warn_only_note),
    ("judge_unexpected_citation", t_judge_unexpected_citation),
    ("judge_refuse_without_citation_passes", t_judge_refuse_without_citation_passes),
    ("run_metrics", t_run_metrics),
    ("run_citation_coverage_partial", t_run_citation_coverage_partial),
    ("run_case_invalid_duplicate", t_run_case_invalid_duplicate),
    ("run_case_invalid_empty_id", t_run_case_invalid_empty_id),
    ("run_case_invalid_action", t_run_case_invalid_action),
    ("run_case_invalid_sources", t_run_case_invalid_sources),
    ("run_gate_ok", t_run_gate_ok),
    ("run_gate_fail_pass_rate", t_run_gate_fail_pass_rate),
    ("run_baseline_regression_detected", t_run_baseline_regression_detected),
    ("run_baseline_fix_detected", t_run_baseline_fix_detected),
    ("run_generated_at_from_clock", t_run_generated_at_from_clock),
    ("run_case_order_sorted", t_run_case_order_sorted),
    ("run_deterministic", t_run_deterministic),
    ("run_report_payload_shape", t_run_report_payload_shape),
]


def run() -> int:
    print(
        "[modules] provenance=%s anonymize=%s"
        % ("real" if _PROVENANCE_REAL else "stub", "real" if _ANON_REAL else "stub")
    )
    return run_cases([Case(name, fn) for name, fn in CASES], title="test_distill", verbose=False)


if __name__ == "__main__":
    sys.exit(run())
