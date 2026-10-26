"""偏好对骨架的离线测试：授权闸门、脱敏闸门、偏好对筛选与产物纪律。

约定与 ``tests/harness.py`` 一致：顶层 ``run() -> int``，最后一行打印
``N/M tests passed``，可单独执行。用例只依赖标准库与交付物自身，
不需要网络、不读真实时钟。

测试数据全部在内存里构造：``samples/`` 目录下只有来源语料，没有生成记录，
所以 generation 由本文件按契约字段现场拼装；配置一律用 ``load_config(ROOT)``
拿真配置，需要改阈值时用 ``dataclasses.replace`` 派生，不落盘、不改文件。
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parent.parent
for _entry in (str(ROOT / "tests"), str(ROOT)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

from tests.harness import Case, expect_pipeline_error, run_cases  # noqa: E402

from dpo_policy.anonymize import Anonymizer, RedactionHit  # noqa: E402
from dpo_policy.config import Config, load_config  # noqa: E402
from dpo_policy.model import (  # noqa: E402
    Candidate,
    ErrorCode,
    GenerationRecord,
    LogicalClock,
    SourceBinding,
    SourceRecord,
    canonical_json,
    make_pair_id,
    normalize_text,
    text_fingerprint,
)
from dpo_policy.pairs import build_pairs  # noqa: E402
from dpo_policy.provenance import SourceRegistry  # noqa: E402
from dpo_policy.store import read_jsonl  # noqa: E402

CFG = load_config(ROOT)
REG = SourceRegistry.from_config(CFG)
ANON = Anonymizer.from_config(CFG)

AXES: tuple[str, ...] = tuple(CFG.pairs["axes"])
BASE_AXES = {axis: 0.60 for axis in AXES}

PROMPT_OK = "P0 故障的响应时限是多少？请给出依据。"
TEXT_A = "根据工单分级规范第 3 版，P0 故障须在 15 分钟内响应并同步值班负责人，跨级升级必须写明依据与影响面 [S:SRC-KB-001@v3]。"
TEXT_B = "P0 故障应该尽快处理，具体时限请咨询值班同事，必要时升级到更高级别，建议参考相关文档后再处理 [S:SRC-KB-001@v3]。"
TEXT_C = "P0 故障建议第一时间通知相关负责人，具体响应时限与升级路径可以稍后再确认，先按经验处置即可 [S:SRC-KB-001@v3]。"
TEXT_D = "P1 故障影响单客户核心流程，响应时限为 1 小时，处置完成后须补齐影响面与已尝试动作 [S:SRC-KB-001@v3]。"
TEXT_SHORT = "P0 故障尽快处理。"
TEXT_LONG = TEXT_A * 3
REF_OK: Mapping[str, str] = {"source_id": "SRC-KB-001", "version": "v3"}


# ---------------------------------------------------------------- 测试夹具


def cand(candidate_id: str, text: str, score: float, **axes: float) -> Candidate:
    """构造一条候选：未显式给出的轴统一 0.60，保证四个轴永远齐全。"""
    merged = dict(BASE_AXES)
    merged.update(axes)
    return Candidate(candidate_id=candidate_id, text=text, score=score, axes=merged)


def gen(
    prompt_id: str = "Q-001",
    prompt: str = PROMPT_OK,
    ref: Mapping[str, str] | None = None,
    candidates: Iterable[Candidate] = (),
    task_type: str = "kb_qa",
) -> GenerationRecord:
    return GenerationRecord(
        prompt_id=prompt_id,
        prompt=prompt,
        source_ref=dict(ref if ref is not None else REF_OK),
        candidates=tuple(candidates),
        task_type=task_type,
    )


def build(
    generations: Iterable[Any],
    *,
    cfg: Config | None = None,
    clock: LogicalClock | None = None,
):
    """按给定配置装配一套 (registry / anonymizer / clock) 再调用 build_pairs。"""
    active = cfg if cfg is not None else CFG
    return build_pairs(
        generations,
        SourceRegistry.from_config(active),
        Anonymizer.from_config(active),
        active,
        clock if clock is not None else LogicalClock(active.clock_start, active.clock_tick_seconds),
    )


def reasons(result: Any) -> list[str]:
    return [str(item["reason"]) for item in result.rejected]


def only_rejection(result: Any) -> Mapping[str, Any]:
    assert len(result.rejected) == 1, f"期望 1 条拒绝，实际 {len(result.rejected)}: {result.rejected}"
    return result.rejected[0]


def sample_records(name: str) -> tuple[SourceRecord, ...]:
    return tuple(SourceRecord.from_dict(raw) for raw in read_jsonl(ROOT / "samples" / name))


def fixture_pair(tag: str = "") -> tuple[Candidate, Candidate]:
    """一对必然成对的候选；tag 用来让不同用例的正文互不相同（避开去重键）。"""
    suffix = f"（{tag}）" if tag else ""
    return (
        cand("c-a", TEXT_A + suffix, 0.90, evidence_citation=0.95),
        cand("c-b", TEXT_B + suffix, 0.70, evidence_citation=0.55),
    )


# ---------------------------------------------------------------- provenance


def test_entries_sorted_and_immutable() -> None:
    entries = REG.entries()
    assert isinstance(entries, tuple)
    keys = [(entry.source_id, entry.version) for entry in entries]
    assert keys == sorted(keys), f"entries() 未排序: {keys}"
    assert len(entries) == len(CFG.registry) == 6


def test_stats_counts() -> None:
    stats = REG.stats()
    assert stats["registered"] == 6
    assert stats["sources"] == 6
    assert stats["licenses"] == {"customer-authorized": 3, "internal-approved": 3}
    assert stats["effective_from"] == "2026-08-15"
    assert stats["effective_to"] == "2026-09-28"


def test_resolve_ok() -> None:
    binding = REG.resolve({"source_id": "SRC-KB-001", "version": "v3"}, record_id="Q-1")
    assert isinstance(binding, SourceBinding)
    assert binding.source_id == "SRC-KB-001"
    assert binding.version == "v3"
    assert binding.license == "customer-authorized"
    assert binding.authorization_ref == "AUTH-2026-0041"
    assert binding.effective_at == "2026-08-15"
    assert binding.content_sha256 == CFG.registry[0].content_sha256


def test_resolve_unknown_source() -> None:
    expect_pipeline_error(
        ErrorCode.SOURCE_UNKNOWN,
        lambda: REG.resolve({"source_id": "SRC-WEB-901", "version": "v1"}),
    )


def test_resolve_version_mismatch() -> None:
    error = expect_pipeline_error(
        ErrorCode.SOURCE_VERSION_MISMATCH,
        lambda: REG.resolve({"source_id": "SRC-KB-001", "version": "v1"}, record_id="Q-9"),
        record_id="Q-9",
    )
    assert error.detail["registered_versions"] == ["v3"]


def test_resolve_missing_source_id() -> None:
    expect_pipeline_error(
        ErrorCode.SOURCE_SCHEMA_INVALID,
        lambda: REG.resolve({"version": "v3"}, record_id="Q-2"),
        record_id="Q-2",
    )


def test_resolve_missing_version() -> None:
    expect_pipeline_error(
        ErrorCode.SOURCE_SCHEMA_INVALID,
        lambda: REG.resolve({"source_id": "SRC-KB-001"}),
    )


def test_resolve_blank_version() -> None:
    expect_pipeline_error(
        ErrorCode.SOURCE_SCHEMA_INVALID,
        lambda: REG.resolve({"source_id": "SRC-KB-001", "version": "   "}),
    )


def test_resolve_non_mapping_ref() -> None:
    expect_pipeline_error(
        ErrorCode.SOURCE_SCHEMA_INVALID,
        lambda: REG.resolve(["SRC-KB-001", "v3"]),  # type: ignore[arg-type]
    )


def test_resolve_hash_mismatch() -> None:
    expect_pipeline_error(
        ErrorCode.SOURCE_HASH_MISMATCH,
        lambda: REG.resolve(
            {"source_id": "SRC-KB-001", "version": "v3", "content_sha256": "0" * 64},
            record_id="Q-3",
        ),
        record_id="Q-3",
    )


def test_resolve_hash_match_is_case_insensitive() -> None:
    digest = CFG.registry[0].content_sha256
    binding = REG.resolve({"source_id": "SRC-KB-001", "version": "v3", "content_sha256": digest.upper()})
    assert binding.content_sha256 == digest


def test_resolve_license_denied() -> None:
    registry = SourceRegistry.from_config(replace(CFG, license_allowlist=("internal-approved",)))
    expect_pipeline_error(
        ErrorCode.SOURCE_UNAUTHORIZED,
        lambda: registry.resolve({"source_id": "SRC-KB-001", "version": "v3"}),
    )


def test_resolve_missing_authorization_ref() -> None:
    entry = replace(CFG.registry[0], authorization_ref="")
    registry = SourceRegistry.from_config(replace(CFG, registry=(entry,)))
    error = expect_pipeline_error(
        ErrorCode.SOURCE_UNAUTHORIZED,
        lambda: registry.resolve({"source_id": "SRC-KB-001", "version": "v3"}),
    )
    assert "授权编号" in error.message


def test_binding_for_default_version() -> None:
    assert REG.binding_for("SRC-KB-001").version == "v3"


def test_binding_for_natural_max_version() -> None:
    base = replace(CFG.registry[0], source_id="SRC-KB-009")
    entries = tuple(replace(base, version=version) for version in ("v2", "v9", "v10"))
    registry = SourceRegistry.from_config(replace(CFG, registry=entries))
    # 纯字符串排序会选到 v9；自然排序必须选到 v10。
    assert registry.binding_for("SRC-KB-009").version == "v10"


def test_binding_for_explicit_version() -> None:
    assert REG.binding_for("SRC-KB-002", "v2").source_id == "SRC-KB-002"


def test_binding_for_unknown_source() -> None:
    expect_pipeline_error(ErrorCode.SOURCE_UNKNOWN, lambda: REG.binding_for("SRC-NOPE-999"))


def test_binding_for_unknown_version() -> None:
    expect_pipeline_error(ErrorCode.SOURCE_UNKNOWN, lambda: REG.binding_for("SRC-KB-001", "v99"))


def test_binding_for_denied_license() -> None:
    cfg = replace(CFG, deny_licenses=tuple(CFG.deny_licenses) + ("customer-authorized",))
    registry = SourceRegistry.from_config(cfg)
    expect_pipeline_error(ErrorCode.SOURCE_UNAUTHORIZED, lambda: registry.binding_for("SRC-KB-001"))


def test_resolve_corpus_accepts_authorized_samples() -> None:
    accepted, rejected = REG.resolve_corpus(sample_records("sources.jsonl"))
    assert len(accepted) == 6, f"授权语料应全部通过，实际通过 {len(accepted)}"
    assert rejected == ()
    assert all(isinstance(record, SourceRecord) for record in accepted)
    assert [record.source_id for record in accepted] == [
        "SRC-KB-001",
        "SRC-KB-002",
        "SRC-KB-003",
        "SRC-KB-004",
        "SRC-KB-005",
        "SRC-LEGAL-006",
    ]


def test_resolve_corpus_rejects_unauthorized_samples() -> None:
    accepted, rejected = REG.resolve_corpus(sample_records("sources_unauthorized.jsonl"))
    assert accepted == ()
    assert len(rejected) == 2
    assert {item["code"] for item in rejected} == {ErrorCode.SOURCE_UNKNOWN}
    assert {item["record_id"] for item in rejected} == {"SRC-WEB-901@v1", "SRC-REVIEW-902@v1"}


def test_resolve_corpus_detects_tampered_text() -> None:
    record = sample_records("sources.jsonl")[0]
    tampered = replace(record, text=record.text + "（被改动）")
    accepted, rejected = REG.resolve_corpus([tampered])
    assert accepted == ()
    assert rejected[0]["code"] == ErrorCode.SOURCE_HASH_MISMATCH
    assert rejected[0]["record_id"] == "SRC-KB-001@v3"


def test_resolve_corpus_detects_license_drift() -> None:
    drifted = replace(sample_records("sources.jsonl")[0], license="internal-approved")
    _accepted, rejected = REG.resolve_corpus([drifted])
    assert rejected[0]["code"] == ErrorCode.SOURCE_UNAUTHORIZED


def test_resolve_corpus_detects_denied_license() -> None:
    cfg = replace(CFG, deny_licenses=tuple(CFG.deny_licenses) + ("customer-authorized",))
    registry = SourceRegistry.from_config(cfg)
    accepted, rejected = registry.resolve_corpus([sample_records("sources.jsonl")[0]])
    assert accepted == ()
    assert rejected[0]["code"] == ErrorCode.SOURCE_UNAUTHORIZED


def test_resolve_corpus_detects_missing_authorization_ref() -> None:
    entry = replace(CFG.registry[0], authorization_ref="")
    registry = SourceRegistry.from_config(replace(CFG, registry=(entry,)))
    accepted, rejected = registry.resolve_corpus([sample_records("sources.jsonl")[0]])
    assert accepted == ()
    assert rejected[0]["code"] == ErrorCode.SOURCE_UNAUTHORIZED


def test_resolve_corpus_accepts_mappings_and_is_deterministic() -> None:
    raws = read_jsonl(ROOT / "samples" / "sources.jsonl")
    first_accepted, first_rejected = REG.resolve_corpus(raws)
    second_accepted, second_rejected = REG.resolve_corpus(list(reversed(raws)))
    assert [r.source_id for r in first_accepted] == [r.source_id for r in second_accepted]
    assert first_rejected == second_rejected
    binding = REG.resolve({"source_id": first_accepted[0].source_id, "version": first_accepted[0].version})
    assert first_accepted[0].content_sha256() == binding.content_sha256


def test_resolve_corpus_rejections_carry_no_raw_text() -> None:
    raws = read_jsonl(ROOT / "samples" / "sources_unauthorized.jsonl")
    _accepted, rejected = REG.resolve_corpus(raws)
    blob = canonical_json([dict(item) for item in rejected])
    for raw in raws:
        assert str(raw["text"])[:12] not in blob, "拒绝清单里出现了来源正文片段"
    assert set(rejected[0]) == {"record_id", "code", "message", "source_id", "version"}


# ---------------------------------------------------------------- anonymize


def fresh() -> Anonymizer:
    return Anonymizer.from_config(CFG)


def test_redact_email() -> None:
    out = fresh().redact_text("请把材料发给 zhang.san@example.com 之后备份")
    assert "zhang.san@example.com" not in out
    assert "<email:" in out
    assert out.startswith("请把材料发给 <email:")


def test_redact_phone() -> None:
    out = fresh().redact_text("客户联系电话 13800138000，请回拨")
    assert "13800138000" not in out
    assert "<phone:" in out


def test_redact_id_card() -> None:
    out = fresh().redact_text("经办人证件号 11010519491231002X 已核验")
    assert "11010519491231002X" not in out
    assert "<id:" in out


def test_redact_bank_card() -> None:
    out = fresh().redact_text("退款账户 6222021234567890 待复核")
    assert "6222021234567890" not in out
    assert "<card:" in out


def test_redact_token() -> None:
    out = fresh().redact_text("调试用的 key 是 sk_abcdefghijklmnop 请勿外传")
    assert "sk_abcdefghijklmnop" not in out
    assert "<token:" in out


def test_redact_credential_url() -> None:
    out = fresh().redact_text("仓库地址 https://deploy:secret123@git.internal/repo.git 需要切换")
    assert "deploy:secret123" not in out
    assert "<credential-url:" in out


def test_redact_person_name() -> None:
    out = fresh().redact_text("这单由张三跟进，李四复核")
    assert "张三" not in out and "李四" not in out
    assert out.count("<person:") == 2


def test_redact_org_name() -> None:
    out = fresh().redact_text("客户华辰精密制造有限公司要求延期交付")
    assert "华辰" not in out
    assert "<org:" in out


def test_redact_ipv4() -> None:
    out = fresh().redact_text("内网节点 10.20.30.40 负载偏高")
    assert "10.20.30.40" not in out
    assert "<ip:" in out


def test_pseudonym_is_stable_and_distinct() -> None:
    anon = fresh()
    first = anon.pseudonym("email", "a.person@example.com")
    second = anon.pseudonym("email", "a.person@example.com")
    other = anon.pseudonym("email", "b.person@example.com")
    assert first == second, "同一 (kind, 原文) 必须得到同一伪名"
    assert first != other
    assert anon.pseudonym("phone_cn", "a.person@example.com") != first, "kind 必须参与派生"


def test_pseudonym_format() -> None:
    anon = fresh()
    placeholder = anon.pseudonym("email", "someone@example.com")
    assert placeholder.startswith("<email:") and placeholder.endswith(">")
    digest = placeholder[len("<email:") : -1]
    assert len(digest) == CFG.pseudonym_len
    assert all(char in "0123456789abcdef" for char in digest)


def test_redact_text_matches_pseudonym_api() -> None:
    anon = fresh()
    assert anon.redact_text("联系 someone@example.com") == "联系 " + anon.pseudonym("email", "someone@example.com")


def test_overlap_prefers_longest_then_rule_order() -> None:
    """18 位卡号同时命中身份证与银行卡：等长时按规则声明顺序取身份证。"""
    anon = fresh()
    out = anon.redact_text("卡号 621234199001011234 已脱敏")
    assert "621234199001011234" not in out
    assert "<id:" in out and "<card:" not in out


def test_overlap_long_match_beats_inner_match() -> None:
    """带凭据 URL 覆盖了里面的 token：长匹配优先，内部短匹配被丢弃。"""
    anon = fresh()
    out = anon.redact_text("入口 https://user:sk_abcdefghijklmnop@host.internal/x 已下线")
    assert "<credential-url:" in out
    assert "<token:" not in out
    assert "sk_abcdefghijklmnop" not in out


def test_redact_text_without_hits_returns_input() -> None:
    anon = fresh()
    text = "P0 故障须在 15 分钟内响应。"
    assert anon.redact_text(text) == text
    assert anon.mapping_size() == 0


def test_redact_text_multiple_hits_offsets() -> None:
    anon = fresh()
    out = anon.redact_text("A zhang@example.com B 13800138000 C 张三 D")
    assert out.startswith("A <email:")
    assert " B <phone:" in out
    assert " C <person:" in out
    assert out.endswith(" D")
    assert "zhang@example.com" not in out


def test_redact_mapping_deep_structure() -> None:
    anon = fresh()
    payload = {
        "联系人": ["张三", {"email": "zhang.san@example.com", "phone": "13800138000"}],
        "tags": ("华辰精密", 7),
        "count": 3,
        "flag": True,
        "nothing": None,
    }
    out = anon.redact_mapping(payload)
    assert isinstance(out["联系人"], list) and isinstance(out["联系人"][1], dict)
    assert isinstance(out["tags"], tuple)
    assert out["count"] == 3 and out["flag"] is True and out["nothing"] is None
    blob = json.dumps(out, ensure_ascii=False)
    for secret in ("张三", "zhang.san@example.com", "13800138000", "华辰精密"):
        assert secret not in blob, f"结构化脱敏后仍残留: {secret}"
    assert "<person:" in blob and "<email:" in blob and "<phone:" in blob and "<org:" in blob


def test_redact_mapping_redacts_keys_and_keeps_input() -> None:
    anon = fresh()
    payload = {"张三": "zhang.san@example.com"}
    out = anon.redact_mapping(payload)
    assert "张三" not in json.dumps(out, ensure_ascii=False)
    assert payload == {"张三": "zhang.san@example.com"}, "入参不允许被就地修改"


def test_redact_mapping_handles_non_string_leaves() -> None:
    anon = fresh()
    data = {"n": 1, "f": 2.5, "b": False, "none": None, "nested": [[3, 4], (5,)]}
    assert anon.redact_mapping(data) == {"n": 1, "f": 2.5, "b": False, "none": None, "nested": [[3, 4], (5,)]}


def test_scan_clean_text() -> None:
    anon = fresh()
    hits = anon.scan("P0 故障须在 15 分钟内响应，并同步值班负责人。")
    assert hits == ()


def test_scan_reports_sorted_hits_with_empty_digest() -> None:
    anon = fresh()
    text = "zhang@example.com 与 13800138000 都要清掉"
    hits = anon.scan(text)
    assert len(hits) == 2
    assert [hit.kind for hit in hits] == ["email", "phone_cn"]
    assert hits[0].start < hits[1].start
    assert all(hit.digest == "" for hit in hits)
    assert isinstance(hits[0], RedactionHit)
    assert text[hits[0].start : hits[0].end] == "zhang@example.com"


def test_assert_clean_block_raises_without_raw_text() -> None:
    anon = fresh()
    error = expect_pipeline_error(
        ErrorCode.ANON_LEAK,
        lambda: anon.assert_clean("残留 zhang@example.com 未清", record_id="Q-7"),
        record_id="Q-7",
    )
    assert error.detail == {"kinds": ["email"]}
    assert "zhang@example.com" not in error.message
    assert "zhang@example.com" not in canonical_json(error.to_dict())


def test_assert_clean_block_passes_clean_text() -> None:
    anon = fresh()
    assert anon.assert_clean("P0 故障须在 15 分钟内响应。") == ()


def test_assert_clean_warn_returns_hits() -> None:
    cfg = replace(CFG, leak_policy="warn")
    anon = Anonymizer.from_config(cfg)
    hits = anon.assert_clean("残留 zhang@example.com 未清", record_id="Q-8")
    assert [hit.kind for hit in hits] == ["email"]


def test_assert_clean_after_redact_is_clean() -> None:
    anon = fresh()
    dirty = "张三 zhang@example.com 13800138000 6222021234567890 sk_abcdefghijklmnop 华辰精密"
    assert anon.scan(dirty), "原始文本应当被扫描出残留"
    clean = anon.redact_text(dirty)
    assert anon.assert_clean(clean) == ()
    assert anon.scan(clean) == ()


def test_mapping_stores_only_kind_and_pseudonym() -> None:
    anon = fresh()
    anon.redact_text("zhang@example.com 与 13800138000")
    entries = anon.entries()
    assert anon.mapping_size() == len(entries) == 2
    assert entries == tuple(sorted(entries))
    blob = canonical_json([list(item) for item in entries])
    for secret in ("zhang@example.com", "13800138000"):
        assert secret not in blob
    kinds = [kind for kind, _ in entries]
    assert kinds == ["email", "phone_cn"]


def test_mapping_digest_is_order_independent() -> None:
    first = fresh()
    first.redact_text("zhang@example.com")
    first.redact_text("13800138000")
    second = fresh()
    second.redact_text("13800138000")
    second.redact_text("zhang@example.com")
    assert first.entries() == second.entries()
    assert first.mapping_digest() == second.mapping_digest()


def test_mapping_digest_changes_with_content() -> None:
    first = fresh()
    first.redact_text("zhang@example.com")
    second = fresh()
    second.redact_text("other@example.com")
    assert first.mapping_digest() != second.mapping_digest()
    assert len(first.mapping_digest()) == 64


def test_redact_text_rejects_non_string() -> None:
    expect_pipeline_error(ErrorCode.ANON_SCHEMA_INVALID, lambda: fresh().redact_text(123))  # type: ignore[arg-type]


# ---------------------------------------------------------------- pairs


def test_pairs_fixture_sizes_fit_config() -> None:
    """夹具本身必须落在配置口径内，否则后面的用例会测到别的东西。"""
    assert len(TEXT_A) >= CFG.pairs["min_chars"] and len(TEXT_B) >= CFG.pairs["min_chars"]
    assert max(len(TEXT_A), len(TEXT_B)) <= CFG.pairs["max_chars"]
    assert max(len(TEXT_A), len(TEXT_B)) / min(len(TEXT_A), len(TEXT_B)) <= CFG.pairs["max_length_ratio"]
    assert len(TEXT_SHORT) < CFG.pairs["min_chars"]
    assert len(TEXT_LONG) / len(TEXT_B) > CFG.pairs["max_length_ratio"]


def test_pairs_empty_input() -> None:
    result = build([])
    assert result.pairs == () and result.rejected == ()
    assert result.stats["generations"] == 0
    assert result.stats["emitted"] == 0
    assert result.stats["avg_axis_margin"] == 0.0


def test_pairs_normal_emits_one_pair() -> None:
    result = build([gen("Q-101", candidates=fixture_pair())])
    assert len(result.pairs) == 1 and result.rejected == ()
    pair = result.pairs[0]
    assert pair.prompt_id == "Q-101"
    assert pair.prompt == PROMPT_OK
    assert pair.chosen.text == TEXT_A and pair.rejected.text == TEXT_B
    assert pair.contrast.axis == "evidence_citation"
    assert pair.contrast.margin == 0.4
    assert pair.contrast.rule == "R-PREF-01"
    assert pair.pair_id == make_pair_id("Q-101", TEXT_A, TEXT_B, "evidence_citation")
    assert pair.dedupe_key == text_fingerprint(TEXT_A) + "|" + text_fingerprint(TEXT_B)
    assert pair.pipeline_version == CFG.pipeline_version
    assert pair.anonymized is True
    assert (pair.source.source_id, pair.source.version) == ("SRC-KB-001", "v3")
    assert pair.source == REG.resolve(REF_OK)


def test_pairs_stats_shape() -> None:
    result = build([gen("Q-102", candidates=fixture_pair())])
    stats = result.stats
    for key in (
        "generations",
        "candidates",
        "emitted",
        "rejected_records",
        "filters",
        "axes",
        "duplicates",
        "avg_axis_margin",
        "avg_score_margin",
    ):
        assert key in stats, f"stats 缺少键 {key}"
    assert (stats["generations"], stats["candidates"], stats["emitted"]) == (1, 2, 1)
    assert stats["rejected_records"] == 0
    assert stats["filters"] == {}
    assert stats["duplicates"] == 0
    assert stats["axes"] == {"evidence_citation": 1, "policy_compliance": 0, "redaction_safety": 0, "instruction_following": 0}
    assert stats["avg_axis_margin"] == 0.4
    assert stats["avg_score_margin"] == 0.2


def test_pairs_contrast_axis_deltas() -> None:
    result = build([gen("Q-103", candidates=fixture_pair())])
    deltas = result.pairs[0].contrast.axis_deltas
    assert deltas["evidence_citation"] == 0.4
    assert all(deltas[axis] == 0.0 for axis in AXES if axis != "evidence_citation")


def test_pairs_chosen_can_be_second_candidate() -> None:
    """chosen 由决定性轴决定，不由候选顺序决定。"""
    candidates = (
        cand("c-a", TEXT_A, 0.80, evidence_citation=0.50),
        cand("c-b", TEXT_B, 0.90, evidence_citation=0.95),
    )
    pair = build([gen("Q-104", candidates=candidates)]).pairs[0]
    assert pair.chosen.text == TEXT_B and pair.rejected.text == TEXT_A
    assert pair.contrast.axis_deltas["evidence_citation"] == 0.45


def test_pairs_deterministic_across_two_runs() -> None:
    records = [
        gen("Q-105", candidates=fixture_pair("run")),
        gen("Q-106", prompt="P1 的响应时限是多少？", candidates=fixture_pair("run2")),
    ]
    first = build(records)
    second = build(records)
    assert [pair.pair_id for pair in first.pairs] == [pair.pair_id for pair in second.pairs]
    assert [pair.created_at for pair in first.pairs] == [pair.created_at for pair in second.pairs]
    assert first.stats == second.stats
    assert first.rejected == second.rejected
    assert canonical_json([pair.to_dict() for pair in first.pairs]) == canonical_json([pair.to_dict() for pair in second.pairs])


def test_pairs_sorted_by_pair_id() -> None:
    records = [
        gen("Q-107", candidates=fixture_pair("s1")),
        gen("Q-108", prompt="P0 与 P1 的升级路径有何不同？", candidates=fixture_pair("s2")),
        gen("Q-109", prompt="跨级升级需要写清什么？", candidates=fixture_pair("s3")),
    ]
    result = build(records)
    ids = [pair.pair_id for pair in result.pairs]
    assert len(ids) == 3
    assert ids == sorted(ids)


def test_pairs_created_at_follows_logical_clock() -> None:
    records = [
        gen("Q-110", candidates=fixture_pair("t1")),
        gen("Q-111", prompt="P1 的响应时限是多少？", candidates=fixture_pair("t2")),
    ]
    clock = LogicalClock(CFG.clock_start, CFG.clock_tick_seconds)
    result = build(records, clock=clock)
    expected = [clock.at(0), clock.at(1)]
    assert [pair.created_at for pair in result.pairs] == expected
    assert clock.step == 2, "每个产物必须占用一个逻辑时钟刻度"
    timestamps = [pair.created_at for pair in result.pairs]
    assert timestamps == sorted(timestamps) and len(set(timestamps)) == len(timestamps)


def test_pairs_prompt_is_redacted() -> None:
    prompt = "客户张三（zhangsan@example.com）问：P0 故障的响应时限是多少？"
    result = build([gen("Q-112", prompt=prompt, candidates=fixture_pair("p"))])
    emitted = result.pairs[0].prompt
    assert "张三" not in emitted and "zhangsan@example.com" not in emitted
    assert "<person:" in emitted and "<email:" in emitted


def test_pairs_output_contains_no_pii() -> None:
    pii_chosen = "客户张三的邮箱是 zhangsan@example.com，电话 13800138000，机构为华辰精密制造有限公司，请按工单规范在 15 分钟内响应。"
    pii_rejected = "请联系对接人，按流程处理即可，时限与升级路径参考既有规范文档，事后补齐影响面说明。"
    candidates = (
        cand("c-a", pii_chosen, 0.90, evidence_citation=0.95),
        cand("c-b", pii_rejected, 0.70, evidence_citation=0.55),
    )
    result = build([gen("Q-113", prompt="张三的工单怎么处理？", candidates=candidates)])
    pair = result.pairs[0]
    blob = canonical_json(pair.to_dict())
    for secret in ("张三", "zhangsan@example.com", "13800138000", "华辰精密"):
        assert secret not in blob, f"产物里残留了原文: {secret}"
    assert "<person:" in pair.chosen.text and "<email:" in pair.chosen.text and "<phone:" in pair.chosen.text
    assert "<org:" in pair.chosen.text
    assert result.stats["emitted"] == 1


def test_pairs_reject_no_candidate() -> None:
    result = build([gen("Q-201", candidates=(cand("c-a", TEXT_A, 0.9),))])
    assert result.pairs == ()
    assert reasons(result) == [ErrorCode.PAIR_NO_CANDIDATE]
    assert result.stats["rejected_records"] == 1
    assert only_rejection(result)["detail"] == {"candidates": 1}


def test_pairs_reject_schema_missing_axis() -> None:
    broken = Candidate(
        candidate_id="c-a",
        text=TEXT_A,
        score=0.9,
        axes={"evidence_citation": 0.9, "policy_compliance": 0.6},
    )
    result = build([gen("Q-202", candidates=(broken, cand("c-b", TEXT_B, 0.7)))])
    assert result.pairs == ()
    assert reasons(result) == [ErrorCode.PAIR_SCHEMA_INVALID]
    assert only_rejection(result)["detail"]["field"] == "axes"


def test_pairs_reject_schema_score_out_of_range() -> None:
    result = build([gen("Q-203", candidates=(cand("c-a", TEXT_A, 1.5), cand("c-b", TEXT_B, 0.7)))])
    assert reasons(result) == [ErrorCode.PAIR_SCHEMA_INVALID]
    assert only_rejection(result)["detail"]["field"] == "score"


def test_pairs_reject_schema_duplicate_candidate_id() -> None:
    result = build(
        [gen("Q-204", candidates=(cand("c-same", TEXT_A, 0.9), cand("c-same", TEXT_B, 0.7)))]
    )
    assert reasons(result) == [ErrorCode.PAIR_SCHEMA_INVALID]
    assert only_rejection(result)["detail"]["problem"] == "duplicate"


def test_pairs_reject_schema_empty_prompt() -> None:
    result = build([gen("Q-205", prompt="   ", candidates=fixture_pair())])
    assert reasons(result) == [ErrorCode.PAIR_SCHEMA_INVALID]
    assert only_rejection(result)["detail"]["field"] == "prompt"


def test_pairs_reject_schema_empty_prompt_id() -> None:
    result = build([gen("", candidates=fixture_pair())])
    assert reasons(result) == [ErrorCode.PAIR_SCHEMA_INVALID]
    assert only_rejection(result)["detail"]["field"] == "prompt_id"
    assert only_rejection(result)["prompt_id"] == ""


def test_pairs_reject_unauthorized_license() -> None:
    """许可不在 allowlist 内时，授权闸门的码原样记进 rejected，不改写成别的码。"""
    cfg = replace(CFG, license_allowlist=("internal-approved",))
    result = build([gen("Q-230", candidates=fixture_pair("lic"))], cfg=cfg)
    assert result.pairs == ()
    assert reasons(result) == [ErrorCode.SOURCE_UNAUTHORIZED]
    assert result.stats["rejected_records"] == 1
    assert result.stats["filters"] == {ErrorCode.SOURCE_UNAUTHORIZED: 1}


def test_pairs_reject_schema_bad_source_ref() -> None:
    result = build([gen("Q-206", ref={"source_id": "SRC-KB-001"}, candidates=fixture_pair())])
    assert reasons(result) == [ErrorCode.PAIR_SCHEMA_INVALID]
    assert only_rejection(result)["detail"]["field"] == "source_ref"


def test_pairs_reject_unknown_source() -> None:
    result = build(
        [gen("Q-207", ref={"source_id": "SRC-WEB-901", "version": "v1"}, candidates=fixture_pair())]
    )
    assert result.pairs == ()
    assert reasons(result) == [ErrorCode.SOURCE_UNKNOWN]
    assert result.stats["filters"] == {ErrorCode.SOURCE_UNKNOWN: 1}


def test_pairs_reject_version_mismatch() -> None:
    result = build(
        [gen("Q-208", ref={"source_id": "SRC-KB-001", "version": "v1"}, candidates=fixture_pair())]
    )
    assert reasons(result) == [ErrorCode.SOURCE_VERSION_MISMATCH]


def test_pairs_reject_score_too_low() -> None:
    candidates = (cand("c-a", TEXT_A, 0.20), cand("c-b", TEXT_B, 0.70))
    result = build([gen("Q-209", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_SCORE_TOO_LOW]
    assert only_rejection(result)["detail"]["min_score"] == CFG.pairs["min_score"]


def test_pairs_reject_length_out_of_bounds() -> None:
    candidates = (cand("c-a", TEXT_SHORT, 0.90, evidence_citation=0.95), cand("c-b", TEXT_B, 0.70, evidence_citation=0.55))
    result = build([gen("Q-210", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_LENGTH_OUT_OF_BOUNDS]
    detail = only_rejection(result)["detail"]
    assert detail["lengths"] == [len(TEXT_SHORT), len(TEXT_B)]
    assert detail["min_chars"] == CFG.pairs["min_chars"]


def test_pairs_reject_length_imbalance() -> None:
    candidates = (cand("c-a", TEXT_LONG, 0.90, evidence_citation=0.95), cand("c-b", TEXT_B, 0.70, evidence_citation=0.55))
    result = build([gen("Q-211", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_LENGTH_IMBALANCE]
    assert only_rejection(result)["detail"]["ratio"] > CFG.pairs["max_length_ratio"]


def test_pairs_reject_identical_text() -> None:
    padded = "  " + TEXT_A + "  "
    candidates = (cand("c-a", TEXT_A, 0.90, evidence_citation=0.95), cand("c-b", padded, 0.70, evidence_citation=0.55))
    result = build([gen("Q-212", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_IDENTICAL_TEXT]
    assert normalize_text(TEXT_A) == normalize_text(padded)


def test_pairs_reject_axis_not_decisive() -> None:
    candidates = (cand("c-a", TEXT_A, 0.90, evidence_citation=0.70), cand("c-b", TEXT_B, 0.70, evidence_citation=0.65))
    result = build([gen("Q-213", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_AXIS_NOT_DECISIVE]
    detail = only_rejection(result)["detail"]
    assert detail["axis"] == "evidence_citation"
    assert detail["axis_delta"] < CFG.pairs["required_axis_delta"]


def test_pairs_reject_cross_axis_reversal() -> None:
    candidates = (
        cand("c-a", TEXT_A, 0.90, evidence_citation=0.95, policy_compliance=0.40),
        cand("c-b", TEXT_B, 0.70, evidence_citation=0.55, policy_compliance=0.95),
    )
    result = build([gen("Q-214", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_CROSS_AXIS_REVERSAL]
    detail = only_rejection(result)["detail"]
    assert detail["axis"] == "evidence_citation"
    assert detail["chosen_delta"] < 0


def test_pairs_reject_low_margin() -> None:
    candidates = (cand("c-a", TEXT_A, 0.60, evidence_citation=0.95), cand("c-b", TEXT_B, 0.58, evidence_citation=0.50))
    result = build([gen("Q-215", candidates=candidates)])
    assert reasons(result) == [ErrorCode.PAIR_LOW_MARGIN]
    detail = only_rejection(result)["detail"]
    assert detail["score_margin"] < CFG.pairs["min_margin"]
    assert detail["decisive_axis"] == "evidence_citation"


def test_pairs_reject_duplicate_key() -> None:
    first = gen("Q-216", candidates=fixture_pair("dup"))
    second = gen("Q-217", prompt="换个问法：P0 的响应时限是多少？", candidates=fixture_pair("dup"))
    result = build([first, second])
    assert len(result.pairs) == 1
    assert reasons(result) == [ErrorCode.PAIR_DUPLICATE]
    assert only_rejection(result)["prompt_id"] == "Q-217"
    assert result.stats["duplicates"] == 1
    assert result.stats["filters"][ErrorCode.PAIR_DUPLICATE] == 1


def test_pairs_cap_one_pair_per_prompt() -> None:
    candidates = (
        cand("c-a", TEXT_A, 0.90, evidence_citation=0.95),
        cand("c-b", TEXT_B, 0.80, evidence_citation=0.75),
        cand("c-c", TEXT_C, 0.70, evidence_citation=0.55),
    )
    result = build([gen("Q-218", candidates=candidates)])
    assert len(result.pairs) == 1
    assert result.rejected == (), "被上限挤掉的候选对不记拒绝"
    assert result.pairs[0].chosen.text == TEXT_A and result.pairs[0].rejected.text == TEXT_C
    assert result.pairs[0].contrast.margin == 0.4


def test_pairs_cap_two_when_configured() -> None:
    cfg = replace(CFG, pairs={**CFG.pairs, "max_pairs_per_prompt": 2})
    candidates = (
        cand("c-a", TEXT_A, 0.90, evidence_citation=0.95),
        cand("c-b", TEXT_B, 0.80, evidence_citation=0.75),
        cand("c-c", TEXT_C, 0.70, evidence_citation=0.55),
    )
    result = build([gen("Q-219", candidates=candidates)], cfg=cfg)
    assert len(result.pairs) == 2
    assert result.rejected == ()
    assert result.stats["emitted"] == 2


def test_pairs_axis_counts_cover_all_axes() -> None:
    result = build([gen("Q-220", candidates=fixture_pair("ax"))])
    assert set(result.stats["axes"]) == set(AXES)
    assert sum(result.stats["axes"].values()) == result.stats["emitted"]


def test_pairs_tie_break_follows_axis_declaration_order() -> None:
    candidates = (
        cand("c-a", TEXT_A, 0.90, evidence_citation=0.90, policy_compliance=0.90),
        cand("c-b", TEXT_B, 0.70, evidence_citation=0.50, policy_compliance=0.50),
    )
    result = build([gen("Q-221", candidates=candidates)])
    assert result.pairs[0].contrast.axis == CFG.pairs["axes"][0]


def test_pairs_candidate_order_does_not_matter() -> None:
    left = cand("c-a", TEXT_A, 0.90, evidence_citation=0.95)
    right = cand("c-b", TEXT_B, 0.70, evidence_citation=0.55)
    forward = build([gen("Q-222", candidates=(left, right))])
    backward = build([gen("Q-222", candidates=(right, left))])
    assert [p.pair_id for p in forward.pairs] == [p.pair_id for p in backward.pairs]
    assert forward.pairs[0].chosen.text == backward.pairs[0].chosen.text == TEXT_A


def test_pairs_accepts_mapping_input() -> None:
    record = gen("Q-223", candidates=fixture_pair("map"))
    result = build([record.to_dict()])
    assert len(result.pairs) == 1
    assert result.pairs[0].prompt_id == "Q-223"


def test_pairs_filter_counts_are_consistent() -> None:
    records = [
        gen("Q-224", ref={"source_id": "SRC-WEB-901", "version": "v1"}, candidates=fixture_pair("c1")),
        gen("Q-225", candidates=(cand("c-a", TEXT_A, 0.20), cand("c-b", TEXT_B, 0.70))),
        gen("Q-226", candidates=fixture_pair("c2")),
    ]
    result = build(records)
    assert result.stats["emitted"] == 1
    assert sum(result.stats["filters"].values()) == len(result.rejected)
    assert set(result.stats["filters"]) == set(reasons(result))
    # rejected_records 只数"整条 prompt 被拒"（记录级），pair 级过滤单独进 filters。
    assert result.stats["rejected_records"] == 1
    assert [item["prompt_id"] for item in result.rejected if item["reason"] == ErrorCode.SOURCE_UNKNOWN] == ["Q-224"]


def test_pairs_bad_record_does_not_stop_batch() -> None:
    records = [
        gen("Q-227", ref={"source_id": "SRC-WEB-901", "version": "v1"}, candidates=fixture_pair("b1")),
        gen("Q-228", prompt="P1 的响应时限是多少？", candidates=fixture_pair("b2")),
    ]
    result = build(records)
    assert len(result.pairs) == 1
    assert result.pairs[0].prompt_id == "Q-228"
    assert reasons(result) == [ErrorCode.SOURCE_UNKNOWN]


def test_pairs_reject_anon_leak() -> None:
    cfg = replace(CFG, redaction_rules=tuple(rule for rule in CFG.redaction_rules if rule.kind != "phone_cn"))
    candidates = (
        cand("c-a", TEXT_A + " 联系电话 13800138000。", 0.90, evidence_citation=0.95),
        cand("c-b", TEXT_B, 0.70, evidence_citation=0.55),
    )
    result = build([gen("Q-229", candidates=candidates)], cfg=cfg)
    assert result.pairs == ()
    assert reasons(result) == [ErrorCode.ANON_LEAK]
    detail = only_rejection(result)["detail"]
    assert detail["kinds"] == ["phone_cn"]
    assert "13800138000" not in canonical_json([dict(item) for item in result.rejected])


def test_pairs_rejected_items_carry_no_raw_text() -> None:
    records = [
        gen("Q-231", candidates=(cand("c-a", TEXT_SHORT, 0.90), cand("c-b", TEXT_B, 0.70))),
        gen("Q-232", candidates=(cand("c-a", TEXT_A, 0.60, evidence_citation=0.95), cand("c-b", TEXT_B, 0.58, evidence_citation=0.50))),
        gen("Q-233", candidates=(cand("c-a", TEXT_LONG, 0.90), cand("c-b", TEXT_B, 0.70))),
    ]
    result = build(records)
    blob = canonical_json([dict(item) for item in result.rejected])
    for text in (TEXT_A, TEXT_B, TEXT_LONG, TEXT_SHORT):
        assert text not in blob, "拒绝说明里出现了完整正文"
    for item in result.rejected:
        assert set(item) == {"prompt_id", "reason", "detail"}
        assert isinstance(item["detail"], Mapping)


def test_pairs_missing_pairs_config_raises() -> None:
    expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: build([], cfg=replace(CFG, pairs={})))


def test_pairs_rejects_unknown_input_type() -> None:
    expect_pipeline_error(ErrorCode.PAIR_SCHEMA_INVALID, lambda: build(["not-a-record"]))


# ---------------------------------------------------------------- 汇总


def _cases() -> list[Case | tuple[str, Any]]:
    found: list[Case | tuple[str, Any]] = []
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            found.append((name, value))
    return found


def run() -> int:
    return run_cases(_cases(), title="test_pairs")


if __name__ == "__main__":
    sys.exit(run())


