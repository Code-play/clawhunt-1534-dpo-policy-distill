"""命令行入口与 demo 主流程。

命令一览（全部零第三方依赖、无网络、不读真实时钟）：

- ``python -m dpo_policy validate-config``：只校验配置，打印本次运行口径；
- ``python -m dpo_policy sources``：授权闸门——索引语料、复核指纹、驱动未授权负样例；
- ``python -m dpo_policy pairs``：构建偏好对，写 `out/preference_pairs.jsonl` + `out/pair_audit.md`；
- ``python -m dpo_policy distill``：轨迹蒸馏，写 `out/distill_triples.jsonl` + `out/policy_card.md`；
- ``python -m dpo_policy regress``：离线回归，写 `out/regression_report.md` + `out/regression_metrics.json`；
- ``python -m dpo_policy demo``：全流程 + 四组负向对照，写全部 `out/` 产物与 `out/demo.log`。

退出码约定：0 通过；2 业务闸门拒绝（未授权来源、脱敏残留、回归闸门不过等）；
3 用法/配置/环境问题。``--out-dir`` / ``--var-dir`` / ``--samples-dir`` 可以把产物写到临时目录，
验证脚本据此在隔离目录里跑两遍做逐字节确定性比对。
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import model, report, store, validate
from .anonymize import Anonymizer
from .config import Config, load_config
from .distill import DistillResult, distill_traces
from .model import (
    ErrorCode,
    GoldenCase,
    GenerationRecord,
    LogicalClock,
    PipelineError,
    PreferencePair,
    SourceRecord,
    exit_code_for,
)
from .pairs import PairBuildResult, build_pairs
from .provenance import SourceRegistry
from .regression import PolicyEngine, run_regression

__all__ = ["main", "PipelineArtifacts", "run_pipeline", "write_artifacts"]

EXIT_OK = 0
EXIT_GATE = 2
EXIT_USAGE = 3


# ---------------------------------------------------------------- 参数解析


class _Parser(argparse.ArgumentParser):
    """把 argparse 的用法错误（默认退出码 2）改成 3。

    平台的 2 表示"业务被拒"，参数写错不能混进去；否则复跑的人会把"命令敲错"读成
    "数据不合格"。
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        raise PipelineError(ErrorCode.USAGE_ERROR, f"用法错误: {message}")


def build_parser() -> argparse.ArgumentParser:
    # 公共参数用 SUPPRESS 做默认值：这样「全局参数放在子命令前」和「放在子命令后」都能生效，
    # 不会被子解析器的 None 默认值覆盖（argparse 的 parents= 经典坑）。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=argparse.SUPPRESS, help="交付物根目录（默认：当前目录）")
    common.add_argument("--out-dir", default=argparse.SUPPRESS, help="产物目录（默认：<root>/out）")
    common.add_argument("--var-dir", default=argparse.SUPPRESS, help="工作数据目录（默认：<root>/var）")
    common.add_argument("--samples-dir", default=argparse.SUPPRESS, help="样例目录（默认：<root>/samples）")
    common.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS, help="只打印一行摘要")

    parser = _Parser(
        prog="dpo_policy",
        description="DPO 偏好与 Policy 蒸馏骨架（离线、可复跑、零第三方依赖）",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for name in ("validate-config", "sources", "pairs", "distill", "regress", "demo"):
        sub.add_parser(name, parents=[common])
    return parser


def _resolve_root(args: argparse.Namespace) -> Path:
    raw = getattr(args, "root", None)
    if raw:
        return Path(raw).resolve()
    # 默认用当前目录；若当前目录不像交付物根（没有 config/pipeline_config.json），
    # 回落到包所在目录的上一级（从任意目录调用也能跑）。
    cwd = Path.cwd()
    if (cwd / "config" / "pipeline_config.json").is_file():
        return cwd
    return Path(__file__).resolve().parents[1]


def _config_with_paths(args: argparse.Namespace) -> Config:
    cfg = load_config(_resolve_root(args))
    paths = dict(cfg.paths)
    for key, attr in (("out", "out_dir"), ("var", "var_dir"), ("samples", "samples_dir")):
        raw = getattr(args, attr, None)
        if raw:
            paths[key] = Path(raw).resolve()
    return replace(cfg, paths=paths)


# ---------------------------------------------------------------- 流水线


@dataclass(frozen=True)
class PipelineArtifacts:
    """一次完整流水线的内存结果（不写盘；写盘由 :func:`write_artifacts` 负责）。"""

    cfg: Config
    clock: LogicalClock
    registry: SourceRegistry
    anonymizer: Anonymizer
    source_accepted: tuple[SourceRecord, ...]
    source_rejected: tuple[dict[str, Any], ...]
    unauthorized_sources_rejected: tuple[dict[str, Any], ...]
    pair_result: PairBuildResult
    unauthorized_pair_result: PairBuildResult
    distill_result: DistillResult
    invalid_traces_rejected: tuple[dict[str, Any], ...]
    regression: model.RegressionReport
    controls: Mapping[str, Any]
    run: Mapping[str, Any]


def _read_samples(cfg: Config, key: str) -> tuple[dict[str, Any], ...]:
    path = cfg.path("samples") / cfg.source_files[key]
    try:
        return store.read_jsonl(path)
    except PipelineError:
        raise
    except OSError as exc:  # pragma: no cover - 目录级错误
        raise PipelineError(ErrorCode.CONFIG_MISSING, f"读取样例失败: {path.name}", detail=str(exc)) from exc


def _load_sources(cfg: Config, filename: str) -> tuple[tuple[SourceRecord, ...], tuple[dict[str, Any], ...]]:
    raws = store.read_jsonl(cfg.path("samples") / filename)
    records = tuple(SourceRecord.from_dict(raw) for raw in raws)
    registry = SourceRegistry.from_config(cfg)
    accepted, rejected = registry.resolve_corpus(records)
    return accepted, rejected


def _generation_objects(raws: Iterable[Mapping[str, Any]], cfg: Config, *, kind: str) -> tuple[GenerationRecord, ...]:
    raws = tuple(raws)
    issues = validate.validate_bundle("generation", raws, cfg)
    if issues:
        raise PipelineError(
            ErrorCode.SCHEMA_INVALID,
            f"{kind} 样例校验未通过：{len(issues)} 处问题",
            record_id=issues[0].record_id,
            detail=[i.to_dict() for i in issues[:5]],
        )
    return tuple(GenerationRecord.from_dict(raw) for raw in raws)


def _negative_generation(raws: Sequence[Mapping[str, Any]], *, source_ref: Mapping[str, str], leaky_text: str | None = None) -> GenerationRecord:
    """用一条真实样例造负向对照：改来源引用，或塞一段故意没被规则覆盖的残留标识。"""
    raw = json.loads(json.dumps(raws[0], ensure_ascii=False))
    raw["prompt_id"] = "NEG-" + str(raw.get("prompt_id", "001"))
    raw["source_ref"] = dict(source_ref)
    if leaky_text is not None:
        raw["candidates"] = list(raw.get("candidates") or [])
        if len(raw["candidates"]) >= 2:
            raw["candidates"][0]["text"] = leaky_text
    return GenerationRecord.from_dict(raw)


def run_pipeline(cfg: Config, *, with_controls: bool = True) -> PipelineArtifacts:
    """跑完整流水线（内存态）。所有闸门都在这里执行，任何一步不合规都会抛带稳定码的异常。"""
    clock = LogicalClock(cfg.clock_start, cfg.clock_tick_seconds)
    registry = SourceRegistry.from_config(cfg)
    anonymizer = Anonymizer.from_config(cfg)

    # 1) 授权闸门
    source_accepted, source_rejected = _load_sources(cfg, cfg.source_files["sources"])
    unauth_accepted, unauth_rejected = _load_sources(cfg, "sources_unauthorized.jsonl")
    if unauth_accepted:
        raise PipelineError(
            ErrorCode.STORE_INTEGRITY,
            "未授权来源负样例竟然通过了授权闸门",
            detail={"accepted": [s.source_id for s in unauth_accepted]},
        )
    issues = validate.validate_bundle("source", [s.to_dict() for s in source_accepted], cfg)
    if issues:
        raise PipelineError(
            ErrorCode.SCHEMA_INVALID,
            f"授权来源记录校验未通过：{len(issues)} 处问题",
            record_id=issues[0].record_id,
            detail=[i.to_dict() for i in issues[:5]],
        )

    # 2) 偏好对
    generations = _generation_objects(_read_samples(cfg, "generations"), cfg, kind="候选生成")
    pair_result = build_pairs(generations, registry, anonymizer, cfg, clock)
    if not pair_result.pairs:
        raise PipelineError(ErrorCode.PAIR_NO_CANDIDATE, "本次没有产出任何偏好对（检查样例与阈值）")
    pair_issues = validate.validate_bundle("pair", [p.to_dict() for p in pair_result.pairs], cfg)
    if pair_issues:
        raise PipelineError(
            ErrorCode.SCHEMA_INVALID,
            f"偏好对产物校验未通过：{len(pair_issues)} 处问题",
            record_id=pair_issues[0].record_id,
            detail=[i.to_dict() for i in pair_issues[:5]],
        )

    # 3) 蒸馏
    trace_raws: list[dict[str, Any]] = []
    trace_raws.extend(_read_samples(cfg, "traces_messages"))
    trace_raws.extend(_read_samples(cfg, "traces_tool"))
    distill_result = distill_traces(trace_raws, registry, anonymizer, cfg, clock)
    if not distill_result.triples:
        raise PipelineError(ErrorCode.DISTILL_EMPTY, "本次没有产出任何蒸馏三元组（检查样例与适配器）")
    triple_issues = validate.validate_bundle("triple", [t.to_dict() for t in distill_result.triples], cfg)
    if triple_issues:
        raise PipelineError(
            ErrorCode.SCHEMA_INVALID,
            f"蒸馏三元组校验未通过：{len(triple_issues)} 处问题",
            record_id=triple_issues[0].record_id,
            detail=[i.to_dict() for i in triple_issues[:5]],
        )

    # 4) 离线回归（先过闸门，再让人看报告）
    golden_raws = _read_samples(cfg, "golden_cases")
    golden_issues = validate.validate_bundle("golden_case", golden_raws, cfg)
    if golden_issues:
        raise PipelineError(
            ErrorCode.REGRESSION_CASE_INVALID,
            f"回归用例校验未通过：{len(golden_issues)} 处问题",
            record_id=golden_issues[0].record_id,
            detail=[i.to_dict() for i in golden_issues[:5]],
        )
    cases = tuple(GoldenCase.from_dict(raw) for raw in golden_raws)
    engine = PolicyEngine(distill_result.cards, cfg)
    regression = run_regression(cases, engine, cfg, clock, anonymizer)
    report_issues = validate.validate_report(regression.to_dict(), cfg)
    if report_issues:
        raise PipelineError(
            ErrorCode.SCHEMA_INVALID,
            f"回归报告结构校验未通过：{len(report_issues)} 处问题",
            detail=[i.to_dict() for i in report_issues[:5]],
        )

    # 5) 负向对照：闸门必须真的拦得住
    controls: dict[str, Any] = {}
    unauthorized_pair_result = PairBuildResult(pairs=(), stats={}, rejected=())
    invalid_traces_rejected: tuple[dict[str, Any], ...] = ()
    if with_controls:
        gen_raws = _read_samples(cfg, "generations")
        unauthorized_pair_result = build_pairs(
            _generation_objects(_read_samples(cfg, "generations_unauthorized"), cfg, kind="未授权候选生成"),
            registry,
            anonymizer,
            cfg,
            clock,
        )
        controls["unauthorized_generations"] = _control(
            expected=(ErrorCode.SOURCE_UNKNOWN, ErrorCode.SOURCE_VERSION_MISMATCH, ErrorCode.SOURCE_UNAUTHORIZED),
            observed=unauthorized_pair_result.rejected,
            extra_ok=not unauthorized_pair_result.pairs,
        )
        controls["version_mismatch"] = _control(
            expected=(ErrorCode.SOURCE_VERSION_MISMATCH,),
            observed=build_pairs(
                [_negative_generation(gen_raws, source_ref={"source_id": "SRC-KB-001", "version": "v9"})],
                registry,
                anonymizer,
                cfg,
                clock,
            ).rejected,
        )
        controls["hash_mismatch"] = _control(
            expected=(ErrorCode.SOURCE_HASH_MISMATCH,),
            observed=build_pairs(
                [
                    _negative_generation(
                        gen_raws,
                        source_ref={"source_id": "SRC-KB-001", "version": "v3", "content_sha256": "0" * 64},
                    )
                ],
                registry,
                anonymizer,
                cfg,
                clock,
            ).rejected,
        )
        controls["residual_pii"] = _control(
            expected=(ErrorCode.ANON_LEAK,),
            observed=build_pairs(
                [
                    _negative_generation(
                        gen_raws,
                        source_ref={"source_id": "SRC-KB-001", "version": "v3"},
                        leaky_text="请联系客户经理，企业微信 wxid_kf_8831001，工作时间 9:00-18:00。",
                    )
                ],
                registry,
                anonymizer,
                cfg,
                clock,
            ).rejected,
        )
        invalid_trace_result = distill_traces(
            _read_samples(cfg, "traces_invalid"), registry, anonymizer, cfg, clock
        )
        invalid_traces_rejected = invalid_trace_result.rejected
        controls["invalid_traces"] = _control(
            expected=(ErrorCode.TRACE_INVALID, ErrorCode.TRACE_ADAPTER_INVALID, ErrorCode.DISTILL_SCHEMA_INVALID),
            observed=invalid_traces_rejected,
            extra_ok=not invalid_trace_result.triples,
        )
        bad = [name for name, item in controls.items() if not item.get("ok")]
        if bad:
            raise PipelineError(
                ErrorCode.STORE_INTEGRITY,
                "负向对照未按预期被拒绝：闸门可能失效",
                detail={"controls": {name: controls[name] for name in bad}},
            )

    run = {
        "pipeline_version": cfg.pipeline_version,
        "config_spec": cfg.spec_text(),
        "generated_at": clock.now(),
        "counts": {
            "sources_accepted": len(source_accepted),
            "sources_rejected": len(source_rejected),
            "unauthorized_sources_rejected": len(unauth_rejected),
            "generations": len(generations),
            "pairs": len(pair_result.pairs),
            "triples": len(distill_result.triples),
            "policy_cards": len(distill_result.cards),
            "regression_cases": len(regression.cases),
            "regression_passed": sum(1 for c in regression.cases if c.passed),
        },
        "pairs_stats": pair_result.stats,
        "distill_stats": distill_result.stats,
        "regression_metrics": regression.metrics,
        "regression_gate": regression.gate,
        "controls": controls,
        "anonymization": {
            "mapping_size": anonymizer.mapping_size(),
            "mapping_digest": anonymizer.mapping_digest(),
            "leak_policy": cfg.leak_policy,
        },
    }

    return PipelineArtifacts(
        cfg=cfg,
        clock=clock,
        registry=registry,
        anonymizer=anonymizer,
        source_accepted=source_accepted,
        source_rejected=source_rejected,
        unauthorized_sources_rejected=unauth_rejected,
        pair_result=pair_result,
        unauthorized_pair_result=unauthorized_pair_result,
        distill_result=distill_result,
        invalid_traces_rejected=invalid_traces_rejected,
        regression=regression,
        controls=controls,
        run=run,
    )


def _control(*, expected: Sequence[str], observed: Iterable[Mapping[str, Any]], extra_ok: bool = True) -> dict[str, Any]:
    codes = sorted({str(item.get("reason") or item.get("code") or "") for item in observed})
    ok = bool(codes) and all(code in expected for code in codes) and extra_ok
    return {"ok": ok, "expected": list(expected), "observed": codes, "count": len(codes)}


# ---------------------------------------------------------------- 产物写入


def write_artifacts(art: PipelineArtifacts, *, only: str | None = None) -> dict[str, Any]:
    """把内存结果写成产物。``only`` 限定只写某一块（pairs/distill/regress），demo 写全部。"""
    cfg = art.cfg
    out_dir = cfg.path("out")
    var_dir = cfg.path("var")
    out_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)
    files: dict[Path, str] = {}

    def put(path: Path, text: str) -> None:
        files[path] = text

    write_pairs = only in (None, "pairs")
    write_distill = only in (None, "distill")
    write_regress = only in (None, "regress")

    if write_pairs:
        put(
            out_dir / "pair_audit.md",
            report.render_pair_audit(
                art.pair_result,
                cfg,
                source_accepted=art.source_accepted,
                source_rejected=art.source_rejected,
                registry_stats=art.registry.stats(),
                anonymizer=art.anonymizer,
                negative={
                    "未授权候选生成": len(art.unauthorized_pair_result.rejected),
                    **{name: ("拦截" if item["ok"] else "未拦截") for name, item in art.controls.items()},
                },
            ),
        )
        put(
            out_dir / "preference_pairs.jsonl",
            "\n".join(model.canonical_json(p.to_dict()) for p in art.pair_result.pairs) + "\n",
        )
        samples = report.render_anonymized_samples(art.pair_result.pairs)
        put(out_dir / "anonymized_samples.jsonl", "\n".join(model.canonical_json(s) for s in samples) + "\n")

    if write_distill:
        put(
            out_dir / "distill_triples.jsonl",
            "\n".join(model.canonical_json(t.to_dict()) for t in art.distill_result.triples) + "\n",
        )
        put(
            out_dir / "policy_card.md",
            report.render_policy_card(
                art.distill_result.cards,
                art.distill_result.triples,
                cfg,
                distill_stats=art.distill_result.stats,
                anonymizer=art.anonymizer,
            ),
        )

    if write_regress:
        put(out_dir / "regression_report.md", report.render_regression_report(art.regression, cfg))
        put(
            out_dir / "regression_metrics.json",
            json.dumps(art.regression.to_dict(), ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        )

    # 工作数据（发布时跳过，但复跑与排查要靠它）
    if write_pairs:
        store.write_json(
            var_dir / "sources_index.json",
            {
                "accepted": [s.to_dict() for s in art.source_accepted],
                "rejected": list(art.source_rejected),
                "unauthorized_negative": list(art.unauthorized_sources_rejected),
                "registry_stats": art.registry.stats(),
            },
        )
        store.write_json(var_dir / "pairs.json", [p.to_dict() for p in art.pair_result.pairs])
        store.write_json(
            var_dir / "pairs_stats.json",
            {"stats": art.pair_result.stats, "rejected": list(art.pair_result.rejected)},
        )
    if write_distill:
        store.write_json(var_dir / "triples.json", [t.to_dict() for t in art.distill_result.triples])
        store.write_json(
            var_dir / "distill_stats.json",
            {
                "stats": art.distill_result.stats,
                "rejected": list(art.distill_result.rejected),
                "cards": [c.to_dict() for c in art.distill_result.cards],
            },
        )
    if write_regress:
        store.write_json(var_dir / "regression.json", art.regression.to_dict())
    store.write_json(
        var_dir / "anonymization.json",
        {
            "mapping_size": art.anonymizer.mapping_size(),
            "mapping_digest": art.anonymizer.mapping_digest(),
            "pseudonym_len": cfg.pseudonym_len,
            "policy": cfg.leak_policy,
            "_note": "只存摘要与条数；映射表本身不落盘、不交付。",
        },
    )
    store.write_json(var_dir / "run_state.json", art.run)

    # 1) 先原子写掉 out/ 下的静态产物，2) 再据此生成清单，3) 最后写自描述的 pipeline_run.json
    #    与 demo.log。顺序这样排是为了让清单里的字节数与磁盘一致，且 demo.log 能列出真实产物。
    # 清单里的路径统一写成 out/<文件名>：产物目录可以被 --out-dir 换到临时目录，
    # 但清单要描述"交付物内的相对位置"，否则隔离复跑时清单会指向临时路径。
    for path in sorted(files, key=lambda p: p.as_posix()):
        store.atomic_write_text(path, files[path])
    ordered = sorted(files, key=lambda p: p.name)
    artifacts = [{"path": f"out/{p.name}", "bytes": p.stat().st_size} for p in ordered]
    digests = {f"out/{p.name}": _digest_of(p) for p in ordered}
    manifest = {
        "artifacts": artifacts,
        "digests": digests,
        "total_bytes": sum(item["bytes"] for item in artifacts),
    }
    if only is None:
        demo_text = _render_demo_log(art, artifacts=artifacts)
        store.atomic_write_text(out_dir / "demo.log", demo_text)
        artifacts_all = sorted(
            artifacts + [{"path": "out/demo.log", "bytes": len(demo_text.encode("utf-8"))}],
            key=lambda item: item["path"],
        )
        run_obj = dict(art.run)
        run_obj["artifacts"] = artifacts_all
        run_obj["digests"] = {**digests, "out/demo.log": model.sha256_text(demo_text)}
        store.atomic_write_text(
            out_dir / "pipeline_run.json",
            json.dumps(run_obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        )
        manifest = {
            "artifacts": artifacts_all,
            "digests": run_obj["digests"],
            "total_bytes": sum(item["bytes"] for item in artifacts_all),
        }
    return manifest


def _digest_of(path: Path) -> str:
    return model.sha256_text(path.read_text(encoding="utf-8"))


def _render_demo_log(art: PipelineArtifacts, artifacts: Sequence[Mapping[str, Any]] = ()) -> str:
    cfg = art.cfg
    lines: list[str] = []
    lines.append("[demo] DPO 偏好与 Policy 蒸馏骨架 —— 全流程日志（逻辑时刻，无真实时钟）")
    lines.append(f"[demo] 配置口径: {cfg.spec_text()}")
    lines.append(f"[demo] 1/6 加载配置并校验：pipeline={cfg.pipeline_version}，登记表 {len(cfg.registry)} 条")
    lines.append(
        f"[demo] 2/6 授权闸门：语料通过 {len(art.source_accepted)} 条，拒绝 {len(art.source_rejected)} 条；"
        f"未授权负样例被拒 {len(art.unauthorized_sources_rejected)} 条"
    )
    lines.append(
        f"[demo] 3/6 偏好对：输入 {art.pair_result.stats.get('generations', 0)} 条 prompt / "
        f"{art.pair_result.stats.get('candidates', 0)} 条候选，产出 {len(art.pair_result.pairs)} 对，"
        f"拦截 {sum(dict(art.pair_result.stats.get('filters', {})).values())} 次"
    )
    lines.append(
        f"[demo] 4/6 蒸馏：轨迹 {art.distill_result.stats.get('traces', 0)} 条，"
        f"三元组 {len(art.distill_result.triples)} 条（SFT {dict(art.distill_result.stats.get('targets', {})).get('sft', 0)} / "
        f"DPO {dict(art.distill_result.stats.get('targets', {})).get('dpo', 0)}），策略卡 {len(art.distill_result.cards)} 张"
    )
    gate = "通过" if art.regression.ok else "不通过"
    lines.append(
        f"[demo] 5/6 离线回归：{art.regression.metrics.get('cases', 0)} 条用例，"
        f"通过 {art.regression.metrics.get('passed', 0)} 条（{art.regression.metrics.get('pass_rate', 0)}），"
        f"闸门 {gate}；回退 {len(dict(art.regression.deltas).get('regressions', ()))} 条"
    )
    lines.append(
        "[demo] 6/6 负向对照：" + "；".join(f"{name}={'拦截' if item['ok'] else '未拦截'}" for name, item in sorted(art.controls.items()))
        if art.controls
        else "[demo] 6/6 负向对照：本次运行未启用"
    )
    lines.append(
        f"[demo] 匿名化：映射 {art.anonymizer.mapping_size()} 条，摘要 {art.anonymizer.mapping_digest()[:16]}（映射表不交付）"
    )
    if artifacts:
        lines.append(f"[demo] 产物 {len(artifacts)} 份（另含本日志与运行清单 pipeline_run.json）：")
        for item in artifacts:
            lines.append(f"[demo]   - {item['path']} ({item['bytes']} B)")
    lines.append("[demo] 完成：退出码 0（闸门全过）")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 各命令


def _print_run_brief(art: PipelineArtifacts) -> None:
    run = art.run
    counts = dict(run.get("counts", {}))
    print(f"配置口径: {run.get('config_spec')}")
    print(
        "授权: 通过 {sources_accepted} 条 / 拒绝 {sources_rejected} 条；候选生成 {generations} 条；"
        "偏好对 {pairs} 对；三元组 {triples} 条；策略卡 {policy_cards} 张；回归 {regression_passed}/{regression_cases} 通过".format(
            **counts
        )
    )
    gate = "通过" if art.regression.ok else "不通过"
    print(f"回归闸门: {gate}；负向对照: " + ("全部拦截" if art.controls and all(v["ok"] for v in art.controls.values()) else "见产物"))


def cmd_validate_config(cfg: Config) -> int:
    print(f"配置校验通过：{cfg.spec_text()}")
    print(f"登记表来源: {', '.join(f'{e.source_id}@{e.version}' for e in cfg.registry)}")
    print(f"策略规则: {', '.join(r.rule_id for r in cfg.policy_rules)}")
    print(f"脱敏规则: {', '.join(r.kind for r in cfg.redaction_rules)}")
    print(f"残留检测: {', '.join(kind for kind, _ in cfg.leak_patterns)}")
    return EXIT_OK


def cmd_sources(cfg: Config) -> int:
    registry = SourceRegistry.from_config(cfg)
    accepted, rejected = _load_sources(cfg, cfg.source_files["sources"])
    unauth_accepted, unauth_rejected = _load_sources(cfg, "sources_unauthorized.jsonl")
    if unauth_accepted:
        raise PipelineError(ErrorCode.STORE_INTEGRITY, "未授权来源负样例通过了闸门", detail=[s.source_id for s in unauth_accepted])
    print(f"授权语料: 通过 {len(accepted)} 条，拒绝 {len(rejected)} 条")
    print(f"未授权负样例: 拒绝 {len(unauth_rejected)} 条（期望全部被拒）")
    for item in unauth_rejected:
        print(f"  - {item.get('source_id')}@{item.get('version')}: {item.get('code')}")
    print(f"登记表统计: {json.dumps(registry.stats(), ensure_ascii=False, sort_keys=True)}")
    if rejected:
        print("语料内被拒条目（应为空或说明原因）:")
        for item in rejected:
            print(f"  - {item.get('source_id')}@{item.get('version')}: {item.get('code')}")
    return EXIT_OK


def cmd_pairs(cfg: Config) -> int:
    art = run_pipeline(cfg, with_controls=True)
    write_artifacts(art, only="pairs")
    _print_run_brief(art)
    print(f"偏好对产物: {cfg.path('out') / 'preference_pairs.jsonl'}（{len(art.pair_result.pairs)} 对）")
    return EXIT_OK


def cmd_distill(cfg: Config) -> int:
    art = run_pipeline(cfg, with_controls=True)
    write_artifacts(art, only="distill")
    _print_run_brief(art)
    print(f"蒸馏产物: {cfg.path('out') / 'distill_triples.jsonl'}（{len(art.distill_result.triples)} 条）")
    return EXIT_OK


def cmd_regress(cfg: Config) -> int:
    art = run_pipeline(cfg, with_controls=True)
    write_artifacts(art, only="regress")
    _print_run_brief(art)
    print(f"回归报告: {cfg.path('out') / 'regression_report.md'}")
    return EXIT_OK if art.regression.ok else EXIT_GATE


def cmd_demo(cfg: Config) -> int:
    art = run_pipeline(cfg, with_controls=True)
    manifest = write_artifacts(art, only=None)
    _print_run_brief(art)
    print(f"产物 {len(manifest['artifacts'])} 份，合计 {manifest['total_bytes']} B：")
    for item in manifest["artifacts"]:
        print(f"  - {item['path']} ({item['bytes']} B)")
    if not art.regression.ok:
        failed = ", ".join(c.case_id for c in art.regression.failed_cases)
        print(f"回归闸门不通过；失败用例: {failed}")
        return EXIT_GATE
    return EXIT_OK


_DISPATCH = {
    "validate-config": cmd_validate_config,
    "sources": cmd_sources,
    "pairs": cmd_pairs,
    "distill": cmd_distill,
    "regress": cmd_regress,
    "demo": cmd_demo,
}


def main(argv: Sequence[str] | None = None) -> int:
    # 参数解析也放进 try：用法错误同样要落成退出码 3，而不是抛栈给调用方。
    try:
        args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
        cfg = _config_with_paths(args)
        handler = _DISPATCH[args.command]
        return handler(cfg)
    except PipelineError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False, sort_keys=True))
        return exit_code_for(exc.code)
    except Exception as exc:  # noqa: BLE001 - 兜底：不让异常静默变成"看起来通过了"
        print(json.dumps({"code": "INTERNAL_ERROR", "message": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
