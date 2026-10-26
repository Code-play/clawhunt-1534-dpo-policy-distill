"""核心层测试：模型、配置、存储、校验、报告模板与命令行契约。

不使用第三方测试框架；``tests/harness.py`` 负责收集与汇总。每个用例都是纯 assert，
断言失败信息里写清"期望什么、实际什么"，方便复跑的人定位。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.harness import Case, expect_pipeline_error, run_cases  # noqa: E402

from dpo_policy import cli, model, report, store, validate  # noqa: E402
from dpo_policy.config import load_config  # noqa: E402
from dpo_policy.model import ErrorCode, PipelineError  # noqa: E402

CONFIG = load_config(ROOT)


# ---------------------------------------------------------------- 工具


def _temp_root(tmp: Path) -> Path:
    """复制一份 config/ 到临时目录，供"故意写坏配置"的用例使用。"""
    root = tmp / "root"
    shutil.copytree(ROOT / "config", root / "config")
    return root


def _mutate_config(root: Path, name: str, mutate) -> None:
    path = root / "config" / name
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def _valid_pair_dict() -> dict:
    candidate = {
        "candidate_id": "C-1",
        "text": "依据《规则》给出带引用的回答，长度足够用于校验。",
        "score": 0.86,
        "axes": {axis: 0.9 for axis in CONFIG.axes},
        "model": "sim",
        "simulated": True,
    }
    rejected = dict(candidate)
    rejected["candidate_id"] = "C-2"
    rejected["text"] = "含糊回答，没有引用也没有依据说明。"
    rejected["axes"] = {axis: 0.5 for axis in CONFIG.axes}
    return {
        "pair_id": model.make_pair_id("GEN-01", candidate["text"], rejected["text"], CONFIG.axes[0]),
        "prompt_id": "GEN-01",
        "prompt": "P0 工单的响应时限？",
        "chosen": candidate,
        "rejected": rejected,
        "contrast": {
            "axis": CONFIG.axes[0],
            "margin": 0.4,
            "axis_deltas": {axis: 0.4 for axis in CONFIG.axes},
            "rule": "R-PREF-01",
        },
        "source": {
            "source_id": "SRC-KB-001",
            "version": "v3",
            "license": "customer-authorized",
            "content_sha256": "a" * 64,
            "authorization_ref": "AUTH-2026-0041",
            "effective_at": "2026-08-15",
        },
        "pipeline_version": CONFIG.pipeline_version,
        "created_at": "2026-10-26T00:00:30Z",
        "dedupe_key": "k1",
        "anonymized": True,
    }


def _valid_triple_dict() -> dict:
    return {
        "triple_id": model.make_triple_id("TRC-M-01", "指令文本", "输出文本足够长，可以用于字段校验。"),
        "trace_id": "TRC-M-01",
        "instruction": "P0 工单的响应时限是多少？",
        "output": "依据《客户工单分级与升级规范》（引用 SRC-KB-001@v3）：P0 须在 15 分钟内响应。",
        "rationale": ["步骤1[retrieve] 命中授权来源 SRC-KB-001@v3"],
        "policy_refs": ["R-CITE-01", "R-AUTH-01"],
        "target": "sft",
        "source": {
            "source_id": "SRC-KB-001",
            "version": "v3",
            "license": "customer-authorized",
            "content_sha256": "b" * 64,
            "authorization_ref": "AUTH-2026-0041",
            "effective_at": "2026-08-15",
        },
        "pipeline_version": CONFIG.pipeline_version,
        "created_at": "2026-10-26T00:01:00Z",
        "dedupe_key": "k2",
        "adapter": "messages",
    }


def _valid_case_dict() -> dict:
    return {
        "case_id": "CASE-X",
        "prompt": "P0 工单的响应时限是多少？",
        "available_sources": [{"source_id": "SRC-KB-001", "version": "v3", "authorized": True}],
        "expected_action": "answer_with_citation",
        "required_source_ids": ["SRC-KB-001"],
        "must_cite": ["SRC-KB-001"],
        "forbidden_patterns": ["全额退款"],
        "tags": ["policy_citation"],
        "note": "",
    }


def _valid_report_dict() -> dict:
    return {
        "generated_at": "2026-10-26T00:02:00Z",
        "ok": True,
        "metrics": {"cases": 3, "passed": 3, "failed": 0, "pass_rate": 1.0, "violations": 0},
        "baseline": {"pipeline_version": "dpo-policy-0.9.0", "pass_rate": 0.875, "cases": 3, "violations": 2},
        "deltas": {"pass_rate": 0.125, "regressions": [], "fixes": [], "violations_delta": -2},
        "gate": {"ok": True, "min_pass_rate": 0.9, "max_regressions": 0, "pass_rate": 1.0, "regression_count": 0},
        "cases": [
            {
                "case_id": "CASE-01",
                "expected_action": "answer_with_citation",
                "actual_action": "answer_with_citation",
                "passed": True,
                "violations": [],
                "citations": ["SRC-KB-001"],
                "notes": [],
            }
        ],
    }


# ---------------------------------------------------------------- 用例


def run() -> int:
    cases: list[Case] = []

    # -- 模型：序列化与哈希 -------------------------------------------------
    def cannonical_is_sorted() -> None:
        text = model.canonical_json({"b": 1, "a": [2, 3], "c": "中文"})
        assert text == '{"a":[2,3],"b":1,"c":"中文"}', text

    cases.append(Case("canonical_json 键排序且不转义中文", cannonical_is_sorted))

    def hash_stable() -> None:
        assert model.sha256_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert model.content_hash({"a": 1}) == model.content_hash({"a": 1})

    cases.append(Case("sha256/content_hash 与已知向量一致", hash_stable))

    def normalize_works() -> None:
        assert model.normalize_text("  Ａ  B\t\n") == "A B", model.normalize_text("  Ａ  B\t\n")
        assert model.text_fingerprint("a  b") == model.text_fingerprint("a b")
        assert model.text_fingerprint("a b") != model.text_fingerprint("a c")

    cases.append(Case("normalize_text 做 NFKC 与空白折叠", normalize_works))

    def short_hash_and_ids() -> None:
        pid = model.make_pair_id("P", "x", "y", "evidence_citation")
        assert pid.startswith("pair_") and len(pid) == len("pair_") + 16, pid
        assert pid == model.make_pair_id("P", " x ", "y", "evidence_citation")
        assert pid != model.make_pair_id("P", "x", "y", "policy_compliance")
        tid = model.make_triple_id("T", "i", "o")
        assert tid.startswith("tri_") and len(tid) == len("tri_") + 16, tid

    cases.append(Case("pair_id/triple_id 由内容派生且唯一", short_hash_and_ids))

    def source_hash_excludes_license() -> None:
        a = model.SourceRecord("SRC-X-001", "v1", "internal-approved", "标题", "正文")
        b = model.SourceRecord("SRC-X-001", "v1", "customer-authorized", "标题", "正文")
        assert a.content_sha256() == b.content_sha256()
        c = model.SourceRecord("SRC-X-001", "v2", "internal-approved", "标题", "正文")
        assert a.content_sha256() != c.content_sha256()

    cases.append(Case("来源指纹覆盖内容不含授权元数据", source_hash_excludes_license))

    def record_roundtrip() -> None:
        raw = {
            "prompt_id": "GEN-X",
            "prompt": "问题",
            "source_ref": {"source_id": "SRC-KB-001", "version": "v3"},
            "candidates": [
                {"candidate_id": "a", "text": "答案一", "score": 0.8, "axes": {"evidence_citation": 0.9}},
                {"candidate_id": "b", "text": "答案二", "score": 0.4, "axes": {}},
            ],
        }
        gen = model.GenerationRecord.from_dict(raw)
        assert gen.prompt_id == "GEN-X" and len(gen.candidates) == 2
        assert gen.candidates[1].axis("evidence_citation") == 0.0
        assert gen.to_dict()["source_ref"] == raw["source_ref"]

    cases.append(Case("GenerationRecord 往返一致且缺轴按 0 处理", record_roundtrip))

    def enum_guards() -> None:
        assert model.ensure_target("SFT") == "sft"
        expect_pipeline_error(ErrorCode.DISTILL_SCHEMA_INVALID, lambda: model.ensure_target("rlhf"))
        assert model.ensure_action("abstain") == "abstain"
        expect_pipeline_error(ErrorCode.REGRESSION_CASE_INVALID, lambda: model.ensure_action("answer"))

    cases.append(Case("target/action 枚举守卫拒绝非法值", enum_guards))

    # -- 模型：逻辑时钟 -----------------------------------------------------
    def clock_deterministic() -> None:
        c1 = model.LogicalClock("2026-10-26T00:00:00Z", 30)
        c2 = model.LogicalClock("2026-10-26T00:00:00Z", 30)
        seq1 = [c1.now() for _ in range(3)]
        seq2 = [c2.now() for _ in range(3)]
        assert seq1 == seq2 == ["2026-10-26T00:00:00Z", "2026-10-26T00:00:30Z", "2026-10-26T00:01:00Z"], seq1
        assert c1.step == 3
        c1.reset()
        assert c1.now() == seq1[0]

    cases.append(Case("逻辑时钟推进确定且可重置", clock_deterministic))

    def clock_rejects_bad_config() -> None:
        expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: model.LogicalClock("2026-10-26 00:00:00", 30))
        expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: model.LogicalClock("2026-10-26T00:00:00Z", 0))

    cases.append(Case("逻辑时钟拒绝非法起点/步长", clock_rejects_bad_config))

    def ts_helpers() -> None:
        moment = model.parse_ts("2026-10-26T00:00:00Z")
        assert model.format_ts(moment) == "2026-10-26T00:00:00Z"
        expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: model.parse_ts("2026-10-26T00:00:00+08:00"))

    cases.append(Case("时刻解析/格式化只接受 UTC 定长格式", ts_helpers))

    # -- 模型：错误码与退出码 ----------------------------------------------
    def error_codes() -> None:
        assert model.exit_code_for(ErrorCode.CONFIG_INVALID) == 3
        assert model.exit_code_for(ErrorCode.USAGE_ERROR) == 3
        assert model.exit_code_for(ErrorCode.SOURCE_UNAUTHORIZED) == 2
        assert model.exit_code_for(ErrorCode.REGRESSION_GATE_FAILED) == 2
        exc = PipelineError(ErrorCode.ANON_LEAK, "残留", record_id="p1")
        assert exc.to_dict()["code"] == "ANON_LEAK" and "p1" in str(exc)

    cases.append(Case("错误码分组决定退出码 2/3", error_codes))

    # -- 配置 ---------------------------------------------------------------
    def config_basics() -> None:
        assert CONFIG.pipeline_version == "dpo-policy-1.0.0"
        assert len(CONFIG.axes) == 4
        assert CONFIG.adapters == ("messages", "tool_trace")
        assert len(CONFIG.registry) == 6
        assert len(CONFIG.policy_rules) == 8
        assert len(CONFIG.leak_patterns) >= 7
        assert "pipeline=dpo-policy-1.0.0" in CONFIG.spec_text()
        for path in CONFIG.paths.values():
            assert Path(path).is_absolute()

    cases.append(Case("配置加载后的关键口径", config_basics))

    def license_policy() -> None:
        assert CONFIG.license_allowed("customer-authorized")
        assert CONFIG.license_allowed("INTERNAL-APPROVED")
        assert not CONFIG.license_allowed("unverified")
        assert not CONFIG.license_allowed("something-else")

    cases.append(Case("许可白名单：允许/拒绝/未知三态", license_policy))

    def registry_index() -> None:
        index = CONFIG.registry_index()
        assert ("SRC-KB-001", "v3") in index
        assert index[("SRC-KB-001", "v3")].authorization_ref.startswith("AUTH-")
        assert all(len(e.content_sha256) == 64 for e in CONFIG.registry)
        keys = [e.key() for e in CONFIG.registry]
        assert len(keys) == len(set(keys))

    cases.append(Case("登记表索引与授权编号齐备", registry_index))

    def config_missing_file() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            (root / "config" / "policy_rules.json").unlink()
            expect_pipeline_error(ErrorCode.CONFIG_MISSING, lambda: load_config(root))

    cases.append(Case("缺配置文件 -> CONFIG_MISSING", config_missing_file))

    def config_bad_json() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            (root / "config" / "pipeline_config.json").write_text("{oops", encoding="utf-8")
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("坏 JSON -> CONFIG_INVALID", config_bad_json))

    def config_license_overlap() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))

            def mutate(data: dict) -> None:
                data["sources"]["deny_licenses"].append("internal-approved")

            _mutate_config(root, "pipeline_config.json", mutate)
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("许可允许/禁止清单重叠 -> CONFIG_INVALID", config_license_overlap))

    def config_short_salt() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            _mutate_config(root, "pipeline_config.json", lambda d: d["anonymize"].__setitem__("salt", "short"))
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("脱敏 salt 过短 -> CONFIG_INVALID", config_short_salt))

    def config_unknown_axis() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            _mutate_config(root, "pipeline_config.json", lambda d: d["pairs"]["axes"].append("vibes"))
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("未支持的对比轴 -> CONFIG_INVALID", config_unknown_axis))

    def config_bad_adapter() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            _mutate_config(root, "pipeline_config.json", lambda d: d["distill"]["adapters"].append("xml"))
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("未实现的轨迹适配器 -> CONFIG_INVALID", config_bad_adapter))

    def config_bad_regex() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            _mutate_config(root, "redaction_rules.json", lambda d: d["rules"][0].__setitem__("pattern", "([a-z"))
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("不可编译的脱敏正则 -> CONFIG_INVALID", config_bad_regex))

    def config_license_not_allowed() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))

            def mutate(data: dict) -> None:
                data["sources"][0]["license"] = "unverified"

            _mutate_config(root, "source_registry.json", mutate)
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("登记表许可不在白名单 -> CONFIG_INVALID", config_license_not_allowed))

    def config_leak_policy_mismatch() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            _mutate_config(root, "redaction_rules.json", lambda d: d["leak_scan"].__setitem__("policy", "warn"))
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("两处脱敏策略不一致 -> CONFIG_INVALID", config_leak_policy_mismatch))

    def config_duplicate_source() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))

            def mutate(data: dict) -> None:
                data["sources"].append(dict(data["sources"][0]))

            _mutate_config(root, "source_registry.json", mutate)
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("登记表主键重复 -> CONFIG_INVALID", config_duplicate_source))

    def config_missing_policy_ref() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _temp_root(Path(tmp))
            _mutate_config(root, "pipeline_config.json", lambda d: d["distill"]["required_policy_refs"].append("R-NOPE-01"))
            expect_pipeline_error(ErrorCode.CONFIG_INVALID, lambda: load_config(root))

    cases.append(Case("蒸馏引用不存在的规则 -> CONFIG_INVALID", config_missing_policy_ref))

    # -- 存储 ---------------------------------------------------------------
    def store_roundtrip() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "records.jsonl"
            store.write_jsonl(path, [{"b": 1, "a": 2}, {"c": "中文"}])
            assert path.read_bytes().count(b"\r\n") == 0
            back = store.read_jsonl(path)
            assert back[0] == {"a": 2, "b": 1} and back[1] == {"c": "中文"}

    cases.append(Case("JSONL 往返且不写 CRLF", store_roundtrip))

    def store_bad_line() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"a":1}\nnot json\n', encoding="utf-8")
            expect_pipeline_error(ErrorCode.STORE_INTEGRITY, lambda: store.read_jsonl(path))
            expect_pipeline_error(ErrorCode.STORE_INTEGRITY, lambda: store.read_jsonl(Path(tmp) / "missing.jsonl"))

    cases.append(Case("坏行/缺文件 -> STORE_INTEGRITY", store_bad_line))

    def store_append_only() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s = store.JsonlStore(Path(tmp) / "x.jsonl")
            assert s.append([{"a": 1}, {"b": 2}]) == 2
            assert s.pending == 2 and s.flushed == 0
            s.flush()
            expect_pipeline_error(ErrorCode.STORE_CONFLICT, s.flush)
            assert store.read_jsonl(Path(tmp) / "x.jsonl")[1] == {"b": 2}

    cases.append(Case("JsonlStore 只允许 flush 一次", store_append_only))

    def store_json_and_summary() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store.write_json(root / "out" / "a.json", {"z": 1, "a": 2})
            obj = store.read_json(root / "out" / "a.json")
            assert obj == {"a": 2, "z": 1}
            summary = store.summarize_files([root / "out" / "a.json"], root)
            assert summary[0]["path"] == "out/a.json" and summary[0]["bytes"] > 0

    cases.append(Case("write_json 可读且 summarize_files 给相对路径", store_json_and_summary))

    # -- 校验 ---------------------------------------------------------------
    def validate_pair_ok() -> None:
        assert validate.validate_pair(_valid_pair_dict(), CONFIG) == ()

    cases.append(Case("合法偏好对通过字段校验", validate_pair_ok))

    def validate_pair_negative() -> None:
        bad = _valid_pair_dict()
        bad["anonymized"] = False
        assert {i.field for i in validate.validate_pair(bad, CONFIG)} == {"anonymized"}
        bad2 = _valid_pair_dict()
        bad2["pair_id"] = "pair_xxx"
        assert any(i.field == "pair_id" for i in validate.validate_pair(bad2, CONFIG))
        bad3 = _valid_pair_dict()
        bad3["source"]["license"] = "unverified"
        assert any(i.field == "source.license" for i in validate.validate_pair(bad3, CONFIG))
        bad4 = _valid_pair_dict()
        bad4["contrast"]["axis"] = "vibes"
        assert any(i.field == "contrast.axis" for i in validate.validate_pair(bad4, CONFIG))
        bad5 = _valid_pair_dict()
        del bad5["created_at"]
        assert any(i.field == "created_at" for i in validate.validate_pair(bad5, CONFIG))

    cases.append(Case("偏好对字段校验的负样例逐项命中", validate_pair_negative))

    def validate_triple_ok() -> None:
        assert validate.validate_triple(_valid_triple_dict(), CONFIG) == ()

    cases.append(Case("合法蒸馏三元组通过字段校验", validate_triple_ok))

    def validate_triple_negative() -> None:
        bad = _valid_triple_dict()
        bad["policy_refs"] = ["R-NOPE-01"]
        assert any(i.field == "policy_refs" for i in validate.validate_triple(bad, CONFIG))
        bad2 = _valid_triple_dict()
        bad2["rationale"] = []
        assert any(i.field == "rationale" for i in validate.validate_triple(bad2, CONFIG))
        bad3 = _valid_triple_dict()
        bad3["adapter"] = "xml"
        assert any(i.field == "adapter" for i in validate.validate_triple(bad3, CONFIG))

    cases.append(Case("三元组校验的负样例逐项命中", validate_triple_negative))

    def validate_golden_and_report() -> None:
        assert validate.validate_golden_case(_valid_case_dict(), CONFIG) == ()
        assert validate.validate_report(_valid_report_dict(), CONFIG) == ()
        bad_case = _valid_case_dict()
        bad_case["expected_action"] = "answer"
        assert any(i.field == "expected_action" for i in validate.validate_golden_case(bad_case, CONFIG))
        bad_report = _valid_report_dict()
        bad_report["metrics"]["pass_rate"] = 1.5
        assert any(i.field == "metrics.pass_rate" for i in validate.validate_report(bad_report, CONFIG))

    cases.append(Case("回归用例与报告结构校验", validate_golden_and_report))

    def validate_bundle_unique() -> None:
        pair = _valid_pair_dict()
        issues = validate.validate_bundle("pair", [pair, dict(pair)], CONFIG)
        assert any(i.field == "pair_id" and "重复" in i.actual for i in issues), [i.to_dict() for i in issues]
        expect_pipeline_error(ErrorCode.SCHEMA_INVALID, lambda: validate.assert_bundle_valid("pair", [pair, dict(pair)], CONFIG))

    cases.append(Case("整批主键重复被识别", validate_bundle_unique))

    def validate_unknown_kind() -> None:
        expect_pipeline_error(ErrorCode.SCHEMA_INVALID, lambda: validate.validate_bundle("nope", [], CONFIG))

    cases.append(Case("未知记录类型被拒绝", validate_unknown_kind))

    # -- 报告模板 -----------------------------------------------------------
    def template_fill() -> None:
        text = report.fill_template("A={{a}} B={{b}}", {"a": "1", "b": "2"})
        assert text == "A=1 B=2"
        expect_pipeline_error(ErrorCode.SCHEMA_INVALID, lambda: report.fill_template("A={{a}} {{missing}}", {"a": "1"}))

    cases.append(Case("模板填充后无残留占位符", template_fill))

    def regression_report_render() -> None:
        case = model.RegressionCaseResult("CASE-01", "answer_with_citation", "answer_with_citation", True, (), ("SRC-KB-001",), ())
        rep = model.RegressionReport(
            generated_at="2026-10-26T00:05:00Z",
            cases=(case,),
            metrics={"cases": 1, "passed": 1, "failed": 0, "pass_rate": 1.0, "violations": 0},
            baseline={"pipeline_version": "dpo-policy-0.9.0", "pass_rate": 0.875, "cases": 16, "violations": 2},
            deltas={"pass_rate": 0.125, "regressions": [], "fixes": ["CASE-05"], "violations_delta": -2},
            gate={"ok": True, "min_pass_rate": 0.9, "max_regressions": 0, "pass_rate": 1.0, "regression_count": 0},
        )
        text = report.render_regression_report(rep, CONFIG)
        assert "结论" in text and "通过" in text
        assert "{{" not in text and "}}" not in text
        assert "dpo-policy-0.9.0" in text and "CASE-01" in text
        assert len(text) > 500

    cases.append(Case("回归报告按模板渲染且无残留占位符", regression_report_render))

    def report_has_no_emoji() -> None:
        text = Path(ROOT / "out" / "pair_audit.md")
        if text.exists():  # demo 跑过才检查（避免测试依赖执行顺序）
            for ch in text.read_text(encoding="utf-8"):
                assert not (0x1F000 <= ord(ch) <= 0x1FAFF), "报告里出现 emoji"
                assert not (0x2600 <= ord(ch) <= 0x27BF), "报告里出现杂符号"

    cases.append(Case("产物报告不含 emoji（若已生成）", report_has_no_emoji))

    # -- 命令行契约 ---------------------------------------------------------
    def parser_usage_error() -> None:
        expect_pipeline_error(ErrorCode.USAGE_ERROR, lambda: cli.build_parser().parse_args(["nope"]))
        expect_pipeline_error(ErrorCode.USAGE_ERROR, lambda: cli.build_parser().parse_args([]))

    cases.append(Case("未知子命令/缺子命令 -> USAGE_ERROR", parser_usage_error))

    def cli_validate_config() -> None:
        assert cli.main(["validate-config", "--root", str(ROOT), "--quiet"]) == 0

    cases.append(Case("validate-config 退出码 0", cli_validate_config))

    def cli_usage_exit_code() -> None:
        assert cli.main(["nope", "--root", str(ROOT)]) == 3

    cases.append(Case("用法错误退出码 3", cli_usage_exit_code))

    def cli_unknown_root() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            # main() 把异常收敛成退出码；这里断言"退出码 3 + 不吞掉错误"。
            assert cli.main(["validate-config", "--root", str(empty)]) == 3

    cases.append(Case("不存在的根目录 -> 退出码 3", cli_unknown_root))

    # -- 样例与产物的一致性 -------------------------------------------------
    def sample_sources_match_registry() -> None:
        raws = store.read_jsonl(ROOT / "samples" / "sources.jsonl")
        assert len(raws) == 6
        index = CONFIG.registry_index()
        for raw in raws:
            rec = model.SourceRecord.from_dict(raw)
            entry = index[(rec.source_id, rec.version)]
            assert entry.content_sha256 == rec.content_sha256(), f"{rec.source_id} 指纹与登记表不一致"
        issues = validate.validate_bundle("source", raws, CONFIG)
        assert not issues, [i.to_dict() for i in issues]

    cases.append(Case("样例来源与登记表指纹一致", sample_sources_match_registry))

    def unauthorized_sources_not_registered() -> None:
        raws = store.read_jsonl(ROOT / "samples" / "sources_unauthorized.jsonl")
        index = CONFIG.registry_index()
        assert raws, "未授权负样例不能为空"
        for raw in raws:
            rec = model.SourceRecord.from_dict(raw)
            assert (rec.source_id, rec.version) not in index

    cases.append(Case("未授权来源不在登记表内", unauthorized_sources_not_registered))

    def sample_generations_valid() -> None:
        raws = store.read_jsonl(ROOT / "samples" / "generations.jsonl")
        assert len(raws) >= 12
        assert not validate.validate_bundle("generation", raws, CONFIG)
        assert not validate.validate_bundle("generation", store.read_jsonl(ROOT / "samples" / "generations_unauthorized.jsonl"), CONFIG)

    cases.append(Case("候选生成样例结构合法", sample_generations_valid))

    def sample_golden_valid() -> None:
        raws = store.read_jsonl(ROOT / "samples" / "golden_cases.jsonl")
        assert len(raws) == 16
        assert not validate.validate_bundle("golden_case", raws, CONFIG)

    cases.append(Case("回归用例样例结构合法", sample_golden_valid))

    def templates_present() -> None:
        tpl = CONFIG.path("config") / "report_templates" / "regression_report.md.tpl"
        assert tpl.is_file() and tpl.stat().st_size > 500
        assert "{{table_cases}}" in tpl.read_text(encoding="utf-8")

    cases.append(Case("回归报告模板存在且带占位符", templates_present))

    def config_override_paths() -> None:
        overridden = replace(CONFIG, paths={**CONFIG.paths, "out": Path(tempfile.gettempdir()) / "dpo_test_out"})
        assert str(overridden.path("out")).endswith("dpo_test_out")
        assert overridden.pipeline_version == CONFIG.pipeline_version

    cases.append(Case("配置可派生（产物目录可覆盖）", config_override_paths))

    return run_cases(cases, title="core")


if __name__ == "__main__":
    sys.exit(run())
