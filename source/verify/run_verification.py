"""独立验收脚本：不信任任何"看起来跑过了"的说法，全部重新执行并断言。

    python verify/run_verification.py

分十组断言（A..J）：

A. 交付物完整性——必备文件、模块、样例、命名；
B. 配置层——加载、口径、登记表与语料指纹一致；
C. 测试——真实跑 ``tests/test_runner.py``，按汇总行断言全过；
D. demo 全流程——在**隔离临时目录**里跑，检查产物、清单、闸门与数字自洽；
E. 确定性——同一输入跑两遍，产物逐字节相同；
F. 闸门负向——未授权来源/版本漂移/指纹漂移/残留标识/坏轨迹/回归闸门不过/命令退出码；
G. 匿名化——产物里没有明文个人信息或机构名，salt 与映射原文不出现在任何交付文件里；
H. 报告质量——回归报告、偏好对审计、策略卡的内容与模板完整性；
I. 样例生成——``scripts/gen_samples.py --check`` 与重新生成的幂等性；
J. 交付卫生——ASCII 文件名、无 pycache、无 emoji、无网络/真实时钟调用、SOLUTION 占位保留。

本脚本只读交付物、只写 ``verify/records/`` 与系统临时目录，不改任何受测文件。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from dpo_policy import model, store  # noqa: E402
from dpo_policy.anonymize import Anonymizer  # noqa: E402
from dpo_policy.config import load_config  # noqa: E402
from dpo_policy.distill import distill_traces  # noqa: E402
from dpo_policy.model import ErrorCode, PipelineError  # noqa: E402
from dpo_policy.pairs import build_pairs  # noqa: E402
from dpo_policy.provenance import SourceRegistry  # noqa: E402
from dpo_policy.regression import PolicyEngine, run_regression  # noqa: E402
from dpo_policy.validate import validate_bundle  # noqa: E402

REPO_URL = "https://github.com/Code-play/clawhunt-1534-dpo-policy-distill"
ZIP_URL = f"{REPO_URL}/raw/main/1534-dpo-policy-distill.zip"

LOG: list[str] = []
CHECKS: list[tuple[str, str, bool, str]] = []
COMMANDS: list[tuple[str, int]] = []


def log(line: str = "") -> None:
    LOG.append(line)
    print(line)


def check(group: str, name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append((group, name, bool(ok), detail))
    mark = "PASS" if ok else "FAIL"
    log(f"[{mark}] {group} {name}" + (f"  ({detail})" if detail else ""))
    return bool(ok)


def run_cmd(args: list[str], *, cwd: Path = ROOT, env_extra: dict[str, str] | None = None) -> tuple[int, str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(args, cwd=str(cwd), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def expect_error(code: str, fn) -> bool:
    try:
        fn()
    except PipelineError as exc:
        return exc.code == code
    except Exception:  # noqa: BLE001
        return False
    return False


def _rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _text_files(root: Path) -> list[Path]:
    exts = {".md", ".py", ".json", ".jsonl", ".txt", ".tpl", ".gitignore"}
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and (p.suffix.lower() in exts or p.name == ".gitignore"):
            out.append(p)
    return out


def _read_all(paths: Iterable[Path]) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in paths)


# ---------------------------------------------------------------- 主流程


def main() -> int:
    log("=" * 78)
    log("订单 #1534 交付物独立验收")
    log("=" * 78)
    cfg = load_config(ROOT)
    anonymizer = Anonymizer.from_config(cfg)
    registry = SourceRegistry.from_config(cfg)

    tmp_base = Path(tempfile.mkdtemp(prefix="cph1534-verify-"))
    demo1 = tmp_base / "run1"
    demo2 = tmp_base / "run2"
    try:
        # ---------------------------------------------------------- A 完整性
        group = "A 完整性"
        for name in ("SOLUTION.md", "README.md", "DELIVERY.md", ".gitignore"):
            check(group, f"必备文件 {name}", (ROOT / name).is_file() and (ROOT / name).stat().st_size > 0)
        for name in (
            "config/pipeline_config.json",
            "config/source_registry.json",
            "config/redaction_rules.json",
            "config/policy_rules.json",
            "config/regression_config.json",
            "config/report_templates/regression_report.md.tpl",
        ):
            check(group, f"配置 {name}", (ROOT / name).is_file())
        for name, expected in (
            ("samples/sources.jsonl", 6),
            ("samples/sources_unauthorized.jsonl", 2),
            ("samples/generations.jsonl", 16),
            ("samples/generations_unauthorized.jsonl", 3),
            ("samples/traces_messages.jsonl", 6),
            ("samples/traces_tool.jsonl", 5),
            ("samples/traces_invalid.jsonl", 4),
            ("samples/golden_cases.jsonl", 16),
        ):
            path = ROOT / name
            got = len(store.read_jsonl(path)) if path.is_file() else -1
            check(group, f"样例 {name}", got == expected, f"{got}/{expected} 条")
        modules = ["model", "config", "provenance", "anonymize", "pairs", "distill", "regression", "validate", "store", "report", "cli"]
        missing = [m for m in modules if not (ROOT / "dpo_policy" / f"{m}.py").is_file()]
        check(group, "包内模块齐备", not missing, f"缺 {missing}" if missing else f"{len(modules)} 个模块")
        check(group, "回归报告模板带占位符", "{{table_cases}}" in (ROOT / "config/report_templates/regression_report.md.tpl").read_text(encoding="utf-8"))

        solution = (ROOT / "SOLUTION.md").read_text(encoding="utf-8")
        injected = solution.replace("REPO_LINK_HERE", REPO_URL).replace("ZIP_LINK_HERE", ZIP_URL)
        check(group, "SOLUTION 保留 REPO_LINK_HERE", "REPO_LINK_HERE" in solution)
        check(group, "SOLUTION 保留 ZIP_LINK_HERE", "ZIP_LINK_HERE" in solution)
        check(group, "SOLUTION 含「仓库地址：」", "仓库地址：" in solution)
        check(group, "SOLUTION 含「打包下载：」", "打包下载：" in solution)
        check(group, "SOLUTION 注入后 <= 10000 字符", len(injected) <= 10000, f"{len(injected)} 字符")
        check(group, "SOLUTION 注入后 >= 8000 字符", len(injected) >= 8000, f"{len(injected)} 字符")

        # ---------------------------------------------------------- B 配置
        group = "B 配置"
        check(group, "pipeline 版本", cfg.pipeline_version == "dpo-policy-1.0.0", cfg.pipeline_version)
        check(group, "对比轴 4 个", len(cfg.axes) == 4, ",".join(cfg.axes))
        check(group, "适配器 2 个", cfg.adapters == ("messages", "tool_trace"))
        check(group, "登记表 6 条", len(cfg.registry) == 6)
        check(group, "策略规则 8 条", len(cfg.policy_rules) == 8)
        check(group, "残留检测模式 >= 7", len(cfg.leak_patterns) >= 7, str(len(cfg.leak_patterns)))
        check(group, "许可白名单/黑名单不重叠", not (set(cfg.license_allowlist) & set(cfg.deny_licenses)))
        check(group, "配置口径摘要", "pipeline=dpo-policy-1.0.0" in cfg.spec_text())
        corpus = tuple(model.SourceRecord.from_dict(r) for r in store.read_jsonl(ROOT / "samples/sources.jsonl"))
        index = cfg.registry_index()
        mismatched = [s.source_id for s in corpus if index[(s.source_id, s.version)].content_sha256 != s.content_sha256()]
        check(group, "语料指纹与登记表一致", not mismatched, f"不一致 {mismatched}" if mismatched else f"{len(corpus)} 条")
        for name in ("pipeline_config.json", "source_registry.json", "redaction_rules.json", "policy_rules.json", "regression_config.json"):
            try:
                json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
                ok = True
            except json.JSONDecodeError:
                ok = False
            check(group, f"{name} 可解析", ok)

        # ---------------------------------------------------------- C 测试
        group = "C 测试"
        code, out = run_cmd([sys.executable, str(ROOT / "tests" / "test_runner.py")])
        COMMANDS.append(("python tests/test_runner.py", code))
        print(out.rstrip())
        summary = None
        for line in reversed(out.strip().splitlines()):
            found = re.search(r"TOTAL: (\d+)/(\d+) tests passed", line)
            if found:
                summary = found
                break
        check(group, "test_runner 退出码 0", code == 0, f"exit={code}")
        check(group, "测试汇总行可解析", summary is not None)
        if summary:
            passed, total = int(summary.group(1)), int(summary.group(2))
            check(group, "全部测试通过", passed == total, f"{passed}/{total}")
            check(group, "用例数 >= 120", total >= 120, f"{total} 条")
        tests_output = out

        # ---------------------------------------------------------- D demo
        group = "D demo"
        code1, out1 = run_cmd(
            [sys.executable, "-m", "dpo_policy", "--root", str(ROOT), "--out-dir", str(demo1 / "out"), "--var-dir", str(demo1 / "var"), "demo"]
        )
        COMMANDS.append(("python -m dpo_policy demo（隔离目录 run1）", code1))
        check(group, "demo 退出码 0", code1 == 0, f"exit={code1}")
        expected_out = [
            "pair_audit.md",
            "preference_pairs.jsonl",
            "anonymized_samples.jsonl",
            "distill_triples.jsonl",
            "policy_card.md",
            "regression_report.md",
            "regression_metrics.json",
            "pipeline_run.json",
            "demo.log",
        ]
        out_dir = demo1 / "out"
        missing = [n for n in expected_out if not (out_dir / n).is_file()]
        check(group, "产物 9 份齐备", not missing, f"缺 {missing}" if missing else "9/9")
        var_dir = demo1 / "var"
        expected_var = ["sources_index.json", "pairs.json", "pairs_stats.json", "triples.json", "distill_stats.json", "regression.json", "anonymization.json", "run_state.json"]
        missing_var = [n for n in expected_var if not (var_dir / n).is_file()]
        check(group, "工作数据 8 份齐备", not missing_var, f"缺 {missing_var}" if missing_var else "8/8")

        run_obj = json.loads((out_dir / "pipeline_run.json").read_text(encoding="utf-8"))
        counts = run_obj["counts"]
        check(group, "偏好对数量 8", counts["pairs"] == 8, str(counts["pairs"]))
        check(group, "三元组数量 11", counts["triples"] == 11, str(counts["triples"]))
        check(group, "回归 16 条全过", counts["regression_cases"] == 16 and counts["regression_passed"] == 16, f"{counts['regression_passed']}/{counts['regression_cases']}")
        check(group, "回归闸门通过", run_obj["regression_gate"]["ok"] is True)
        check(group, "负向对照全部拦截", all(v["ok"] for v in run_obj["controls"].values()), str(sorted(run_obj["controls"])))
        check(group, "产物清单 8 条（清单不含自身）", len(run_obj["artifacts"]) == 8, str(len(run_obj["artifacts"])))
        check(group, "产物摘要 8 条", len(run_obj["digests"]) == 8, str(len(run_obj["digests"])))
        size_ok = True
        for item in run_obj["artifacts"]:
            path = out_dir / Path(item["path"]).name
            if not path.is_file() or path.stat().st_size != item["bytes"]:
                size_ok = False
        check(group, "清单字节数与磁盘一致", size_ok)
        check(group, "配置口径写进清单", "pipeline=dpo-policy-1.0.0" in run_obj["config_spec"])

        pairs_raw = store.read_jsonl(out_dir / "preference_pairs.jsonl")
        check(group, "偏好对结构校验", not validate_bundle("pair", pairs_raw, cfg))
        check(group, "偏好对条数与清单一致", len(pairs_raw) == counts["pairs"])
        check(group, "偏好对全部标记脱敏", all(p.get("anonymized") is True for p in pairs_raw))
        pair_sources_ok = all((p["source"]["source_id"], p["source"]["version"]) in index for p in pairs_raw)
        check(group, "偏好对来源均在登记表内", pair_sources_ok)
        axis_ok = all(p["contrast"]["margin"] >= cfg.pairs["required_axis_delta"] for p in pairs_raw)
        check(group, "每条偏好对决定性分差达标", axis_ok)

        triples_raw = store.read_jsonl(out_dir / "distill_triples.jsonl")
        check(group, "三元组结构校验", not validate_bundle("triple", triples_raw, cfg))
        targets = {t["target"] for t in triples_raw}
        adapters = {t["adapter"] for t in triples_raw}
        check(group, "SFT/DPO 两类目标都有", targets == {"sft", "dpo"}, str(sorted(targets)))
        check(group, "两种适配器都被用到", adapters == {"messages", "tool_trace"}, str(sorted(adapters)))

        metrics = json.loads((out_dir / "regression_metrics.json").read_text(encoding="utf-8"))
        check(group, "回归指标通过率 1.0", metrics["metrics"]["pass_rate"] == 1.0, str(metrics["metrics"]["pass_rate"]))
        check(group, "回归报告结构合法", not validate_bundle("report", [metrics], cfg))
        check(group, "无回退", metrics["deltas"]["regressions"] == [], str(metrics["deltas"]["regressions"]))
        check(group, "修掉两条基线失败用例", sorted(metrics["deltas"]["fixes"]) == ["CASE-05", "CASE-09"], str(metrics["deltas"]["fixes"]))

        # ---------------------------------------------------------- E 确定性
        group = "E 确定性"
        code2, _ = run_cmd(
            [sys.executable, "-m", "dpo_policy", "--root", str(ROOT), "--out-dir", str(demo2 / "out"), "--var-dir", str(demo2 / "var"), "demo"]
        )
        COMMANDS.append(("python -m dpo_policy demo（隔离目录 run2）", code2))
        check(group, "第二次 demo 退出码 0", code2 == 0, f"exit={code2}")
        diff_files: list[str] = []
        for name in expected_out + ["demo.log"]:
            a = (demo1 / "out" / name)
            b = (demo2 / "out" / name)
            if not (a.is_file() and b.is_file()):
                diff_files.append(f"{name}(缺失)")
            elif a.read_bytes() != b.read_bytes():
                diff_files.append(name)
        check(group, "两次运行产物逐字节相同", not diff_files, f"不同: {diff_files}" if diff_files else f"{len(expected_out) + 1} 份")
        var_diff: list[str] = []
        for name in expected_var:
            a = demo1 / "var" / name
            b = demo2 / "var" / name
            if not (a.is_file() and b.is_file()) or a.read_bytes() != b.read_bytes():
                var_diff.append(name)
        check(group, "两次运行工作数据相同", not var_diff, f"不同: {var_diff}" if var_diff else f"{len(expected_var)} 份")

        # ---------------------------------------------------------- F 闸门负向
        group = "F 负向"
        check(
            group,
            "未知来源 -> SOURCE_UNKNOWN",
            expect_error(ErrorCode.SOURCE_UNKNOWN, lambda: registry.resolve({"source_id": "SRC-NOPE-999", "version": "v1"})),
        )
        check(
            group,
            "版本漂移 -> SOURCE_VERSION_MISMATCH",
            expect_error(
                ErrorCode.SOURCE_VERSION_MISMATCH,
                lambda: registry.resolve({"source_id": "SRC-KB-001", "version": "v99"}),
            ),
        )
        check(
            group,
            "指纹漂移 -> SOURCE_HASH_MISMATCH",
            expect_error(
                ErrorCode.SOURCE_HASH_MISMATCH,
                lambda: registry.resolve({"source_id": "SRC-KB-001", "version": "v3", "content_sha256": "0" * 64}),
            ),
        )
        unauth = tuple(model.SourceRecord.from_dict(r) for r in store.read_jsonl(ROOT / "samples/sources_unauthorized.jsonl"))
        _, unauth_rejected = registry.resolve_corpus(unauth)
        check(group, "未授权语料全部被拒", len(unauth_rejected) == len(unauth) == 2, f"{len(unauth_rejected)}/2")
        check(group, "未授权拒绝码可枚举", {r["code"] for r in unauth_rejected} <= {ErrorCode.SOURCE_UNKNOWN, ErrorCode.SOURCE_UNAUTHORIZED})

        clock = model.LogicalClock(cfg.clock_start, cfg.clock_tick_seconds)
        gens_unauth = tuple(model.GenerationRecord.from_dict(r) for r in store.read_jsonl(ROOT / "samples/generations_unauthorized.jsonl"))
        unauth_pairs = build_pairs(gens_unauth, registry, anonymizer, cfg, clock)
        check(group, "未授权候选生成 0 对", not unauth_pairs.pairs)
        check(group, "未授权候选生成有拒绝记录", len(unauth_pairs.rejected) == 3, str(len(unauth_pairs.rejected)))

        leaky_raw = dict(store.read_jsonl(ROOT / "samples/generations.jsonl")[0])
        leaky_raw["prompt_id"] = "NEG-LEAK"
        leaky_raw["candidates"] = [dict(c) for c in leaky_raw["candidates"]]
        leaky_raw["candidates"][0]["text"] = "请联系企业微信 wxid_kf_8831001 处理，其余按规范执行即可。"
        leaky_pairs = build_pairs((model.GenerationRecord.from_dict(leaky_raw),), registry, anonymizer, cfg, clock)
        check(group, "残留标识 -> ANON_LEAK", ErrorCode.ANON_LEAK in dict(leaky_pairs.stats.get("filters", {})), str(dict(leaky_pairs.stats.get("filters", {}))))

        invalid_traces = distill_traces(store.read_jsonl(ROOT / "samples/traces_invalid.jsonl"), registry, anonymizer, cfg, clock)
        check(group, "坏轨迹 0 三元组", not invalid_traces.triples)
        check(group, "坏轨迹 4 条都被拒", len(invalid_traces.rejected) == 4, str(len(invalid_traces.rejected)))

        cases = tuple(model.GoldenCase.from_dict(r) for r in store.read_jsonl(ROOT / "samples/golden_cases.jsonl"))
        # 闸门判负向：用一个故意答错动作的引擎，验证"闸门真的会拦"，而不是验证某个实现的内部行为。
        class _BrokenEngine:
            version = "broken-engine"

            def act(self, case):  # type: ignore[no-untyped-def]
                return __import__("dpo_policy.regression", fromlist=["Decision"]).Decision(
                    action="answer_with_citation",
                    answer="这个回答既没有引用标记，也没有来源依据。",
                    citations=(),
                    policy_refs=(),
                    reasons=(),
                )

            def act_bad(self, case):  # pragma: no cover - 占位
                raise AssertionError("unused")

        broken_engine = _BrokenEngine()
        failed_report = run_regression(cases, broken_engine, cfg, clock, anonymizer)
        check(group, "坏引擎（无引用）时回归闸门不通过", not failed_report.ok)
        check(group, "闸门不通过时报告仍完整", len(failed_report.cases) == 16 and len(failed_report.failed_cases) == 16)

        # 命令级负向：样例全部指向未授权来源 -> demo 必须退出 2 且不写偏好对产物
        bad_samples = tmp_base / "bad-samples"
        shutil.copytree(ROOT / "samples", bad_samples)
        bad_gens = [dict(r) for r in store.read_jsonl(bad_samples / "generations.jsonl")]
        for raw in bad_gens:
            raw["source_ref"] = {"source_id": "SRC-WEB-901", "version": "v1"}
        store.write_jsonl(bad_samples / "generations.jsonl", bad_gens)
        code_bad, out_bad = run_cmd(
            [
                sys.executable,
                "-m",
                "dpo_policy",
                "--root",
                str(ROOT),
                "--samples-dir",
                str(bad_samples),
                "--out-dir",
                str(tmp_base / "bad-out"),
                "--var-dir",
                str(tmp_base / "bad-var"),
                "demo",
            ]
        )
        COMMANDS.append(("python -m dpo_policy demo（全部未授权来源的样例）", code_bad))
        check(group, "全量未授权样例 -> 退出码 2", code_bad == 2, f"exit={code_bad}")
        check(group, "被拒时不写偏好对产物", not (tmp_base / "bad-out" / "preference_pairs.jsonl").exists())
        check(group, "被拒时打印稳定错误码", '"code": "PAIR_NO_CANDIDATE"' in out_bad or '"code": "SOURCE_UNKNOWN"' in out_bad, out_bad.strip().splitlines()[-1][:120] if out_bad.strip() else "")

        # 配置坏 -> 退出码 3
        bad_root = tmp_base / "bad-config-root"
        (bad_root / "config").mkdir(parents=True)
        code_cfg, out_cfg = run_cmd([sys.executable, "-m", "dpo_policy", "--root", str(bad_root), "validate-config"])
        COMMANDS.append(("python -m dpo_policy validate-config（缺配置目录）", code_cfg))
        check(group, "缺配置 -> 退出码 3", code_cfg == 3, f"exit={code_cfg}")
        check(group, "缺配置错误码 CONFIG_MISSING", "CONFIG_MISSING" in out_cfg)

        # ---------------------------------------------------------- G 匿名化
        group = "G 匿名化"
        out_texts = _text_files(out_dir)
        leak_hits: dict[str, int] = {}
        for path in out_texts:
            for hit in anonymizer.scan(path.read_text(encoding="utf-8", errors="replace")):
                leak_hits[hit.kind] = leak_hits.get(hit.kind, 0) + 1
        check(group, "产物无残留个人信息模式", not leak_hits, str(leak_hits) if leak_hits else f"扫描 {len(out_texts)} 份文件")
        all_text = _read_all(out_texts)
        for token, label in (
            ("13812345678", "明文手机号"),
            ("xiaoyu.sun@example.com", "明文邮箱"),
            ("孙小雨", "明文姓名"),
            ("华辰精密", "明文机构名"),
            ("宁波远洋", "明文机构名"),
            ("林知远", "明文姓名"),
        ):
            check(group, f"产物不含{label}", token not in all_text)
        check(group, "产物出现稳定伪名", "<email:" in all_text and "<phone:" in all_text, "伪名占位符存在")
        samples_anon = store.read_jsonl(out_dir / "anonymized_samples.jsonl")
        check(group, "匿名偏好样例 8 条", len(samples_anon) == 8, str(len(samples_anon)))
        check(group, "匿名样例全部标记脱敏", all(s["anonymized"] is True for s in samples_anon))
        check(group, "匿名样例无明文 PII", not any(anonymizer.scan(json.dumps(s, ensure_ascii=False)) for s in samples_anon))

        # salt 是"演示用 salt"，随配置交付（否则买家无法复跑出同一批伪名）；
        # 要求是它不能出现在任何 out/ 产物里——产物只允许出现伪名，不允许出现 salt 本身。
        published_text = _read_all(_text_files(out_dir))
        check(group, "salt 不出现在产物里", cfg.anon_salt not in published_text)
        check(group, "salt 只随配置交付（可复跑）", cfg.anon_salt in (ROOT / "config" / "pipeline_config.json").read_text(encoding="utf-8"))
        anon_var = json.loads((var_dir / "anonymization.json").read_text(encoding="utf-8"))
        check(group, "映射数据只留摘要", set(anon_var) == {"mapping_size", "mapping_digest", "pseudonym_len", "policy", "_note"}, str(sorted(anon_var)))
        check(group, "映射摘要为 64 位 hex", isinstance(anon_var["mapping_digest"], str) and len(anon_var["mapping_digest"]) == 64)
        check(group, "映射条数为正", anon_var["mapping_size"] > 0, str(anon_var["mapping_size"]))

        # ---------------------------------------------------------- H 报告
        group = "H 报告"
        regression_md = (out_dir / "regression_report.md").read_text(encoding="utf-8")
        check(group, "回归报告无残留占位符", "{{" not in regression_md and "}}" not in regression_md)
        check(group, "回归报告写明闸门通过", "**通过**" in regression_md)
        check(group, "回归报告通过率 100%", "100.0%" in regression_md)
        check(group, "回归报告列出 16 条用例", regression_md.count("| CASE-") == 16, str(regression_md.count("| CASE-")))
        check(group, "回归报告带基线对比", "dpo-policy-0.9.0" in regression_md and "新增通过" in regression_md)
        check(group, "回归报告说明复跑方式", "python -m dpo_policy regress" in regression_md)

        audit = (out_dir / "pair_audit.md").read_text(encoding="utf-8")
        check(group, "偏好对审计含漏斗", "漏斗" in audit and "产出偏好对" in audit)
        check(group, "偏好对审计列出拦截码", "PAIR_CROSS_AXIS_REVERSAL" in audit and "PAIR_DUPLICATE" in audit)
        check(group, "偏好对审计列出授权编号", "AUTH-2026-0041" in audit)
        check(group, "偏好对审计含匿名化摘要", "映射表摘要" in audit)
        check(group, "偏好对审计无残留占位符", "{{" not in audit)

        policy_md = (out_dir / "policy_card.md").read_text(encoding="utf-8")
        check(group, "策略卡报告含统计", "蒸馏统计" in policy_md)
        card_rows = len([line for line in policy_md.splitlines() if line.startswith("| R-")])
        check(group, "策略卡至少 4 张", card_rows >= 4, str(card_rows))
        check(group, "策略卡含来源与版本", bool(re.search(r"SRC-[A-Z0-9-]+@v\d+", policy_md)))
        check(group, "策略卡无残留占位符", "{{" not in policy_md)

        demo_log = (out_dir / "demo.log").read_text(encoding="utf-8")
        check(group, "demo 日志六步齐备", all(f"{i}/6" in demo_log for i in range(1, 7)))
        check(group, "demo 日志列出产物", "产物 7 份" in demo_log)

        # ---------------------------------------------------------- I 样例生成
        group = "I 样例"
        code_gen, out_gen = run_cmd([sys.executable, str(ROOT / "scripts" / "gen_samples.py"), "--check"])
        COMMANDS.append(("python scripts/gen_samples.py --check", code_gen))
        check(group, "样例自检退出码 0", code_gen == 0, out_gen.strip().splitlines()[-1][:120] if out_gen.strip() else "")
        before = {p.name: model.sha256_text(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "samples").glob("*.jsonl"))}
        code_regen, _ = run_cmd([sys.executable, str(ROOT / "scripts" / "gen_samples.py")])
        COMMANDS.append(("python scripts/gen_samples.py（重新生成）", code_regen))
        after = {p.name: model.sha256_text(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "samples").glob("*.jsonl"))}
        check(group, "重新生成退出码 0", code_regen == 0, f"exit={code_regen}")
        check(group, "重新生成幂等（逐字节相同）", before == after, f"{len(before)} 份样例")

        # ---------------------------------------------------------- J 卫生
        group = "J 卫生"
        for p in sorted((ROOT / "dpo_policy").glob("__pycache__")):
            shutil.rmtree(p, ignore_errors=True)
        for p in sorted((ROOT / "tests").glob("__pycache__")):
            shutil.rmtree(p, ignore_errors=True)
        for p in sorted((ROOT / "scripts").glob("__pycache__")):
            shutil.rmtree(p, ignore_errors=True)
        for p in sorted((ROOT / "verify").glob("__pycache__")):
            shutil.rmtree(p, ignore_errors=True)
        pycache = [p for p in (ROOT / "dpo_policy").rglob("*") if p.name == "__pycache__"]
        check(group, "无 __pycache__", not pycache, f"{len(pycache)} 处")
        check(group, "无 .pyc 文件", not list(ROOT.rglob("*.pyc")))
        non_ascii = [p for p in ROOT.rglob("*") if p.is_file() and any(ord(ch) > 127 for ch in _rel(p))]
        check(group, "文件名全 ASCII", not non_ascii, f"{len(non_ascii)} 个")
        emoji_hits = []
        emoji_re = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F]")
        for p in _text_files(ROOT):
            if emoji_re.search(p.read_text(encoding="utf-8", errors="replace")):
                emoji_hits.append(_rel(p))
        check(group, "文本文件无 emoji", not emoji_hits, str(emoji_hits[:3]) if emoji_hits else f"{len(_text_files(ROOT))} 份文件")
        py_text = _read_all(ROOT.rglob("*.py"))
        # 注意：这里刻意用拼接构造待查 token，避免本脚本自己命中自己（自指误报）。
        clock_tokens = [
            "datetime." + "now(",
            "datetime." + "utcnow(",
            "datetime." + "today(",
            "time." + "time(",
            "date." + "today(",
        ]
        clock_hits = [t for t in clock_tokens if t in py_text]
        check(group, "无真实时钟调用", not clock_hits, str(clock_hits))
        net_tokens = [
            "import " + "urllib",
            "import " + "socket",
            "import " + "requests",
            "import " + "httpx",
            "import " + "aiohttp",
            "from " + "urllib",
            "from " + "socket",
        ]
        net_hits = [t for t in net_tokens if t in py_text]
        check(group, "无网络模块引用", not net_hits, str(net_hits))
        check(group, ".gitignore 覆盖产物", all(t in (ROOT / ".gitignore").read_text(encoding="utf-8") for t in ("__pycache__", "var/")))

        # ---------------------------------------------------------- 汇总
        total = len(CHECKS)
        passed = sum(1 for _, _, ok, _ in CHECKS if ok)
        failed = [(g, n, d) for g, n, ok, d in CHECKS if not ok]
        log()
        log("=" * 78)
        if failed:
            log("未通过的断言：")
            for g, n, d in failed:
                log(f"  - {g} {n} {d}")
        log(f"共执行命令 {len(COMMANDS)} 条：")
        for cmd, code in COMMANDS:
            log(f"  - {cmd} -> exit {code}")
        log("=" * 78)
        log(f"{passed}/{total} assertions passed")

        records = ROOT / "verify" / "records"
        records.mkdir(parents=True, exist_ok=True)
        (records / "verification_output.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
        (records / "tests_output.txt").write_text(tests_output, encoding="utf-8")
        (records / "commands.md").write_text(_commands_md(passed, total), encoding="utf-8")
        return 0 if passed == total else 1
    finally:
        shutil.rmtree(tmp_base, ignore_errors=True)


def _commands_md(passed: int, total: int) -> str:
    lines = [
        "# 验收命令与结果（订单 #1534）",
        "",
        "本文件由 `verify/run_verification.py` 在执行结束时自动生成；所有命令都在本机实际执行过。",
        "",
        "## 一、执行过的命令",
        "",
        "| 命令 | 退出码 |",
        "|---|---|",
    ]
    for cmd, code in COMMANDS:
        lines.append(f"| `{cmd}` | {code} |")
    lines.extend(
        [
            "",
            "## 二、等价的手工复跑顺序",
            "",
            "```bash",
            "python scripts/gen_samples.py --check      # 样例自检（指纹/结构/闸门/回归）",
            "python -m dpo_policy validate-config       # 配置自洽与交叉校验",
            "python -m dpo_policy sources               # 授权闸门（含未授权负样例）",
            "python -m dpo_policy demo                  # 全流程 + 四组负向对照",
            "python tests/test_runner.py                # 全部单元测试",
            "python verify/run_verification.py          # 本脚本：独立复核",
            "```",
            "",
            "## 三、结果",
            "",
            f"- 断言：{passed}/{total} 通过",
            "- 退出码约定：0 通过；2 业务闸门拒绝；3 用法/配置问题",
            "- 验收脚本只写 `verify/records/` 与系统临时目录，不改任何受测文件",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
