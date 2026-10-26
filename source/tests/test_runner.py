"""测试总入口：把三份测试文件各跑一遍并汇总。

    python tests/test_runner.py

为什么用子进程而不是直接 import：每份测试文件都要求"能单独执行"，用子进程跑正好
顺带验证了这一点；同时也避免测试之间的模块级状态互相污染。汇总行固定为
``TOTAL: X/Y tests passed``，验证脚本按这一行解析。
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_FILES = ("test_core.py", "test_pairs.py", "test_distill.py")
SUMMARY_RE = re.compile(r"(\d+)/(\d+) tests passed")


def main() -> int:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    passed_total = 0
    total = 0
    failed_files: list[str] = []

    for name in TEST_FILES:
        path = ROOT / "tests" / name
        if not path.is_file():
            print(f"[runner] 缺少测试文件: {name}")
            failed_files.append(name)
            continue
        print(f"[runner] == {name} ==")
        proc = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        print(out.rstrip())
        match = None
        for line in reversed(out.strip().splitlines()):
            found = SUMMARY_RE.search(line)
            if found:
                match = found
                break
        if match is None:
            print(f"[runner] {name} 没有输出汇总行，视为失败")
            failed_files.append(name)
            continue
        file_passed, file_total = int(match.group(1)), int(match.group(2))
        passed_total += file_passed
        total += file_total
        if proc.returncode != 0 or file_passed != file_total:
            failed_files.append(f"{name} ({file_passed}/{file_total}, exit={proc.returncode})")

    print(f"[runner] 失败文件: {', '.join(failed_files) if failed_files else '无'}")
    print(f"TOTAL: {passed_total}/{total} tests passed")
    return 0 if not failed_files and passed_total == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
