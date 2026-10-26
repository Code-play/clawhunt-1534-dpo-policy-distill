"""无第三方框架的最小测试收集器。

测试文件统一遵循三条约定，``tests/test_runner.py`` 才能把它们聚起来：

1. 顶层提供 ``run() -> int``：跑完所有用例并返回退出码（0 全过，1 有失败）；
2. 打印一行汇总，形如 ``12/12 tests passed``，且必须是最后一行；
3. ``if __name__ == "__main__": sys.exit(run())``，可单独执行。

为什么不用 pytest：交付物要求"零第三方依赖、一条命令复跑"，标准库能做完的事不引入依赖。
"""

from __future__ import annotations

import sys
import traceback
from typing import Callable, Iterable, Sequence

from dpo_policy.model import PipelineError

__all__ = ["run_cases", "expect_pipeline_error", "Case"]


class Case:
    """一个具名用例：名字 + 无参可调用。"""

    __slots__ = ("name", "fn")

    def __init__(self, name: str, fn: Callable[[], None]) -> None:
        self.name = name
        self.fn = fn


def expect_pipeline_error(code: str, fn: Callable[[], None], *, record_id: str | None = None) -> PipelineError:
    """断言 ``fn`` 恰好抛出指定错误码的 :class:`PipelineError`。

    验收只认码不认文本，所以测试也必须按码断言；顺带校验 ``record_id``（给出时）。
    """
    try:
        fn()
    except PipelineError as exc:
        if exc.code != code:
            raise AssertionError(f"期望错误码 {code}，实际 {exc.code}（{exc.message}）") from exc
        if record_id is not None and exc.record_id != record_id:
            raise AssertionError(f"期望 record_id={record_id!r}，实际 {exc.record_id!r}") from exc
        return exc
    raise AssertionError(f"期望抛出 PipelineError({code})，实际没有抛异常")


def run_cases(cases: Iterable[Case | tuple[str, Callable[[], None]]], *, title: str = "", verbose: bool = True) -> int:
    """逐条执行用例，汇总后打印 ``passed/total tests passed``（必须是最后一行）。"""
    passed = 0
    failed = 0
    failures: list[tuple[str, str]] = []
    for item in cases:
        case = item if isinstance(item, Case) else Case(item[0], item[1])
        try:
            case.fn()
        except AssertionError as exc:
            failed += 1
            failures.append((case.name, str(exc) or "assertion failed"))
        except Exception as exc:  # noqa: BLE001 - 测试里任何异常都算失败，但要留住堆栈
            failed += 1
            failures.append((case.name, f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"))
        else:
            passed += 1
            if verbose:
                print(f"  ok   {case.name}")
    total = passed + failed
    if title:
        print(f"[{title}]")
    for name, detail in failures:
        print(f"  FAIL {name}: {detail}")
    print(f"{passed}/{total} tests passed")
    return 0 if failed == 0 else 1


def main(run: Callable[[], int]) -> None:
    """``__main__`` 的统一收尾：保证退出码与汇总行一致。"""
    sys.exit(run())
