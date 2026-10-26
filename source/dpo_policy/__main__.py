"""``python -m dpo_policy`` 入口：等价于 ``python -m dpo_policy.cli``。"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
