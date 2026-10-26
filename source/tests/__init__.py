"""测试包：让测试文件可以用 ``from tests.harness import ...`` 的统一写法。

为什么建这个文件：交付物体检脚本按"顶层目录是否含 ``__init__.py``"判断本地模块，
把 ``harness`` 当成第三方依赖会误报。加一个包标记后，``tests`` 被识别为本仓库模块，
测试仍然可以直接 ``python tests/test_pairs.py`` 单独执行（脚本会自己把项目根插进 ``sys.path``）。
"""
