"""
pure — 纯 Python 工具实现（零外部二进制依赖）
"""
import asyncio
from typing import Any, Coroutine


def run_async(coro: Coroutine) -> Any:
    """
    安全地运行异步协程，兼容各种运行环境：
    - 普通脚本（无事件循环）
    - Jupyter / IPython（已有运行中的事件循环）
    - 多线程环境
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # 已有运行中的事件循环，在新线程中执行
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, coro)
        return future.result()
