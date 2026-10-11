"""Asyncio bridge for PySide6 GUI applications.

Runs network and cryptographic operations in a dedicated background asyncio thread
and dispatches completion/error callbacks safely to the Qt main GUI thread.
"""

import asyncio
import threading
from typing import Any, Callable, Coroutine, Optional
from PySide6.QtCore import QObject, Signal


class AsyncDispatcher(QObject):
    """Dispatches coroutine execution to a background event loop and routes callbacks to Qt."""

    sig_success = Signal(object, object)  # (on_success, result)
    sig_error = Signal(object, object)    # (on_error, exception)
    sig_finally = Signal(object)          # (on_finally)

    def __init__(self):
        super().__init__()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="VaultSync-AsyncLoop")
        self._thread.start()

        # Connect signals so callbacks execute on the Qt main GUI thread
        self.sig_success.connect(self._dispatch_success)
        self.sig_error.connect(self._dispatch_error)
        self.sig_finally.connect(self._dispatch_finally)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _dispatch_success(self, callback: Any, result: Any) -> None:
        if callable(callback):
            callback(result)

    def _dispatch_error(self, callback: Any, exception: Any) -> None:
        if callable(callback):
            callback(exception)

    def _dispatch_finally(self, callback: Any) -> None:
        if callable(callback):
            callback()

    def run(
        self,
        coro: Coroutine[Any, Any, Any],
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_finally: Optional[Callable[[], None]] = None,
    ) -> asyncio.Future:
        """Schedule coroutine on background loop and route callbacks to Qt."""

        async def _wrapper():
            try:
                result = await coro
                self.sig_success.emit(on_success, result)
            except Exception as exc:
                self.sig_error.emit(on_error, exc)
            finally:
                if on_finally:
                    self.sig_finally.emit(on_finally)

        return asyncio.run_coroutine_threadsafe(_wrapper(), self._loop)


_global_dispatcher: Optional[AsyncDispatcher] = None


def get_dispatcher() -> AsyncDispatcher:
    """Retrieve or initialize the global AsyncDispatcher singleton."""
    global _global_dispatcher
    if _global_dispatcher is None:
        _global_dispatcher = AsyncDispatcher()
    return _global_dispatcher


def run_async(
    coro: Coroutine[Any, Any, Any],
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_finally: Optional[Callable[[], None]] = None,
) -> asyncio.Future:
    """Convenience function to run a coroutine asynchronously with Qt GUI callbacks."""
    return get_dispatcher().run(coro, on_success=on_success, on_error=on_error, on_finally=on_finally)
