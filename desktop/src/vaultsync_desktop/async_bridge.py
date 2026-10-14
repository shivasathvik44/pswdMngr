"""Asyncio bridge for PySide6 GUI applications.

Runs network and cryptographic operations in a dedicated background asyncio thread
and dispatches completion/error callbacks safely to the Qt main GUI thread.
"""

import asyncio
import logging
import threading
from typing import Any, Callable, Coroutine, Optional
from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QApplication

logger = logging.getLogger(__name__)


class AsyncDispatcher(QObject):
    """Dispatches coroutine execution to a background event loop and routes callbacks to Qt."""

    sig_success = Signal(object, object)  # (on_success, result)
    sig_error = Signal(object, object)    # (on_error, exception)
    sig_finally = Signal(object)          # (on_finally)
    sig_call = Signal(object, tuple, dict)  # (func, args, kwargs)

    def __init__(self):
        super().__init__()
        app = QApplication.instance()
        if app is not None and self.thread() != app.thread():
            self.moveToThread(app.thread())

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="VaultSync-AsyncLoop")
        self._thread.start()

        # Connect signals so callbacks execute on the Qt main GUI thread
        self.sig_success.connect(self._dispatch_success)
        self.sig_error.connect(self._dispatch_error)
        self.sig_finally.connect(self._dispatch_finally)
        self.sig_call.connect(self._dispatch_call)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def stop(self) -> None:
        """Cleanly stop the background event loop."""
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    @Slot(object, object)
    def _dispatch_success(self, callback: Any, result: Any) -> None:
        if callable(callback):
            try:
                callback(result)
            except RuntimeError as re:
                logger.debug("Skipping on_success for deleted Qt object: %s", re)
            except Exception as exc:
                logger.error("Error in on_success callback: %s", exc)

    @Slot(object, object)
    def _dispatch_error(self, callback: Any, exception: Any) -> None:
        if callable(callback):
            try:
                callback(exception)
            except RuntimeError as re:
                logger.debug("Skipping on_error for deleted Qt object: %s", re)
            except Exception as exc:
                logger.error("Error in on_error callback: %s", exc)

    @Slot(object)
    def _dispatch_finally(self, callback: Any) -> None:
        if callable(callback):
            try:
                callback()
            except RuntimeError as re:
                logger.debug("Skipping on_finally for deleted Qt object: %s", re)
            except Exception as exc:
                logger.error("Error in on_finally callback: %s", exc)

    @Slot(object, tuple, dict)
    def _dispatch_call(self, func: Any, args: tuple, kwargs: dict) -> None:
        if callable(func):
            try:
                func(*args, **kwargs)
            except RuntimeError as re:
                logger.debug("Skipping call for deleted Qt object: %s", re)
            except Exception as exc:
                logger.error("Error executing callback on GUI thread: %s", exc)

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


def call_on_gui_thread(func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """Execute func on the Qt main GUI thread safely.

    If already on the Qt main GUI thread, or if no QApplication instance exists
    (e.g. in headless unit tests), func is invoked immediately.
    Otherwise, func is dispatched to the Qt main thread via the Qt event loop.
    """
    app = QApplication.instance()
    if app is None:
        func(*args, **kwargs)
        return

    gui_thread = app.thread()
    if QThread.currentThread() == gui_thread:
        func(*args, **kwargs)
    else:
        dispatcher = get_dispatcher()
        dispatcher.sig_call.emit(func, args, kwargs)

