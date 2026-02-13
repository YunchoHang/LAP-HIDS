from __future__ import annotations

import logging
import os
import time
from typing import Callable, Dict, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

SendFn = Callable[[str, str, dict, str], None]
# send(kind, summary, details, severity)


class _Handler(FileSystemEventHandler):
    def __init__(self, send: SendFn, ignore_hidden: bool = True, cooldown_sec: int = 2):
        super().__init__()
        self.send = send
        self.ignore_hidden = ignore_hidden
        self.cooldown_sec = cooldown_sec
        self._last: Dict[str, float] = {}  # key -> last ts (dedupe)

    def _should_ignore(self, path: str) -> bool:
        if not path:
            return True
        if self.ignore_hidden and any(part.startswith(".") for part in path.split(os.sep) if part):
            return True
        return False

    def _emit(self, kind: str, path: str, extra: Optional[dict] = None, severity: str = "INFO"):
        if self._should_ignore(path):
            return
        key = f"{kind}:{path}"
        now = time.time()
        if now - self._last.get(key, 0.0) < self.cooldown_sec:
            return
        self._last[key] = now
        details = {"path": path}
        if extra:
            details.update(extra)
        self.send(kind, f"{kind.replace('_',' ').title()}: {path}", details, severity)

    def on_created(self, event):
        if event.is_directory:
            return
        self._emit("file_created", event.src_path, severity="WARN")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._emit("file_modified", event.src_path, severity="INFO")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._emit("file_deleted", event.src_path, severity="WARN")

    def on_moved(self, event):
        if event.is_directory:
            return
        self._emit(
            "file_moved",
            event.dest_path,
            extra={"from": event.src_path, "to": event.dest_path},
            severity="WARN",
        )


class FileWatcher:
    def __init__(self, paths: list[str], send: SendFn, recursive: bool = True):
        self.paths = paths
        self.observer = Observer()
        self.handler = _Handler(send=send)
        self.recursive = recursive
        self._started = False

    def start(self):
        if self._started:
            return
        for p in self.paths:
            if os.path.exists(p):
                self.observer.schedule(self.handler, p, recursive=self.recursive)
                logger.info(f"[filewatch] Watching: {p}")
            else:
                logger.warning(f"[filewatch] Path not found: {p}")
        self.observer.start()
        self._started = True

    def stop(self):
        if not self._started:
            return
        self.observer.stop()
        self.observer.join(timeout=5)
        self._started = False
