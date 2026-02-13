from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import json
import logging
import os
import subprocess
import time
from typing import Dict, Tuple, Optional

from agent.filewatch import FileWatcher
from agent.config import (
    MANAGER_TARGETS, PSK_HEX, AUTH_LOG, WATCH_PATHS,
    INTEGRITY_INTERVAL_SEC, PROCESS_INTERVAL_SEC, AUTH_LOG_INTERVAL_SEC,
    LOG_DIR, LOG_LEVEL, FAILED_LOGIN_THRESHOLD, SUSPICIOUS_PROCESSES,
)
from agent.crypto import sign_hmac_sha256
from agent.events import Event
from agent.net import TcpFailoverClient
from agent.rules import classify_severity


# ---------------- Logging ----------------
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "agent.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ---------------- Helpers ----------------
def _extract_ipv4(text: str) -> Optional[str]:
    parts = text.replace("(", " ").replace(")", " ").replace("[", " ").replace("]", " ").split()
    for p in parts:
        if p.count(".") == 3:
            octets = p.split(".")
            if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                return p
    return None


def _now() -> float:
    return time.time()


# ---------------- Agent ----------------
class HIDSAgent:
    """
    Agent monitors:
      - suspicious processes
      - auth log failures
      - real-time filesystem events (watchdog)
      - optional periodic file integrity hashing
    Sends signed events to manager.
    """

    # Cooldown to avoid spamming the same process alert repeatedly
    PROC_ALERT_COOLDOWN_SEC = 120  # 2 minutes

    # File hashing safety limits
    MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
    SKIP_DIRS = {".git", "__pycache__", ".cache", "node_modules", "venv", ".venv", "proc", "sys", "dev", "run"}

    def __init__(self):
        self.psk = bytes.fromhex(PSK_HEX)
        self.client = TcpFailoverClient(MANAGER_TARGETS)
        self.running = True

        # Auth log tail position
        self.last_auth_pos = 0

        # Dedup for process alerts: (pid, token) -> last_alert_ts
        self.seen_proc_alerts: Dict[Tuple[str, str], float] = {}

        # File integrity hashes: path -> sha256
        self.file_hashes: Dict[str, str] = {}

        # Normalize suspicious tokens once
        self.suspicious_tokens = [s.lower() for s in SUSPICIOUS_PROCESSES]

        # Real-time filesystem watcher
        self.filewatch = FileWatcher(paths=WATCH_PATHS, send=self.send_simple, recursive=True)

    # ---- Sending / signing ----
    def make_envelope(self, event: Event) -> bytes:
        event_dict = json.loads(event.to_json())
        msg = json.dumps(event_dict, separators=(",", ":"), sort_keys=True).encode()
        sig = sign_hmac_sha256(self.psk, msg)
        env = {"sig": sig, "event": event_dict}
        return (json.dumps(env) + "\n").encode()

    def send_event(self, event: Event) -> None:
        sev = event.severity if getattr(event, "severity", None) else classify_severity(event)
        event = Event(
            ts=event.ts,
            source=event.source,
            kind=event.kind,
            severity=sev,
            summary=event.summary,
            details=event.details,
        )
        try:
            self.client.send_line(self.make_envelope(event))
            logger.info(f"Sent: {event.kind} ({event.severity})")
        except Exception as e:
            logger.error(f"Failed to send event: {e}", exc_info=True)

    # Callback for FileWatcher
    def send_simple(self, kind: str, summary: str, details: dict, severity: str = "INFO") -> None:
        e = Event.create(
            source="agent",
            kind=kind,
            summary=summary,
            details=details,
            severity=severity,
        )
        self.send_event(e)

    # ---- Process monitoring ----
    def monitor_processes(self) -> None:
        try:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
            lines = result.stdout.splitlines()
            if len(lines) <= 1:
                return

            for line in lines[1:]:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 11:
                    continue

                pid = parts[1]
                cmd = " ".join(parts[10:])
                cmd_l = cmd.lower()

                for token in self.suspicious_tokens:
                    if token in cmd_l:
                        key = (pid, token)
                        last = self.seen_proc_alerts.get(key, 0.0)
                        if _now() - last < self.PROC_ALERT_COOLDOWN_SEC:
                            break

                        self.seen_proc_alerts[key] = _now()
                        e = Event.create(
                            source="agent",
                            kind="proc_suspicious",
                            summary=f"Suspicious process token='{token}' detected: {cmd}",
                            details={"pid": pid, "command": cmd, "match": token},
                            severity="CRITICAL",
                        )
                        self.send_event(e)
                        break

            cutoff = _now() - (self.PROC_ALERT_COOLDOWN_SEC * 10)
            self.seen_proc_alerts = {k: v for k, v in self.seen_proc_alerts.items() if v >= cutoff}

        except Exception as e:
            logger.error(f"Process monitoring error: {e}", exc_info=True)

    # ---- Auth log monitoring ----
    def monitor_auth_log(self) -> None:
        try:
            if not os.path.exists(AUTH_LOG):
                logger.warning(f"Auth log not found: {AUTH_LOG}")
                return

            with open(AUTH_LOG, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.last_auth_pos)
                new_lines = f.readlines()
                self.last_auth_pos = f.tell()

            if not new_lines:
                return

            failed_ips: Dict[str, int] = {}

            for line in new_lines:
                if "Failed password" in line or "Invalid user" in line:
                    ip = _extract_ipv4(line) or "unknown"
                    failed_ips[ip] = failed_ips.get(ip, 0) + 1

            for ip, count in failed_ips.items():
                if count >= FAILED_LOGIN_THRESHOLD:
                    e = Event.create(
                        source="agent",
                        kind="ssh_fail",
                        summary=f"Multiple failed SSH attempts from {ip}",
                        details={"ip": ip, "fail_count": count},
                        severity="HIGH" if count >= (FAILED_LOGIN_THRESHOLD * 2) else "WARN",
                    )
                    self.send_event(e)

        except Exception as e:
            logger.error(f"Auth log monitoring error: {e}", exc_info=True)

    # ---- Optional periodic file hashing (useful for /etc; can be noisy for /home) ----
    def _hash_file_sha256(self, filepath: str) -> Optional[str]:
        import hashlib
        try:
            st = os.stat(filepath)
            if st.st_size > self.MAX_FILE_BYTES:
                return None
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError, IsADirectoryError, OSError):
            return None

    def monitor_file_integrity(self) -> None:
        try:
            for watch_path in WATCH_PATHS:
                if not os.path.exists(watch_path):
                    continue

                for root, dirs, files in os.walk(watch_path):
                    dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

                    for fname in files:
                        filepath = os.path.join(root, fname)
                        new_hash = self._hash_file_sha256(filepath)
                        if not new_hash:
                            continue

                        old_hash = self.file_hashes.get(filepath)
                        if old_hash and old_hash != new_hash:
                            e = Event.create(
                                source="agent",
                                kind="file_change",
                                summary=f"File integrity changed: {filepath}",
                                details={"path": filepath, "old_hash": old_hash, "new_hash": new_hash},
                                severity="WARN",
                            )
                            self.send_event(e)

                        self.file_hashes[filepath] = new_hash

        except Exception as e:
            logger.error(f"File integrity monitoring error: {e}", exc_info=True)

    # ---- Startup / loop ----
    def startup_event(self) -> None:
        e = Event.create(
            source="agent",
            kind="agent_started",
            summary="HIDS Agent started",
            details={"targets": MANAGER_TARGETS, "watch_paths": WATCH_PATHS, "version": "1.2"},
            severity="INFO",
        )
        self.send_event(e)

    def run(self) -> None:
        logger.info("HIDS Agent starting...")
        self.startup_event()

        # Start real-time file watcher
        try:
            self.filewatch.start()
        except Exception as e:
            logger.error(f"Filewatch failed to start: {e}", exc_info=True)

        last_process_check = 0.0
        last_auth_check = 0.0
        last_integrity_check = 0.0

        try:
            while self.running:
                now = _now()

                if now - last_process_check >= PROCESS_INTERVAL_SEC:
                    self.monitor_processes()
                    last_process_check = now

                if now - last_auth_check >= AUTH_LOG_INTERVAL_SEC:
                    self.monitor_auth_log()
                    last_auth_check = now

                # If you feel you get duplicates/noise, comment this block out
                if now - last_integrity_check >= INTEGRITY_INTERVAL_SEC:
                    self.monitor_file_integrity()
                    last_integrity_check = now

                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Agent shutting down (Ctrl+C)...")
        except Exception as e:
            logger.error(f"Agent error: {e}", exc_info=True)
        finally:
            try:
                self.filewatch.stop()
            except Exception:
                pass
            try:
                self.client.close()
            except Exception:
                pass


def main():
    HIDSAgent().run()


if __name__ == "__main__":
    main()
