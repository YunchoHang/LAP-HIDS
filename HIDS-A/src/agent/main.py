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


def _extract_user_from_accepted(line: str) -> str:
    parts = line.split()
    try:
        i = parts.index("for")
        if i + 1 < len(parts):
            return parts[i + 1]
    except ValueError:
        pass
    return "unknown"


def _now() -> float:
    return time.time()


# ---------------- Agent ----------------
class HIDSAgent:

    PROC_ALERT_COOLDOWN_SEC = 120
    LOGIN_SUCCESS_COOLDOWN_SEC = 30

    MAX_FILE_BYTES = 5 * 1024 * 1024
    SKIP_DIRS = {".git", "__pycache__", ".cache", "node_modules", "venv", ".venv", "proc", "sys", "dev", "run"}

    def __init__(self):
        self.psk = bytes.fromhex(PSK_HEX)
        self.client = TcpFailoverClient(MANAGER_TARGETS)
        self.running = True

        # Start reading auth log like tail -f
        self.last_auth_pos = os.path.getsize(AUTH_LOG) if os.path.exists(AUTH_LOG) else 0

        self.seen_proc_alerts: Dict[Tuple[str, str], float] = {}
        self.seen_login_success: Dict[str, float] = {}

        self.known_ips: set[str] = set()
        self.file_hashes: Dict[str, str] = {}

        self.suspicious_tokens = [s.lower() for s in SUSPICIOUS_PROCESSES]

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

            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 11:
                    continue

                pid = parts[1]
                cmd = " ".join(parts[10:])
                cmd_l = cmd.lower()

                for token in self.suspicious_tokens:
                    if token in cmd_l:

                        key = (pid, token)
                        last = self.seen_proc_alerts.get(key, 0)

                        if _now() - last < self.PROC_ALERT_COOLDOWN_SEC:
                            break

                        self.seen_proc_alerts[key] = _now()

                        e = Event.create(
                            source="agent",
                            kind="proc_suspicious",
                            summary=f"Suspicious process '{token}' detected",
                            details={"pid": pid, "command": cmd},
                            severity="CRITICAL",
                        )
                        self.send_event(e)
                        break

        except Exception as e:
            logger.error(f"Process monitor error: {e}")

    # ---- Auth log monitoring ----
    def monitor_auth_log(self) -> None:

        try:

            if not os.path.exists(AUTH_LOG):
                return

            with open(AUTH_LOG, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.last_auth_pos)
                new_lines = f.readlines()
                self.last_auth_pos = f.tell()

            failed_ips: Dict[str, int] = {}

            for line in new_lines:

                # SUCCESSFUL LOGIN
                if (
                    "Accepted password" in line
                    or "Accepted publickey" in line
                    or "session opened for user" in line
                ):

                    ip = _extract_ipv4(line) or "unknown"
                    user = _extract_user_from_accepted(line)

                    last = self.seen_login_success.get(ip, 0)

                    if _now() - last > self.LOGIN_SUCCESS_COOLDOWN_SEC:

                        self.seen_login_success[ip] = _now()

                        is_new_ip = ip not in self.known_ips
                        self.known_ips.add(ip)

                        kind = "ssh_login_success_new_ip" if is_new_ip else "ssh_login_success"

                        e = Event.create(
                            source="agent",
                            kind=kind,
                            summary=f"Successful SSH login {user} from {ip}",
                            details={"user": user, "ip": ip},
                            severity="WARN" if is_new_ip else "INFO",
                        )

                        self.send_event(e)

                # FAILED / SCAN DETECTION
                if (
                    "Failed password" in line
                    or "Invalid user" in line
                    or "authentication failure" in line
                    or "Connection closed by authenticating user" in line
                    or "Disconnected from authenticating user" in line
                ):

                    ip = _extract_ipv4(line) or "unknown"
                    failed_ips[ip] = failed_ips.get(ip, 0) + 1

            for ip, count in failed_ips.items():

                if count >= FAILED_LOGIN_THRESHOLD:

                    e = Event.create(
                        source="agent",
                        kind="ssh_fail",
                        summary=f"Multiple SSH failures from {ip}",
                        details={"ip": ip, "count": count},
                        severity="HIGH" if count >= FAILED_LOGIN_THRESHOLD * 2 else "WARN",
                    )

                    self.send_event(e)

        except Exception as e:
            logger.error(f"Auth monitor error: {e}")

    # ---- File Integrity ----
    def monitor_file_integrity(self):

        import hashlib

        try:
            for path in WATCH_PATHS:

                for root, dirs, files in os.walk(path):

                    dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

                    for f in files:

                        fp = os.path.join(root, f)

                        try:
                            if os.path.getsize(fp) > self.MAX_FILE_BYTES:
                                continue

                            h = hashlib.sha256()

                            with open(fp, "rb") as file:
                                for chunk in iter(lambda: file.read(4096), b""):
                                    h.update(chunk)

                            new_hash = h.hexdigest()
                            old_hash = self.file_hashes.get(fp)

                            if old_hash and old_hash != new_hash:

                                e = Event.create(
                                    source="agent",
                                    kind="file_change",
                                    summary=f"File modified {fp}",
                                    details={"path": fp},
                                    severity="WARN",
                                )

                                self.send_event(e)

                            self.file_hashes[fp] = new_hash

                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"Integrity monitor error: {e}")

    # ---- Startup ----
    def startup_event(self):

        e = Event.create(
            source="agent",
            kind="agent_started",
            summary="HIDS agent started",
            details={"targets": MANAGER_TARGETS},
            severity="INFO",
        )

        self.send_event(e)

    # ---- Main loop ----
    def run(self):

        logger.info("HIDS Agent starting")
        self.startup_event()

        try:
            self.filewatch.start()
        except Exception:
            pass

        last_proc = 0
        last_auth = 0
        last_integrity = 0

        while self.running:

            now = _now()

            if now - last_proc >= PROCESS_INTERVAL_SEC:
                self.monitor_processes()
                last_proc = now

            if now - last_auth >= AUTH_LOG_INTERVAL_SEC:
                self.monitor_auth_log()
                last_auth = now

            if now - last_integrity >= INTEGRITY_INTERVAL_SEC:
                self.monitor_file_integrity()
                last_integrity = now

            time.sleep(1)


def main():
    HIDSAgent().run()


if __name__ == "__main__":
    main()