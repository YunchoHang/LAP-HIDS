from __future__ import annotations
import os

# PSK (required)
PSK_HEX = os.getenv("HIDS_PSK", "").strip()
if not PSK_HEX:
    raise RuntimeError("HIDS_PSK not set (load it from .env or environment)")

# Optional: quick sanity check (prevents accidental bad keys)
if len(PSK_HEX) != 64 or any(c not in "0123456789abcdefABCDEF" for c in PSK_HEX):
    raise RuntimeError("HIDS_PSK must be exactly 64 hex characters")

# Manager targets (LAN first, then Tailscale fallback)
MANAGER_PORT = int(os.getenv("HIDS_MANAGER_PORT", "5055"))
MANAGER_TARGETS = [
    (os.getenv("HIDS_MANAGER_LAN", "192.168.0.103").strip(), MANAGER_PORT),
    (os.getenv("HIDS_MANAGER_REMOTE", "100.83.22.62").strip(), MANAGER_PORT),
]

# Linux monitoring paths
AUTH_LOG = os.getenv("HIDS_AUTH_LOG", "/var/log/auth.log")
WATCH_PATHS = [p.strip() for p in os.getenv("HIDS_WATCH_PATHS", "/etc,/usr/bin,/usr/sbin").split(",") if p.strip()]

# Avoid false positives: shells are everywhere; use tool-like suspects instead
SUSPICIOUS_PROCESSES = [p.strip().lower() for p in os.getenv(
    "HIDS_SUSPICIOUS_PROCESSES",
    "nc,ncat,netcat,socat,curl,wget"
).split(",") if p.strip()]

# Baseline
BASELINE_PATH = os.getenv("HIDS_BASELINE_PATH", "/opt/hids/baseline.json")
BASELINE_CHECK_ENABLED = os.getenv("HIDS_BASELINE_ENABLED", "1") not in ("0", "false", "False", "no", "NO")

# Timing (seconds)
INTEGRITY_INTERVAL_SEC = int(os.getenv("HIDS_INTEGRITY_INTERVAL", "300"))
PROCESS_INTERVAL_SEC = int(os.getenv("HIDS_PROCESS_INTERVAL", "10"))
AUTH_LOG_INTERVAL_SEC = int(os.getenv("HIDS_AUTH_INTERVAL", "5"))

# Logging (user-writable default)
LOG_DIR = os.getenv("HIDS_LOG_DIR", os.path.expanduser("~/hids_logs"))
LOG_LEVEL = os.getenv("HIDS_LOG_LEVEL", "INFO").upper()

# Thresholds
FAILED_LOGIN_THRESHOLD = int(os.getenv("HIDS_FAILED_LOGIN_THRESHOLD", "5"))
SSH_PORT_DEFAULT = int(os.getenv("HIDS_SSH_PORT_DEFAULT", "22"))
