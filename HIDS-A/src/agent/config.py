from __future__ import annotations
import os
from pathlib import Path

# PSK from environment variable or default (for testing only)
PSK_HEX = os.getenv("HIDS_PSK", "").strip()
if not PSK_HEX:
    raise RuntimeError("HIDS_PSK not set (load it from .env or environment)")

# Manager targets - update these to your actual Windows machine IPs
MANAGER_TARGETS = [
    (os.getenv("HIDS_MANAGER_LAN", "192.168.0.101"), int(os.getenv("HIDS_MANAGER_PORT", "5055"))),
    (os.getenv("HIDS_MANAGER_REMOTE", "100.83.22.62"), int(os.getenv("HIDS_MANAGER_PORT", "5055"))),
]

# System monitoring paths (Linux-specific)
AUTH_LOG = "/var/log/auth.log"
WATCH_PATHS = ["/etc", "/usr/bin", "/usr/sbin"]
SUSPICIOUS_PROCESSES = ["nc", "ncat", "netcat", "bash", "sh"]  # Common malware tools

# File integrity baseline
BASELINE_PATH = "/opt/hids/baseline.json"
BASELINE_CHECK_ENABLED = True

# Timing intervals (seconds)
INTEGRITY_INTERVAL_SEC = 300  # 5 minutes
PROCESS_INTERVAL_SEC = 10
AUTH_LOG_INTERVAL_SEC = 5

# Logging
LOG_DIR = "/var/log/hids"
LOG_LEVEL = os.getenv("HIDS_LOG_LEVEL", "INFO")

# Thresholds for alerting
FAILED_LOGIN_THRESHOLD = 5  # Alert after 5 failed logins
SSH_PORT_DEFAULT = 22