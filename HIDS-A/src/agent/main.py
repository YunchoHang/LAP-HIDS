from dotenv import load_dotenv
load_dotenv()
from __future__ import annotations
import json
import logging
import threading
import time
import os
import subprocess
from agent.config import (
    MANAGER_TARGETS, PSK_HEX, AUTH_LOG, WATCH_PATHS, 
    INTEGRITY_INTERVAL_SEC, PROCESS_INTERVAL_SEC, AUTH_LOG_INTERVAL_SEC,
    LOG_DIR, LOG_LEVEL, FAILED_LOGIN_THRESHOLD
)
from agent.crypto import sign_hmac_sha256
from agent.events import Event
from agent.net import TcpFailoverClient
from agent.rules import classify_severity

# Setup logging
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HIDSAgent:
    def __init__(self):
        self.psk = bytes.fromhex(PSK_HEX)
        self.client = TcpFailoverClient(MANAGER_TARGETS)
        self.running = False
        self.last_auth_pos = 0
        self.monitored_processes = {}
        
    def make_envelope(self, event: Event) -> bytes:
        """Create signed envelope for event."""
        msg = event.to_json().encode()
        sig = sign_hmac_sha256(self.psk, msg)
        env = {
            "sig": sig,
            "event": json.loads(event.to_json())
        }
        return (json.dumps(env) + "\n").encode()
    
    def send_event(self, event: Event) -> None:
        """Send event to manager with severity classification."""
        event = Event(
            ts=event.ts,
            source=event.source,
            kind=event.kind,
            severity=classify_severity(event),
            summary=event.summary,
            details=event.details
        )
        try:
            envelope = self.make_envelope(event)
            self.client.send_line(envelope)
            logger.info(f"Sent: {event.kind} ({event.severity})")
        except Exception as e:
            logger.error(f"Failed to send event: {e}")
    
    def monitor_processes(self) -> None:
        """Monitor running processes for suspicious activity."""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5
            )
            processes = result.stdout.split('\n')[1:]  # Skip header
            
            for line in processes:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 11:
                    continue
                
                pid, cmd = parts[1], ' '.join(parts[10:])
                
                # Check for suspicious commands
                for suspicious in ["nc", "ncat", "netcat", "/bin/bash", "/bin/sh"]:
                    if suspicious.lower() in cmd.lower():
                        e = Event.create(
                            source="agent",
                            kind="proc_suspicious",
                            summary=f"Suspicious process detected: {cmd}",
                            details={"pid": pid, "command": cmd}
                        )
                        self.send_event(e)
                        break
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")
    
    def monitor_auth_log(self) -> None:
        """Monitor SSH/auth failures."""
        try:
            if not os.path.exists(AUTH_LOG):
                logger.warning(f"Auth log not found: {AUTH_LOG}")
                return
            
            with open(AUTH_LOG, 'r') as f:
                f.seek(self.last_auth_pos)
                new_lines = f.readlines()
                self.last_auth_pos = f.tell()
            
            failed_ips = {}
            
            for line in new_lines:
                if "Failed password" in line or "Invalid user" in line:
                    # Extract IP if possible
                    parts = line.split()
                    ip = "unknown"
                    for part in parts:
                        if part.replace(".", "").isdigit() and len(part.split(".")) == 4:
                            ip = part
                            break
                    
                    failed_ips[ip] = failed_ips.get(ip, 0) + 1
            
            for ip, count in failed_ips.items():
                if count >= FAILED_LOGIN_THRESHOLD:
                    severity = "HIGH" if count >= 10 else "WARN"
                    e = Event.create(
                        source="agent",
                        kind="ssh_fail",
                        summary=f"Multiple failed SSH attempts from {ip}",
                        details={"ip": ip, "fail_count": count},
                        severity=severity
                    )
                    self.send_event(e)
        except Exception as e:
            logger.error(f"Auth log monitoring error: {e}")
    
    def monitor_file_integrity(self) -> None:
        """Monitor watched directories for changes."""
        try:
            import hashlib
            for watch_path in WATCH_PATHS:
                if not os.path.exists(watch_path):
                    logger.warning(f"Watch path not found: {watch_path}")
                    continue
                
                for root, dirs, files in os.walk(watch_path):
                    # Skip common non-critical subdirs
                    dirs[:] = [d for d in dirs if d not in ['.cache', '__pycache__', '.git']]
                    
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'rb') as f:
                                file_hash = hashlib.sha256(f.read()).hexdigest()
                            
                            current_hash = self.monitored_processes.get(filepath)
                            if current_hash and current_hash != file_hash:
                                e = Event.create(
                                    source="agent",
                                    kind="file_change",
                                    summary=f"File integrity changed: {filepath}",
                                    details={"path": filepath, "old_hash": current_hash, "new_hash": file_hash},
                                    severity="WARN"
                                )
                                self.send_event(e)
                            
                            self.monitored_processes[filepath] = file_hash
                        except (PermissionError, OSError):
                            pass
        except Exception as e:
            logger.error(f"File integrity monitoring error: {e}")
    
    def startup_event(self) -> None:
        """Send agent startup event."""
        e = Event.create(
            source="agent",
            kind="agent_started",
            summary="HIDS Agent started",
            details={
                "targets": MANAGER_TARGETS,
                "watch_paths": WATCH_PATHS,
                "version": "1.0"
            }
        )
        self.send_event(e)
    
    def run(self) -> None:
        """Main agent loop."""
        self.running = True
        logger.info("HIDS Agent starting...")
        self.startup_event()
        
        last_process_check = 0
        last_auth_check = 0
        last_integrity_check = 0
        
        try:
            while self.running:
                now = time.time()
                
                # Process monitoring
                if now - last_process_check >= PROCESS_INTERVAL_SEC:
                    self.monitor_processes()
                    last_process_check = now
                
                # Auth log monitoring
                if now - last_auth_check >= AUTH_LOG_INTERVAL_SEC:
                    self.monitor_auth_log()
                    last_auth_check = now
                
                # File integrity monitoring
                if now - last_integrity_check >= INTEGRITY_INTERVAL_SEC:
                    self.monitor_file_integrity()
                    last_integrity_check = now
                
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Agent shutting down...")
        except Exception as e:
            logger.error(f"Agent error: {e}", exc_info=True)
        finally:
            self.client.close()

def main():
    agent = HIDSAgent()
    agent.run()

if __name__ == "__main__":
    main()