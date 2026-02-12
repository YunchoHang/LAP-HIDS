from __future__ import annotations
import json
import socket
import threading
import logging
from manager.crypto import verify_hmac_sha256
from manager.storage import Storage

logger = logging.getLogger(__name__)

def parse_line(line: str) -> dict:
    """Parse and validate event envelope."""
    env = json.loads(line)
    if "sig" not in env or "event" not in env:
        raise ValueError("Invalid envelope: missing 'sig' or 'event'")
    return env

def run_receiver(host: str, port: int, psk_hex: str, db_path: str):
    """Run the event receiver server."""
    psk = bytes.fromhex(psk_hex)
    store = Storage(db_path)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((host, port))
        s.listen(20)
        logger.info(f"Receiver listening on {host}:{port}")
    except OSError as e:
        logger.error(f"Failed to bind to {host}:{port}: {e}")
        raise
    
    def handle(conn, addr):
        """Handle client connection."""
        logger.info(f"Client connected: {addr}")
        buf = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                
                # Process complete lines
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    if not raw_line.strip():
                        continue
                    
                    try:
                        raw = raw_line.decode("utf-8", errors="ignore")
                        env = parse_line(raw)
                        event = env["event"]
                        sig = env["sig"]
                        
                        # Reconstruct message for verification
                        msg = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
                        
                        if verify_hmac_sha256(psk, msg, sig):
                            store.insert(event, raw)
                            logger.debug(f"Event stored: {event.get('kind')} ({event.get('severity')})")
                        else:
                            logger.warning(f"Invalid signature from {addr}")
                    except json.JSONDecodeError as e:
                        logger.warning(f"JSON parse error from {addr}: {e}")
                    except ValueError as e:
                        logger.warning(f"Envelope validation error from {addr}: {e}")
                    except Exception as e:
                        logger.error(f"Error processing event from {addr}: {e}")
        except Exception as e:
            logger.error(f"Connection error from {addr}: {e}")
        finally:
            conn.close()
            logger.info(f"Client disconnected: {addr}")
    
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Receiver shutting down...")
    finally:
        s.close()