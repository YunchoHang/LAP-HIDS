from __future__ import annotations
import socket
import time
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

class TcpFailoverClient:
    """TCP client with automatic failover to multiple targets."""
    
    def __init__(
        self,
        targets: List[Tuple[str, int]],
        timeout_sec: float = 5.0,
        retry_delay_sec: float = 2.0
    ):
        self.targets = targets
        self.timeout_sec = timeout_sec
        self.retry_delay_sec = retry_delay_sec
        self.sock: socket.socket | None = None
        self.connected_to: Tuple[str, int] | None = None

    def connect(self) -> None:
        """Connect to first available target with exponential backoff."""
        backoff = self.retry_delay_sec
        while True:
            for host, port in self.targets:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout_sec)
                    logger.info(f"Attempting connection to {host}:{port}")
                    s.connect((host, port))
                    s.settimeout(None)
                    self.sock = s
                    self.connected_to = (host, port)
                    logger.info(f"Connected to {host}:{port}")
                    return
                except Exception as e:
                    logger.debug(f"Failed to connect to {host}:{port}: {e}")
                    try:
                        s.close()
                    except Exception:
                        pass
                    self.sock = None
                    self.connected_to = None
            
            logger.warning(f"All targets unreachable, retrying in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 1.5, 30)  # Cap at 30s

    def send_line(self, line: bytes) -> None:
        """Send a line of data, reconnecting if necessary."""
        if not self.sock:
            self.connect()
        assert self.sock is not None
        
        try:
            self.sock.sendall(line)
            logger.debug(f"Sent {len(line)} bytes to {self.connected_to}")
        except Exception as e:
            logger.warning(f"Send failed: {e}, reconnecting...")
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected_to = None
            self.connect()
            assert self.sock is not None
            self.sock.sendall(line)

    def close(self) -> None:
        """Close the connection."""
        if self.sock:
            try:
                self.sock.close()
                logger.info("Connection closed")
            except Exception:
                pass
        self.sock = None
        self.connected_to = None