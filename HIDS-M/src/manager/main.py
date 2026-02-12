from __future__ import annotations
import threading
import logging
import os
from manager.receiver import run_receiver
from manager.gui import ManagerGUI

# Configuration
HOST = "0.0.0.0"
PORT = int(os.getenv("HIDS_MANAGER_PORT", "5055"))
DB_PATH = os.getenv("HIDS_DB_PATH", "hids_events.db")

# PSK must match agent's PSK
PSK_HEX = os.getenv(
    "HIDS_PSK",
    "8b5ffcc63494672c8f5f9ad6966832e7bcee6445e8bfa7241e22b2136174b76f"
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler("hids_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    logger.info("HIDS Manager starting...")
    logger.info(f"Listening on {HOST}:{PORT}")
    logger.info(f"Database: {DB_PATH}")
    
    # Start receiver in background thread
    t = threading.Thread(
        target=run_receiver,
        args=(HOST, PORT, PSK_HEX, DB_PATH),
        daemon=True
    )
    t.start()
    logger.info("Receiver thread started")
    
    # Start GUI
    try:
        app = ManagerGUI(DB_PATH)
        app.mainloop()
    except Exception as e:
        logger.error(f"GUI error: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()