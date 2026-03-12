import logging
import json
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform support
init(autoreset=True)

class HIDSLogger:
    def __init__(self, log_dir="logs", txt_filename="security_log.txt", json_filename="security_log.json", use_json=True):
        self.log_dir = log_dir
        self.txt_filename = os.path.join(log_dir, txt_filename)
        self.json_filename = os.path.join(log_dir, json_filename)
        self.use_json = use_json

        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        # Setup standard Python logging for the txt file
        self.logger = logging.getLogger("HIDS")
        self.logger.setLevel(logging.INFO)
        
        # Prevent adding handlers multiple times if instantiated multiple times
        if not self.logger.handlers:
            file_handler = logging.FileHandler(self.txt_filename)
            file_formatter = logging.Formatter("[%(levelname)s] %(message)s")
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def _log_json(self, level, event_type, details):
        if not self.use_json:
            return
            
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "event_type": event_type,
            "details": details
        }
        
        with open(self.json_filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

    def _format_txt_message(self, event_type, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details_str = " ".join([f"{k}: {v}" for k, v in details.items()])
        return f"{event_type} {details_str} Time: {timestamp}"

    def info(self, event_type, details):
        """Log informational messages (e.g., system startup, baseline creation)."""
        msg = self._format_txt_message(event_type, details)
        self.logger.info(msg)
        self._log_json("INFO", event_type, details)
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {msg}")

    def warning(self, event_type, details):
        """Log warnings (e.g., suspicious processes)."""
        msg = self._format_txt_message(event_type, details)
        self.logger.warning(msg)
        self._log_json("WARNING", event_type, details)
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")

    def critical(self, event_type, details, alert_message=None):
        """Log critical security alerts (e.g., file integrity violation)."""
        msg = self._format_txt_message(event_type, details)
        self.logger.critical(msg)
        self._log_json("CRITICAL", event_type, details)
        
        if alert_message:
            print(f"{Fore.RED}{Style.BRIGHT}[CRITICAL] {alert_message}{Style.RESET_ALL}")
        print(f"{Fore.RED}[ALERT]{Style.RESET_ALL} {msg}")

# Global instance for easy access across modules
logger = HIDSLogger()
