import hashlib
import json
import os

from .config import config
from .logger import logger


class FIM:
    def __init__(self):
        self.baseline = {}
        self.load_baseline()

    def hash_file(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as file_handle:
                while chunk := file_handle.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except PermissionError:
            return None
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.warning("File Read Error", {"File": filepath, "Error": str(exc)})
            return None

    def load_baseline(self):
        if os.path.exists(config.baseline_filepath):
            try:
                with open(config.baseline_filepath, "r") as file_handle:
                    self.baseline = json.load(file_handle)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Baseline Load Error", {"Error": str(exc)})
                self.baseline = {}

    def save_baseline(self):
        try:
            with open(config.baseline_filepath, "w") as file_handle:
                json.dump(self.baseline, file_handle, indent=4)
        except OSError as exc:
            logger.warning("Baseline Save Error", {"Error": str(exc)})

    def init_baseline(self):
        """Explicitly replace the trusted baseline with current file hashes."""
        self.baseline.clear()
        count = 0
        for directory in config.monitored_directories:
            if not os.path.exists(directory):
                logger.warning("Directory Not Found", {"Directory": directory})
                continue
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    file_hash = self.hash_file(filepath)
                    if file_hash:
                        self.baseline[os.path.abspath(filepath).lower()] = file_hash
                        count += 1
        self.save_baseline()
        logger.info("Baseline Initialization Complete", {"FilesTracked": str(count)})
        return count

    def verify_file(self, filepath, context="modification"):
        """Compare a file with the trusted baseline without silently accepting changes."""
        abs_path = os.path.abspath(filepath).lower()
        current_hash = self.hash_file(abs_path)
        if not current_hash:
            return False

        if abs_path not in self.baseline:
            logger.critical(
                "Unauthorized File Creation",
                {"File": filepath, "Hash": current_hash},
                alert_message="New file created in monitored directory!",
            )
            return False

        old_hash = self.baseline[abs_path]
        if current_hash != old_hash:
            logger.critical(
                f"File {context}",
                {"File": filepath, "Old Hash": old_hash, "New Hash": current_hash},
                alert_message="File integrity violation detected!",
            )
            return False
        return True

    def _mark_deleted(self, filepath):
        abs_path = os.path.abspath(filepath).lower()
        if abs_path in self.baseline:
            logger.critical(
                "Unauthorized File Deletion",
                {"File": filepath, "Old Hash": self.baseline[abs_path]},
                alert_message="Monitored file was deleted!",
            )
            # Keep the original baseline so a recreated file is still checked
            # against the trusted hash.


fim_engine = FIM()
