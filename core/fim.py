import hashlib
import json
import os
from .logger import logger
from .config import config

class FIM:
    def __init__(self):
        self.baseline = {}
        self.load_baseline()

    def hash_file(self, filepath):
        """Calculates and returns the SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                # Read completely, for very large files chunking might be better, 
                # but chunking is standard for SHA256 anyway.
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except PermissionError:
            # Skip files we can't read natively
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.warning("File Read Error", {"File": filepath, "Error": str(e)})
            return None

    def load_baseline(self):
        """Loads the baseline hashes from the JSON file."""
        if os.path.exists(config.baseline_filepath):
            try:
                with open(config.baseline_filepath, 'r') as f:
                    self.baseline = json.load(f)
            except Exception as e:
                logger.warning("Baseline Load Error", {"Error": str(e)})
                self.baseline = {}
        else:
            self.baseline = {}

    def save_baseline(self):
        """Saves current baseline hashes to the JSON file."""
        try:
            with open(config.baseline_filepath, 'w') as f:
                json.dump(self.baseline, f, indent=4)
        except Exception as e:
            logger.warning("Baseline Save Error", {"Error": str(e)})

    def init_baseline(self):
        """Generates a new baseline across all monitored directories."""
        self.baseline.clear()
        
        count = 0
        for directory in config.monitored_directories:
            if not os.path.exists(directory):
                logger.warning("Directory Not Found", {"Directory": directory})
                continue
                
            logger.info("FIM Mapping", {"Directory": directory, "Status": "Starting walk"})
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    file_hash = self.hash_file(filepath)
                    if file_hash:
                        # Store lowercase filepath for consistent lookup across OS types
                        self.baseline[os.path.abspath(filepath).lower()] = file_hash
                        count += 1
                        
        self.save_baseline()
        logger.info("Baseline Initialization Complete", {"FilesTracked": str(count)})
        return count

    def verify_file(self, filepath, context="modification"):
        """
        Calculates hash of single file and compares with baseline.
        Returns:
            bool: True if file matches baseline or was added to baseline legitimately (ignoring events temporarily), False otherwise.
        """
        abs_path = os.path.abspath(filepath).lower()
        current_hash = self.hash_file(abs_path)
        
        if not current_hash:
            return False

        if abs_path not in self.baseline:
            # File newly created? 
            # We can flag it as violation if it wasn't there before
            alert_msg = "New file created in monitored directory!"
            logger.critical("Unauthorized File Creation", {
                "File": filepath,
                "Hash": current_hash
            }, alert_message=alert_msg)
            
            # Optionally add to baseline after alert depending on policy
            self.baseline[abs_path] = current_hash
            self.save_baseline()
            return False

        old_hash = self.baseline[abs_path]
        if current_hash != old_hash:
            alert_msg = "File integrity violation detected!"
            logger.critical(f"File {context}", {
                "File": filepath,
                "Old Hash": old_hash,
                "New Hash": current_hash
            }, alert_message=alert_msg)
            
            # Update baseline so it doesn't repeatedly trigger for one change? 
            # Usually strict FIM alerts every time until restored manually. Let's update it so watchog doesn't spam.
            self.baseline[abs_path] = current_hash
            self.save_baseline()
            return False
            
        return True

    def _mark_deleted(self, filepath):
        """Handles deletion event for FIM baseline."""
        abs_path = os.path.abspath(filepath).lower()
        if abs_path in self.baseline:
            logger.critical("Unauthorized File Deletion", {
                "File": filepath,
                "Old Hash": self.baseline[abs_path]
            }, alert_message="Monitored file was deleted!")
            
            del self.baseline[abs_path]
            self.save_baseline()

fim_engine = FIM()
