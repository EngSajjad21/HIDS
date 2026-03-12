import os
import platform

def get_default_directories():
    """
    Returns default critical directories based on the operating system.
    """
    sys_platform = platform.system().lower()
    
    if sys_platform == "windows":
        # Usually C:\Windows\System32, but we'll try to find the actual system drive
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        return [os.path.join(system_root, "System32")]
    elif sys_platform in ["linux", "darwin"]:
        # Monitor critical config files/directories in Linux
        # Note: watchdog monitors directories by default, monitoring single files is tricky, 
        # but we can monitor /etc and filter inside FIM.
        return ["/etc"]
    else:
        return []

def get_critical_files_linux():
    """Specific critical files to track directly (mostly relevant for Linux)."""
    return ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]

class Config:
    def __init__(self):
        self.monitored_directories = get_default_directories()
        self.baseline_file = "baseline.json"
        self.cpu_threshold = 80.0  # Percentage
        self.db_path = "db"
        
        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path)

        self.baseline_filepath = os.path.join(self.db_path, self.baseline_file)

    def add_directory(self, path):
        if os.path.exists(path) and os.path.isdir(path):
            if path not in self.monitored_directories:
                self.monitored_directories.append(path)
                return True
        return False

# Global configuration instance
config = Config()
