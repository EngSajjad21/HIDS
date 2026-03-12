import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .config import config
from .logger import logger
from .fim import fim_engine

class SecurityFileSystemEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            fim_engine.verify_file(event.src_path, context="modification")

    def on_created(self, event):
        if not event.is_directory:
            fim_engine.verify_file(event.src_path, context="creation")

    def on_deleted(self, event):
        if not event.is_directory:
            fim_engine._mark_deleted(event.src_path)

def start_fs_monitor():
    """Starts the real-time filesystem monitor using watchdog."""
    if not config.monitored_directories:
        logger.warning("No directories to monitor", {"Status": "FS Monitor Not Started"})
        return None

    observer = Observer()
    event_handler = SecurityFileSystemEventHandler()

    count = 0
    for directory in config.monitored_directories:
        if os.path.exists(directory):
            observer.schedule(event_handler, directory, recursive=True)
            count += 1
            logger.info("FS Monitor Started", {"Directory": directory})
        else:
            logger.warning("Cannot monitor path", {"Path": directory, "Reason": "Does not exist"})

    if count > 0:
        observer.start()
        return observer
    return None

def stop_fs_monitor(observer):
    if observer:
        observer.stop()
        observer.join()
        logger.info("FS Monitor Stopped", {"Status": "Success"})
