import argparse
import sys
import time
import threading

from core.logger import logger
from core.config import config
from core.fim import fim_engine
from core.monitor_fs import start_fs_monitor, stop_fs_monitor
from core.monitor_proc import continuous_process_monitor
from colorama import Fore, Style

def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
===================================================
     PYTHON HOST-BASED INTRUSION DETECTION SYSTEM
==================================================={Style.RESET_ALL}""")

def parse_args():
    parser = argparse.ArgumentParser(description="Python Host-Based Intrusion Detection System (HIDS)")
    parser.add_argument("--init", action="store_true", help="Initialize the FIM baseline hashes for monitored directories.")
    parser.add_argument("--monitor", action="store_true", help="Start continuous real-time monitoring (FS and Processes).")
    parser.add_argument("--dirs", nargs="+", help="Add custom directories to monitor.")
    parser.add_argument("--cpu-threshold", type=float, help="Set CPU usage threshold percentage for process monitoring (default 80.0).")
    return parser.parse_args()

def main():
    banner()
    args = parse_args()

    # Apply configuration overrides
    if args.dirs:
        for d in args.dirs:
            if config.add_directory(d):
                logger.info("Custom Directory Added", {"Directory": d})
            else:
                logger.warning("Custom Directory Invalid", {"Directory": d, "Reason": "Not found or not a directory"})

    if args.cpu_threshold:
        config.cpu_threshold = args.cpu_threshold
        logger.info("CPU Threshold Updated", {"Threshold": f"{config.cpu_threshold}%"})

    if not args.init and not args.monitor:
        logger.warning("No action specified", {"Hint": "Use --init or --monitor. Use --help for options."})
        sys.exit(1)

    if args.init:
        logger.info("Starting Baseline Initialization...", {"Notice": "This may take a while depending on directory size"})
        fim_engine.init_baseline()
        logger.info("Initialization Finished", {"Baseline Size": len(fim_engine.baseline)})
        
        # If user didn't explicitly ask to monitor, we can exit here
        if not args.monitor:
            sys.exit(0)

    if args.monitor:
        logger.info("Starting HIDS Monitoring", {"OS Monitored Dirs": config.monitored_directories})
        
        if not fim_engine.baseline:
            logger.warning("Empty Baseline Detect", {"Warning": "You might want to run with --init first if FIM is needed."})

        # Start FS Monitor
        fs_observer = start_fs_monitor()

        # Start Process Monitor in a separate thread to allow main thread to handle Ctrl+C easily
        proc_thread = threading.Thread(target=continuous_process_monitor, args=(10,), daemon=True)
        proc_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print()
            logger.info("Shutting down...", {"Status": "Caught KeyboardInterrupt"})
        finally:
            if fs_observer:
                stop_fs_monitor(fs_observer)
            logger.info("HIDS Stopped", {"Status": "Clean exit"})

if __name__ == "__main__":
    main()
