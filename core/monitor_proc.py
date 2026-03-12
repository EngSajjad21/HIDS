import psutil
import ipaddress
import time
from .logger import logger
from .config import config

def is_external_ip(ip_string):
    """
    Checks if an IP address is external (not loopback, private, or multicast).
    """
    try:
        ip = ipaddress.ip_address(ip_string)
        if ip.is_loopback or ip.is_private or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False
        return True
    except ValueError:
        return False

def scan_processes():
    """
    Performs a single sweep of all running processes checking for CPU usage and network connections.
    """
    # First pass to initialize CPU times
    # psutil.cpu_percent needs an interval. We can do it per process by checking 
    # proc.cpu_percent() twice with a slight delay, but checking hundreds of processes 
    # individually takes time. So wait briefly:
    
    suspicious_found = False
    
    try:
        # Get list of all processes we can read
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # We need to call it once to initialize, then again after a delay. 
                # For a quick one-shot, cpu_percent() without interval might return 0.0 or a non-blocking value 
                # based on last call. We will use what it gives, or a short `0.05` interval.
                cpu_usage = proc.cpu_percent(interval=None)
                
                # Check CPU Threshold
                if cpu_usage > config.cpu_threshold:
                    logger.warning("High CPU Process Detected", {
                        "Process": proc.info['name'],
                        "PID": proc.info['pid'],
                        "CPU": f"{cpu_usage}%"
                    })
                    suspicious_found = True

                # Check Network Connections
                # net_connections requires admin/root for all processes on some OS, but we catch AccessDenied
                try:
                    connections = proc.connections(kind='inet')
                    for conn in connections:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            remote_ip = conn.raddr.ip
                            if is_external_ip(remote_ip):
                                logger.warning("Suspicious External Connection", {
                                    "Process": proc.info['name'],
                                    "PID": proc.info['pid'],
                                    "Connected IP": f"{remote_ip}:{conn.raddr.port}"
                                })
                                suspicious_found = True
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass # Ignore if we can't inspect network connections for this process (needs higher privileges)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
    except Exception as e:
        logger.warning("Process Scan Error", {"Error": str(e)})

    return suspicious_found

def continuous_process_monitor(interval=10):
    """
    Continuously loops and scans processes every interval.
    Intended to be run in a separate thread.
    """
    logger.info("Process Monitor Started", {"Interval": f"{interval}s"})
    # Warm up cpu_percent
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except:
            pass
            
    try:
        while True:
            time.sleep(interval)
            scan_processes()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.warning("Process Monitor Crash", {"Error": str(e)})
    finally:
        logger.info("Process Monitor Stopped", {"Status": "Stopped gracefully"})
