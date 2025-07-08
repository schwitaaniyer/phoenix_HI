import json
import os
import time
import subprocess
from collections import defaultdict

# Thresholds (realistic to avoid excessive flags)
THRESHOLDS = {
    "err_in": 5,           # Network errors per interval
    "drop_in": 2,          # Dropped packets per interval
    "bytes_total_rate": 500000,  # 500KB/s
    "mem_used_percent": 0, # Warn at 80% memory usage
    "disk_used_percent": 1, # Warn at 90% disk usage
    "cpu_usage_system": 0, # Warn at 70% system CPU
    "proc_cpu_usage": 2,   # Warn if a process uses >20% CPU
    "proc_memory_rss": 1,  # Warn if a process uses >10% memory
    "load_average_5min": 2.0,  # Warn if 5-min load exceeds 2.0
    "swap_used_percent": 5,   # Warn if swap is >50% used
}

# Device-specific settings for AH-DEBIAN
TOTAL_MEMORY_MB = 15958  # 16GB
DHCP_CHECK_SECONDS = 10  # Seconds to check for DHCP packets
METRICS_FILE = "/var/log/telegraf/telegraf_metrics.json"
BACKUP_IP = "221.171.86.1"

# Dynamically detect Ethernet interfaces
def get_ethernet_interfaces():
    """Return a list of Ethernet interfaces, excluding virtual/tunnel/loopback."""
    interfaces = []
    for iface in os.listdir("/sys/class/net"):
        try:
            with open(f"/sys/class/net/{iface}/type", "r") as f:
                iface_type = int(f.read().strip())
            if iface_type == 1 and iface not in ["lo", "dummy0"]:
                interfaces.append(iface)
        except (FileNotFoundError, ValueError):
            continue
    return sorted(interfaces)

INTERFACES = get_ethernet_interfaces()

# Track state
flags_raised = set()
prev_data = {}
last_processed_time = 0
violation_counts = defaultdict(int)  # Tracks consecutive breaches

def raise_flag(metric, condition, message, reason="Unknown", persistence_key=None, action=None):
    """Flag issues after 5 consecutive breaches, log without action."""
    if not condition:
        if persistence_key in violation_counts:
            del violation_counts[persistence_key]  # Reset if cleared
        return False
    
    if persistence_key:
        violation_counts[persistence_key] += 1
        if violation_counts[persistence_key] < 5:  # Wait for 5 breaches
            return False
        elif message not in flags_raised:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] FLAG: {message}")
            print(f"[{timestamp}] REASON: {reason}")
            if action:
                print(f"[{timestamp}] ACTION: {action}")
            flags_raised.add(message)
            return True
    return False

def get_interval(name):
    """Intervals matching telegraf.conf (seconds)."""
    return {
        "cpu": 120, "net": 120, "mem": 120, "disk": 3600, "system": 600, "procstat": 120, "file_monitor": 30
    }.get(name, 120)

def get_ip_status(interface):
    """Check IPv4/IPv6 addresses."""
    output = subprocess.getoutput(f"ip addr show {interface}")
    ipv4 = "None"
    ipv6 = "None"
    if "inet " in output:
        ipv4 = "Assigned"
    if "inet6 " in output:
        if "fe80::" in output:
            ipv6 = "Link-local"
        else:
            ipv6 = "Global"
    return ipv4, ipv6

def check_link_status(interface):
    """Check physical link (cable connected)."""
    try:
        output = subprocess.getoutput(f"ethtool {interface}")
        return "Link detected: yes" in output
    except:
        return False

def check_dhcp_activity(interface):
    """Check for DHCP requests (sign of IP assignment issues)."""
    try:
        cmd = f"timeout {DHCP_CHECK_SECONDS} tcpdump -i {interface} -n udp port 68 -c 1 2>/dev/null"
        output = subprocess.getoutput(cmd)
        return "BOOTP/DHCP" in output
    except:
        return False

def get_top_process_by_cpu():
    """Identify process using most CPU."""
    try:
        result = subprocess.run("ps aux --sort=-%cpu | head -n 2 | tail -n 1", shell=True, capture_output=True, text=True)
        parts = result.stdout.split()
        return f"Process '{parts[10]}' (PID: {parts[1]}, CPU: {parts[2]}%)"
    except Exception:
        return "Unable to identify process"

def get_top_process_by_memory():
    """Identify process using most memory."""
    try:
        result = subprocess.run("ps aux --sort=-%mem | head -n 2 | tail -n 1", shell=True, capture_output=True, text=True)
        parts = result.stdout.split()
        return f"Process '{parts[10]}' (PID: {parts[1]}, Memory: {parts[3]}%)"
    except Exception:
        return "Unable to identify process"

def get_network_drop_reason(iface):
    """Determine reason for network drops or errors."""
    try:
        result = subprocess.run(f"ip -s link show {iface}", shell=True, capture_output=True, text=True)
        if "DOWN" in result.stdout:
            return f"Interface {iface} is DOWN"
        elif "errors" in result.stdout.lower():
            return f"Interface {iface} has errors"
        return "Possible congestion or hardware issue"
    except Exception:
        return "Unable to determine network issue"

def get_disk_usage_reason(path):
    """Find largest disk consumer."""
    try:
        result = subprocess.run(f"du -h {path}/* 2>/dev/null | sort -hr | head -n 1", shell=True, capture_output=True, text=True)
        return f"Largest consumer: {result.stdout.strip()}"
    except Exception:
        return "Unable to identify disk usage culprit"

def get_system_load():
    """Get 5-minute load average."""
    try:
        with open("/proc/loadavg", "r") as f:
            return float(f.read().split()[1])
    except:
        return 0.0

def get_swap_usage():
    """Get swap usage percentage."""
    try:
        result = subprocess.run("free | grep Swap", shell=True, capture_output=True, text=True)
        total, used, _ = map(int, result.stdout.split()[1:4])
        if total == 0:
            return 0.0
        return (used / total) * 100
    except:
        return 0.0

def get_process_details(pid):
    """Get details of a process by PID."""
    try:
        result = subprocess.run(f"ps -p {pid} -o comm=,pid=,pcpu=,pmem=", shell=True, capture_output=True, text=True)
        return result.stdout.strip() or f"PID {pid} not found"
    except Exception:
        return f"Unable to get details for PID {pid}"

def log_all_metrics():
    """Log all metrics with placeholders if Telegraf data is missing."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    for iface in INTERFACES:
        ipv4_status, ipv6_status = get_ip_status(iface)
        link_status = check_link_status(iface)
        dhcp_active = check_dhcp_activity(iface)
        bytes_total = prev_data.get(f"{iface}_bytes", 0)
        print(f"[{timestamp}] INFO: NET: {iface} - RX+TX: {bytes_total} bytes, Errors: N/A, Drops: N/A, IPv4: {ipv4_status}, IPv6: {ipv6_status}, Link: {'Up' if link_status else 'Down'}, Severity: normal")
        if dhcp_active:
            print(f"[{timestamp}] INFO: {iface} - DHCP requests detected, possible IP assignment issue")
            raise_flag("net", True,
                       f"{iface} - No IPv4 Address, DHCP Failing",
                       "DHCP server not responding",
                       f"net_{iface}_no_ipv4_dhcp",
                       f"Verify DHCP server or set static IP with 'sudo ip addr add 221.171.100.68/24 dev {iface}'")

    swap_percent = get_swap_usage()
    load_avg = get_system_load()
    print(f"[{timestamp}] INFO: MEM: Used: N/A%, Swap: {swap_percent:.1f}%, Severity: normal")
    print(f"[{timestamp}] INFO: CPU: System Usage: N/A%, Load Average (5min): {load_avg:.2f}, Severity: normal")
    print(f"[{timestamp}] INFO: DISK: / - Used: N/A%, Severity: normal")
    print(f"[{timestamp}] INFO: PROC: No process data available")
    print(f"[{timestamp}] INFO: FILE: /var/log/threshold.log - Value: N/A")

while True:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] INFO: Scanning at {timestamp}")
    if not INTERFACES:
        print(f"[{timestamp}] ERROR: No Ethernet interfaces detected")
        time.sleep(120)
        INTERFACES = get_ethernet_interfaces()
        continue

    try:
        if not os.path.exists(METRICS_FILE):
            print(f"[{timestamp}] ERROR: Metrics file {METRICS_FILE} not found")
            log_all_metrics()
            time.sleep(120)
            continue

        with open(METRICS_FILE, "r") as f:
            lines = f.readlines()
            if not lines:
                print(f"[{timestamp}] WARNING: Metrics file {METRICS_FILE} is empty")
                log_all_metrics()
                time.sleep(120)
                continue

            metrics_processed = False
            for line in lines:
                try:
                    data = json.loads(line.strip())
                    name = data.get("name")
                    tags = data.get("tags", {})
                    fields = data.get("fields", {})
                    timestamp = data.get("timestamp", 0)
                    severity = tags.get("severity", "normal")

                    if timestamp <= last_processed_time:
                        continue

                    metrics_processed = True
                    log_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                    # Network Monitoring
                    if name == "net" and "interface" in tags and tags["interface"] in INTERFACES:
                        iface = tags["interface"]
                        bytes_total = fields.get("bytes_recv", 0) + fields.get("bytes_sent", 0)
                        err_in = fields.get("err_in", 0)
                        drop_in = fields.get("drop_in", 0)
                        packets_recv = fields.get("packets_recv", 0)
                        ipv4_status, ipv6_status = get_ip_status(iface)
                        link_status = check_link_status(iface)
                        dhcp_active = check_dhcp_activity(iface)

                        print(f"[{log_timestamp}] INFO: NET: {iface} - RX+TX: {bytes_total} bytes, Errors: {err_in}, Drops: {drop_in}, IPv4: {ipv4_status}, IPv6: {ipv6_status}, Link: {'Up' if link_status else 'Down'}, Severity: {severity}")
                        if dhcp_active:
                            print(f"[{log_timestamp}] INFO: {iface} - DHCP requests detected, possible IP assignment issue")

                        key = f"{iface}_bytes"
                        interval = get_interval(name)
                        if key in prev_data:
                            rate = (bytes_total - prev_data[key]) / interval
                            raise_flag("net", rate > THRESHOLDS["bytes_total_rate"],
                                       f"{iface} - High Traffic (Rate: {rate:.2f} B/s)",
                                       "Excessive data transfer detected",
                                       f"net_{iface}_bytes_total_rate",
                                       f"Run 'iftop -i {iface}' to identify traffic source")
                        prev_data[key] = bytes_total

                        raise_flag("net", err_in > THRESHOLDS["err_in"],
                                   f"{iface} - High Errors (Errors: {err_in})",
                                   get_network_drop_reason(iface),
                                   f"net_{iface}_err_in",
                                   f"Reset interface with 'sudo ip link set {iface} down && sudo ip link set {iface} up'")

                        raise_flag("net", drop_in > THRESHOLDS["drop_in"],
                                   f"{iface} - Possible Link Down (Drops: {drop_in})",
                                   get_network_drop_reason(iface),
                                   f"net_{iface}_drop_in",
                                   f"Switch to backup IP with 'sudo ip route add default via {BACKUP_IP} dev {iface}'")

                        raise_flag("net", packets_recv == 0 and link_status,
                                   f"{iface} - No Traffic",
                                   get_network_drop_reason(iface),
                                   f"net_{iface}_no_traffic",
                                   f"Reset interface with 'sudo ip link set {iface} down && sudo ip link set {iface} up'")

                        if ipv4_status == "None" and dhcp_active:
                            raise_flag("net", True,
                                       f"{iface} - No IPv4 Address, DHCP Failing",
                                       "DHCP server not responding",
                                       f"net_{iface}_no_ipv4_dhcp",
                                       f"Verify DHCP server or set static IP with 'sudo ip addr add 221.171.100.68/24 dev {iface}'")

                        if severity in ["warning", "critical"]:
                            raise_flag("net", True,
                                       f"{iface} - Network Issue (Severity: {severity})",
                                       "High network usage detected by Telegraf",
                                       f"net_{iface}_severity_{severity}",
                                       f"Check 'iftop -i {iface}' or network configuration")

                    # Memory Monitoring
                    elif name == "mem":
                        used_percent = fields.get("used_percent", 0)
                        swap_percent = get_swap_usage()
                        print(f"[{log_timestamp}] INFO: MEM: Used: {used_percent:.1f}%, Swap: {swap_percent:.1f}%, Severity: {severity}")
                        raise_flag("mem", used_percent > THRESHOLDS["mem_used_percent"],
                                   f"High Memory Usage ({used_percent:.1f}%)",
                                   get_top_process_by_memory(),
                                   "mem_used_percent",
                                   "Check 'free -m' and clear caches with 'sudo echo 3 > /proc/sys/vm/drop_caches'")
                        raise_flag("mem", swap_percent > THRESHOLDS["swap_used_percent"],
                                   f"High Swap Usage ({swap_percent:.1f}%)",
                                   "System is using too much swap memory",
                                   "mem_swap_percent",
                                   "Check processes with 'ps aux --sort=-%mem' or add more RAM")
                        if severity in ["warning", "critical"]:
                            raise_flag("mem", True,
                                       f"Memory Issue (Severity: {severity})",
                                       "High memory usage detected by Telegraf",
                                       f"mem_severity_{severity}",
                                       f"Check 'free -m' or top processes")

                    # Disk Monitoring
                    elif name == "disk":
                        used_percent = fields.get("used_percent", 0)
                        path = tags.get("path", "unknown")
                        print(f"[{log_timestamp}] INFO: DISK: {path} - Used: {used_percent:.1f}%, Severity: {severity}")
                        raise_flag("disk", used_percent > THRESHOLDS["disk_used_percent"],
                                   f"{path} - High Storage Usage ({used_percent:.1f}%)",
                                   get_disk_usage_reason(path),
                                   f"disk_{path}_used_percent",
                                   "Clear old logs with 'sudo find /var/log -type f -name \"*.log\" -mtime +30 -delete'")
                        if severity in ["warning", "critical"]:
                            raise_flag("disk", True,
                                       f"{path} - Disk Issue (Severity: {severity})",
                                       "High disk usage detected by Telegraf",
                                       f"disk_{path}_severity_{severity}",
                                       f"Check disk usage with 'df -h'")

                    # CPU Monitoring
                    elif name == "cpu":
                        usage_system = fields.get("usage_system", 0)
                        load_avg = get_system_load()
                        print(f"[{log_timestamp}] INFO: CPU: System Usage: {usage_system:.1f}%, Load Average (5min): {load_avg:.2f}, Severity: {severity}")
                        raise_flag("cpu", usage_system > THRESHOLDS["cpu_usage_system"],
                                   f"High CPU Usage ({usage_system:.1f}%)",
                                   get_top_process_by_cpu(),
                                   "cpu_usage_system",
                                   "Check processes with 'ps aux --sort=-%cpu'")
                        raise_flag("cpu", load_avg > THRESHOLDS["load_average_5min"],
                                   f"High System Load (5min: {load_avg:.2f})",
                                   "Too many tasks running",
                                   "cpu_load_average",
                                   "Check processes with 'top' or 'htop'")
                        if severity in ["warning", "critical"]:
                            raise_flag("cpu", True,
                                       f"CPU Issue (Severity: {severity})",
                                       "High CPU usage detected by Telegraf",
                                       f"cpu_severity_{severity}",
                                       f"Check processes with 'top'")

                    # Process Monitoring
                    elif name == "procstat":
                        pid = tags.get("pid", "unknown")
                        cpu_usage = fields.get("cpu_usage", 0)
                        memory_rss = fields.get("memory_rss", 0) / 1024 / 1024  # Bytes to MB
                        memory_percent = (memory_rss / TOTAL_MEMORY_MB) * 100
                        proc_details = get_process_details(pid)
                        print(f"[{log_timestamp}] INFO: PROC: PID {pid} - CPU: {cpu_usage:.1f}%, Memory: {memory_percent:.1f}% ({proc_details})")
                        raise_flag("procstat", cpu_usage > THRESHOLDS["proc_cpu_usage"],
                                   f"High CPU Process (PID {pid}, CPU: {cpu_usage:.1f}%)",
                                   proc_details,
                                   f"procstat_{pid}_cpu_usage",
                                   f"Investigate PID {pid} with 'ps -p {pid} -o comm=,pid=,pcpu=,pmem='")
                        raise_flag("procstat", memory_percent > THRESHOLDS["proc_memory_rss"],
                                   f"High Memory Process (PID {pid}, Memory: {memory_percent:.1f}%)",
                                   proc_details,
                                   f"procstat_{pid}_memory_rss",
                                   f"Investigate PID {pid} with 'ps -p {pid} -o comm=,pid=,pcpu=,pmem='")

                    # File Monitor
                    elif name == "file_monitor":
                        value = fields.get("value", 0)
                        print(f"[{log_timestamp}] INFO: FILE: /var/log/threshold.log - Value: {value}")
                        raise_flag("file_monitor", value > 0,
                                   f"Threshold Log Alert (Value: {value})",
                                   "Issue detected in threshold.log",
                                   "file_monitor_value",
                                   "Check contents of /var/log/threshold.log")

                    last_processed_time = max(last_processed_time, timestamp)

                except json.JSONDecodeError:
                    print(f"[{log_timestamp}] WARNING: Skipping invalid JSON line: {line.strip()}")
                    continue

            if not metrics_processed:
                print(f"[{log_timestamp}] WARNING: No new metrics processed in this cycle")
                log_all_metrics()

    except FileNotFoundError:
        print(f"[{timestamp}] ERROR: Metrics file {METRICS_FILE} not found")
        log_all_metrics()
    except Exception as e:
        print(f"[{timestamp}] ERROR: Unexpected issue - {str(e)}")
        log_all_metrics()

    time.sleep(120)  # Match 2m interval