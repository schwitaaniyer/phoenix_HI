from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
import subprocess
import psutil
import json
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from datetime import datetime, timedelta
from .models import Alert
import time

class DashboardView(LoginRequiredMixin, View):
    def get(self, request):
        # Get system information
        interfaces_count = len(psutil.net_if_addrs())
        
        # Simulate tunnel count (would be from actual VPN/IPSEC status)
        tunnels_count = 2
        
        # Get network throughput
        net_io = psutil.net_io_counters()
        throughput = round((net_io.bytes_sent + net_io.bytes_recv) / (1024 * 1024), 2)  # MB
        
        # Get CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        
        # Get interface status
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            status = 'up' if name.startswith(('eth', 'en', 'wan')) else 'down'
            ip = next((addr.address for addr in addrs if addr.family == 2), '')  # AF_INET
            traffic = psutil.cpu_percent() % 100  # Simulate traffic
            interfaces.append({
                'name': name,
                'status': status,
                'ip': ip,
                'traffic': traffic
            })
        
        # Simulate alerts
        alerts = [
            {
                'title': 'High CPU Usage',
                'time': '2 minutes ago',
                'message': 'CPU usage exceeded 90%',
                'source': 'System Monitor',
                'level': 'warning'
            },
            {
                'title': 'New Firmware Available',
                'time': '1 hour ago',
                'message': 'SD-WAN firmware v2.1 is available',
                'source': 'Update Service',
                'level': 'info'
            }
        ]
        
        context = {
            'interfaces_count': interfaces_count,
            'tunnels_count': tunnels_count,
            'throughput': throughput,
            'cpu_usage': cpu_usage,
            'interfaces': interfaces,
            'alerts': alerts
        }
        return render(request, 'dashboard.html', context)

@login_required
@require_http_methods(["GET"])
def get_metrics(request):
    try:
        # Get system metrics
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        memory_used = round(memory.used / (1024 * 1024 * 1024), 2)  # Convert to GB
        
        # Get uptime and last boot time
        boot_time = psutil.boot_time()
        current_time = time.time()
        uptime_seconds = int(current_time - boot_time)
        last_boot = datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')
        
        # Get network interfaces with detailed status
        interfaces = []
        interfaces_count = 0
        active_interfaces = 0
        total_bandwidth = 0
        current_bandwidth = 0
        
        # Get network I/O counters for bandwidth calculation
        net_io_start = psutil.net_io_counters()
        time.sleep(1)  # Wait for 1 second
        net_io_end = psutil.net_io_counters()
        
        # Calculate current bandwidth
        bytes_sent = net_io_end.bytes_sent - net_io_start.bytes_sent
        bytes_recv = net_io_end.bytes_recv - net_io_start.bytes_recv
        current_bandwidth = (bytes_sent + bytes_recv) * 8  # Convert to bits
        
        for name, addrs in psutil.net_if_addrs().items():
            if name.startswith(('eth', 'en', 'wan', 'wlan')):
                interfaces_count += 1
                status = 'up' if name.startswith(('eth', 'en', 'wan')) else 'down'
                if status == 'up':
                    active_interfaces += 1
                
                # Get IP address
                ip = next((addr.address for addr in addrs if addr.family == 2), '')
                
                # Get interface statistics
                try:
                    stats = psutil.net_if_stats()[name]
                    speed = stats.speed
                    mtu = stats.mtu
                    duplex = stats.duplex
                    if speed:
                        total_bandwidth += speed
                except:
                    speed = 0
                    mtu = 1500
                    duplex = 'unknown'
                
                # Get interface traffic
                try:
                    io = psutil.net_io_counters(pernic=True)[name]
                    rx_bytes = io.bytes_recv
                    tx_bytes = io.bytes_sent
                except:
                    rx_bytes = 0
                    tx_bytes = 0
                
                interfaces.append({
                    'name': name,
                    'status': status,
                    'ip': ip,
                    'speed': speed,
                    'mtu': mtu,
                    'duplex': duplex,
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes
                })
        
        # Get active tunnels with detailed status
        tunnels = []
        tunnels_count = 0
        healthy_tunnels = 0
        
        try:
            result = subprocess.run(['ip', 'tunnel', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    tunnels_count += 1
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        status = 'up' if 'up' in line.lower() else 'down'
                        if status == 'up':
                            healthy_tunnels += 1
                        
                        # Get tunnel details
                        try:
                            tunnel_info = subprocess.run(['ip', 'tunnel', 'show', name], 
                                                       capture_output=True, text=True)
                            local = next((p.split(':')[1] for p in tunnel_info.stdout.split('\n') 
                                        if 'local' in p), '')
                            remote = next((p.split(':')[1] for p in tunnel_info.stdout.split('\n') 
                                         if 'remote' in p), '')
                        except:
                            local = ''
                            remote = ''
                        
                        tunnels.append({
                            'name': name,
                            'status': status,
                            'local': local,
                            'remote': remote
                        })
        except:
            pass
        
        # Get network traffic
        net_io = psutil.net_io_counters()
        inbound_traffic = net_io.bytes_recv / 1024 / 1024  # Convert to MB
        outbound_traffic = net_io.bytes_sent / 1024 / 1024  # Convert to MB
        total_traffic = inbound_traffic + outbound_traffic
        
        # Calculate today's traffic (since midnight)
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        today_traffic = 0  # This would need to be calculated from historical data
        
        # Calculate system health
        healthy_components = 0
        warning_components = 0
        critical_components = 0
        
        # CPU health
        if cpu_usage < 70:
            healthy_components += 1
        elif cpu_usage < 90:
            warning_components += 1
        else:
            critical_components += 1
        
        # Memory health
        if memory_usage < 70:
            healthy_components += 1
        elif memory_usage < 90:
            warning_components += 1
        else:
            critical_components += 1
        
        # Network health
        if active_interfaces == interfaces_count:
            healthy_components += 1
        elif active_interfaces > interfaces_count / 2:
            warning_components += 1
        else:
            critical_components += 1
        
        # Tunnel health
        if healthy_tunnels == tunnels_count:
            healthy_components += 1
        elif healthy_tunnels > tunnels_count / 2:
            warning_components += 1
        else:
            critical_components += 1
        
        return JsonResponse({
            'interfaces_count': interfaces_count,
            'active_interfaces': active_interfaces,
            'interfaces': interfaces,
            'tunnels_count': tunnels_count,
            'healthy_tunnels': healthy_tunnels,
            'tunnels': tunnels,
            'throughput': round((inbound_traffic + outbound_traffic) / 1024, 2),  # Convert to Mbps
            'peak_throughput': round(max(inbound_traffic, outbound_traffic) / 1024, 2),
            'cpu_usage': cpu_usage,
            'cpu_load': psutil.getloadavg()[0],
            'memory_usage': memory_usage,
            'memory_used': memory_used,
            'inbound_traffic': round(inbound_traffic / 1024, 2),  # Convert to Mbps
            'outbound_traffic': round(outbound_traffic / 1024, 2),  # Convert to Mbps
            'healthy_components': healthy_components,
            'warning_components': warning_components,
            'critical_components': critical_components,
            'bandwidth': round(current_bandwidth / 1000000, 2),  # Convert to Mbps
            'total_bandwidth': round(total_bandwidth / 1000, 2),  # Convert to Gbps
            'uptime': uptime_seconds,
            'last_boot': last_boot,
            'total_traffic': total_traffic,
            'today_traffic': today_traffic
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)