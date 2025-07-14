from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse, HttpResponse
import subprocess
import psutil
import platform
import os
import configparser
from datetime import datetime
import json
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
import re

class LogsView(LoginRequiredMixin, View):
    def get(self, request):
        # Get system logs (simplified example)
        try:
            logs = subprocess.check_output(['journalctl', '--no-pager', '-n', '100']).decode('utf-8')
        except:
            logs = "Unable to retrieve logs"
        
        # Get running processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'user': proc.info['username'],
                    'cpu': proc.info['cpu_percent'],
                    'memory': proc.info['memory_percent'],
                    'command': proc.info['name']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort by CPU usage
        processes = sorted(processes, key=lambda p: p['cpu'], reverse=True)[:50]
        
        return render(request, 'system/logs.html', {
            'system_logs': logs,
            'processes': processes
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'clear_logs':
            try:
                subprocess.run(['journalctl', '--flush'], check=True)
                subprocess.run(['journalctl', '--rotate'], check=True)
                subprocess.run(['journalctl', '--vacuum-time=1s'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'kill_process':
            pid = request.POST.get('pid')
            try:
                p = psutil.Process(int(pid))
                p.terminate()
                return JsonResponse({'success': True})
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})

class SystemInfoView(LoginRequiredMixin, View):
    def get(self, request):
        # Hardware information
        hardware = {
            'model': subprocess.getoutput('cat /sys/firmware/devicetree/base/model').strip() or 'Unknown',
            'serial': subprocess.getoutput('cat /sys/firmware/devicetree/base/serial-number').strip() or 'Unknown',
            'cpu': platform.processor(),
            'cores': psutil.cpu_count(logical=False),
            'memory': f"{round(psutil.virtual_memory().total / (1024 ** 3), 1)} GB",
            'storage': f"{round(psutil.disk_usage('/').total / (1024 ** 3), 1)} GB",
            'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
        }
        
        # Software information
        software = {
            'os': platform.system(),
            'kernel': platform.release(),
            'sdwan_version': '2.0.1',
            'last_updated': '2023-10-15',
            'license_valid': True,
            'license_expiry': '2024-10-15'
        }
        
        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        cpu_cores = [psutil.cpu_percent(interval=1, percpu=True)[i] for i in range(psutil.cpu_count())]
        
        # Memory usage
        mem = psutil.virtual_memory()
        memory_usage = mem.percent
        memory_used = round(mem.used / (1024 ** 2))
        memory_total = round(mem.total / (1024 ** 2))
        
        # Disk usage
        disks = []
        for part in psutil.disk_partitions():
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                'mount': part.mountpoint,
                'percent': usage.percent,
                'used': round(usage.used / (1024 ** 3), 1),
                'total': round(usage.total / (1024 ** 3), 1)
            })
        
        return render(request, 'system/info.html', {
            'hardware': hardware,
            'software': software,
            'cpu_usage': cpu_usage,
            'cpu_cores': cpu_cores,
            'memory_usage': memory_usage,
            'memory_used': memory_used,
            'memory_total': memory_total,
            'disks': disks
        })

@login_required
def interfaces_view(request):
    # Get network interfaces
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        interfaces = []
        
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
                
            # Parse interface information
            match = re.match(r'^\d+:\s+(\w+):\s+<(.+)>\s+mtu\s+(\d+).*', line)
            if match:
                name = match.group(1)
                flags = match.group(2)
                mtu = match.group(3)
                
                # Get interface status
                status = 'up' if 'UP' in flags else 'down'
                
                # Get interface details
                try:
                    ip_result = subprocess.run(['ip', 'addr', 'show', name], capture_output=True, text=True)
                    mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', ip_result.stdout)
                    ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
                    
                    mac_address = mac_match.group(1) if mac_match else 'N/A'
                    ip_address = ip_match.group(1) if ip_match else 'N/A'
                except:
                    mac_address = 'N/A'
                    ip_address = 'N/A'
                
                # Get interface speed and duplex
                try:
                    ethtool_result = subprocess.run(['ethtool', name], capture_output=True, text=True)
                    speed_match = re.search(r'Speed:\s+(\d+)\s+Mbps', ethtool_result.stdout)
                    duplex_match = re.search(r'Duplex:\s+(\w+)', ethtool_result.stdout)
                    
                    speed = speed_match.group(1) if speed_match else 'N/A'
                    duplex = duplex_match.group(1).lower() if duplex_match else 'N/A'
                except:
                    speed = 'N/A'
                    duplex = 'N/A'
                
                # Get VLAN information
                try:
                    vlan_result = subprocess.run(['bridge', 'vlan', 'show', name], capture_output=True, text=True)
                    vlan_match = re.search(r'PVID:\s+(\d+)', vlan_result.stdout)
                    vlan = vlan_match.group(1) if vlan_match else '1'
                except:
                    vlan = '1'
                
                interfaces.append({
                'name': name,
                    'status': status,
                    'speed': speed,
                    'duplex': duplex,
                    'mac_address': mac_address,
                    'ip_address': ip_address,
                    'mtu': mtu,
                    'vlan': vlan
            })
        
        return render(request, 'system/interfaces.html', {
            'ports': interfaces
        })
    except Exception as e:
        return render(request, 'system/interfaces.html', {
            'error': str(e),
            'ports': []
        })

@login_required
@require_http_methods(['POST'])
def toggle_port(request, port_name):
    try:
        data = json.loads(request.body)
        new_status = data.get('status')
        
        if new_status not in ['up', 'down']:
            return JsonResponse({'success': False, 'error': 'Invalid status'})
        
        # Toggle port status
        subprocess.run(['ip', 'link', 'set', port_name, new_status], check=True)
        
        return JsonResponse({'success': True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': f'Failed to toggle port: {str(e)}'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(['POST'])
def edit_port(request, port_name):
    try:
        data = json.loads(request.body)
        speed = data.get('speed')
        duplex = data.get('duplex')
        mtu = data.get('mtu')
        vlan = data.get('vlan')
        
        # Validate inputs
        if not all([speed, duplex, mtu, vlan]):
            return JsonResponse({'success': False, 'error': 'Missing required parameters'})
        
        if not mtu.isdigit() or not (68 <= int(mtu) <= 9000):
            return JsonResponse({'success': False, 'error': 'Invalid MTU value'})
        
        if not vlan.isdigit() or not (1 <= int(vlan) <= 4094):
            return JsonResponse({'success': False, 'error': 'Invalid VLAN value'})
        
        # Update MTU
        subprocess.run(['ip', 'link', 'set', port_name, 'mtu', mtu], check=True)
        
        # Update speed and duplex using ethtool
        subprocess.run(['ethtool', '-s', port_name, 'speed', speed, 'duplex', duplex], check=True)
        
        # Update VLAN
        subprocess.run(['bridge', 'vlan', 'add', 'vid', vlan, 'dev', port_name, 'pvid', 'untagged'], check=True)
        
        return JsonResponse({'success': True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': f'Failed to update port: {str(e)}'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def create_vlan(request):
    try:
        data = json.loads(request.body)
        interface = data.get("interface")
        vlan_id = data.get("vlan_id")
        if not interface or not vlan_id:
            return JsonResponse({"success": False, "error": "Missing interface or VLAN ID"})
        vlan_name = f"{interface}.{vlan_id}"
        # Create VLAN interface
        subprocess.run(["ip", "link", "add", "link", interface, "name", vlan_name, "type", "vlan", "id", str(vlan_id)], check=True)
        subprocess.run(["ip", "link", "set", vlan_name, "up"], check=True)
        return JsonResponse({"success": True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({"success": False, "error": str(e)})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

@login_required
@require_http_methods(["POST"])
def create_bridge(request):
    try:
        data = json.loads(request.body)
        bridge_name = data.get("bridge_name")
        interfaces = data.get("interfaces", [])
        if not bridge_name or not interfaces:
            return JsonResponse({"success": False, "error": "Missing bridge name or interfaces"})
        # Create bridge
        subprocess.run(["ip", "link", "add", bridge_name, "type", "bridge"], check=True)
        for iface in interfaces:
            subprocess.run(["ip", "link", "set", iface, "master", bridge_name], check=True)
        subprocess.run(["ip", "link", "set", bridge_name, "up"], check=True)
        for iface in interfaces:
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        return JsonResponse({"success": True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({"success": False, "error": str(e)})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

@login_required
@require_http_methods(["POST"])
def create_team(request):
    try:
        data = json.loads(request.body)
        team_name = data.get("team_name")
        interfaces = data.get("interfaces", [])
        mode = data.get("mode", "activebackup")
        if not team_name or not interfaces:
            return JsonResponse({"success": False, "error": "Missing team name or interfaces"})
        # Create team device
        subprocess.run(["ip", "link", "add", team_name, "type", "team"], check=True)
        subprocess.run(["ip", "link", "set", team_name, "up"], check=True)
        # Set mode (requires teamd, simplified for demo)
        # Add interfaces as team ports
        for iface in interfaces:
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            subprocess.run(["ip", "link", "set", iface, "master", team_name], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        return JsonResponse({"success": True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({"success": False, "error": str(e)})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

@login_required
@require_http_methods(["POST"])
def edit_ip(request, port_name):
    try:
        data = json.loads(request.body)
        ip_type = data.get("ip_type")
        ip_address = data.get("ip_address")
        netmask = data.get("netmask")
        gateway = data.get("gateway")
        if ip_type == "dhcp":
            # Set DHCP (using dhclient)
            subprocess.run(["dhclient", "-r", port_name], check=False)
            subprocess.run(["dhclient", port_name], check=True)
        elif ip_type in ["static", "manual"]:
            if not ip_address or not netmask:
                return JsonResponse({"success": False, "error": "Missing IP address or netmask"})
            # Remove any existing IPs
            subprocess.run(["ip", "addr", "flush", "dev", port_name], check=True)
            # Add new IP
            subprocess.run(["ip", "addr", "add", f"{ip_address}/{netmask}", "dev", port_name], check=True)
            if gateway:
                subprocess.run(["ip", "route", "add", "default", "via", gateway, "dev", port_name], check=True)
        else:
            return JsonResponse({"success": False, "error": "Invalid IP type"})
        return JsonResponse({"success": True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({"success": False, "error": str(e)})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

class ConfigurationView(LoginRequiredMixin, View):
    def get(self, request):
        config = configparser.ConfigParser()
        config_path = '/etc/sdwan/sdwan.conf'
        
        if os.path.exists(config_path):
            config.read(config_path)
        
        # Get backup files
        backup_dir = '/etc/sdwan/backups'
        backups = []
        if os.path.exists(backup_dir):
            for filename in os.listdir(backup_dir):
                if filename.endswith('.conf'):
                    path = os.path.join(backup_dir, filename)
                    backups.append({
                        'filename': filename,
                        'date': datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M'),
                        'size': f"{os.path.getsize(path) / 1024:.1f} KB"
                    })
        
        return render(request, 'system/configuration.html', {
            'config': config,
            'backups': backups
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'upload_config':
            uploaded_file = request.FILES.get('config_file')
            if uploaded_file:
                try:
                    # Save uploaded file
                    config_path = '/etc/sdwan/sdwan.conf'
                    with open(config_path, 'wb+') as destination:
                        for chunk in uploaded_file.chunks():
                            destination.write(chunk)
                    
                    # Validate config
                    config = configparser.ConfigParser()
                    config.read(config_path)
                    
                    return JsonResponse({'success': True})
                except Exception as e:
                    return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'save_config':
            section = request.POST.get('section')
            key = request.POST.get('key')
            value = request.POST.get('value')
            
            try:
                config = configparser.ConfigParser()
                config_path = '/etc/sdwan/sdwan.conf'
                config.read(config_path)
                
                if not config.has_section(section):
                    config.add_section(section)
                
                config.set(section, key, value)
                
                with open(config_path, 'w') as configfile:
                    config.write(configfile)
                
                return JsonResponse({'success': True})
            except Exception as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'reset_config':
            try:
                default_config = """
                [system]
                hostname = sdwan
                timezone = UTC
                
                [network]
                interfaces = eth0,eth1
                """
                
                with open('/etc/sdwan/sdwan.conf', 'w') as f:
                    f.write(default_config)
                
                return JsonResponse({'success': True})
            except Exception as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'backup_restore':
            filename = request.POST.get('filename')
            try:
                backup_path = os.path.join('/etc/sdwan/backups', filename)
                with open(backup_path, 'r') as src, open('/etc/sdwan/sdwan.conf', 'w') as dst:
                    dst.write(src.read())
                
                return JsonResponse({'success': True})
            except Exception as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})