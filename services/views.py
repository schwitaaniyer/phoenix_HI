from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django import forms
import subprocess
import os
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from .models import PacketAnalysis, SevereFlowLog, Settings
from .utils import analyze_packet
from .forms import RetentionForm
import json
import logging
import threading
import time
import netifaces
import ipaddress
import re
from datetime import datetime, timedelta

# IPSec Views
class IPsecView(LoginRequiredMixin, View):
    def get(self, request):
        # Get IPSec tunnel status
        try:
            status = subprocess.check_output(['ipsec', 'status']).decode('utf-8')
        except:
            status = "Unable to retrieve IPSec status"
        
        # Simulate tunnel list
        tunnels = [
            {
                'id': 1,
                'name': 'tunnel1',
                'status': 'up',
                'local': '192.168.1.1',
                'remote': '203.0.113.5',
                'preshared': '********',
                'ike': 'aes256-sha1-modp1024',
                'esp': 'aes256-sha1'
            },
            {
                'id': 2,
                'name': 'tunnel2',
                'status': 'down',
                'local': '192.168.1.2',
                'remote': '198.51.100.10',
                'preshared': '********',
                'ike': 'aes128-sha1-modp1024',
                'esp': 'aes128-sha1'
            }
        ]
        
        # Get IPSec logs
        try:
            logs = subprocess.check_output(['journalctl', '-u', 'ipsec', '--no-pager', '-n', '20']).decode('utf-8')
        except:
            logs = "Unable to retrieve IPSec logs"
        
        # Form for tunnel configuration
        class TunnelForm(forms.Form):
            name = forms.CharField(max_length=50)
            local = forms.GenericIPAddressField()
            remote = forms.GenericIPAddressField()
            preshared = forms.CharField(widget=forms.PasswordInput())
            ike = forms.ChoiceField(choices=[
                ('aes256-sha1-modp1024', 'aes256-sha1-modp1024'),
                ('aes128-sha1-modp1024', 'aes128-sha1-modp1024'),
                ('aes256-sha256-modp2048', 'aes256-sha256-modp2048')
            ])
            esp = forms.ChoiceField(choices=[
                ('aes256-sha1', 'aes256-sha1'),
                ('aes128-sha1', 'aes128-sha1'),
                ('aes256-sha256', 'aes256-sha256')
            ])
        
        return render(request, 'services/ipsec.html', {
            'status': status,
            'tunnels': tunnels,
            'logs': logs,
            'tunnel_form': TunnelForm()
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'start_tunnel':
            tunnel_id = request.POST.get('tunnel_id')
            try:
                subprocess.run(['ipsec', 'up', f'tunnel{tunnel_id}'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'stop_tunnel':
            tunnel_id = request.POST.get('tunnel_id')
            try:
                subprocess.run(['ipsec', 'down', f'tunnel{tunnel_id}'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'restart_ipsec':
            try:
                subprocess.run(['systemctl', 'restart', 'ipsec'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})

# VPN Views
class VPNView(LoginRequiredMixin, View):
    def get(self, request):
        # Get VPN status
        try:
            status = subprocess.check_output(['systemctl', 'status', 'openvpn']).decode('utf-8')
        except:
            status = "Unable to retrieve VPN status"
        
        # Simulate client list
        clients = [
            {
                'id': 1,
                'name': 'client1',
                'status': 'connected',
                'ip': '10.8.0.2',
                'connected': '2023-10-15 14:30:22'
            },
            {
                'id': 2,
                'name': 'client2',
                'status': 'disconnected',
                'ip': '',
                'connected': ''
            }
        ]
        
        # Form for server configuration
        class ServerForm(forms.Form):
            PROTOCOL_CHOICES = [('udp', 'UDP'), ('tcp', 'TCP')]
            CIPHER_CHOICES = [
                ('AES-256-GCM', 'AES-256-GCM'),
                ('AES-128-GCM', 'AES-128-GCM'),
                ('AES-256-CBC', 'AES-256-CBC')
            ]
            
            port = forms.IntegerField(min_value=1, max_value=65535)
            protocol = forms.ChoiceField(choices=PROTOCOL_CHOICES)
            cipher = forms.ChoiceField(choices=CIPHER_CHOICES)
            dh_bits = forms.ChoiceField(choices=[('2048', '2048'), ('3072', '3072'), ('4096', '4096')])
            compression = forms.BooleanField(required=False)
            push_dns = forms.BooleanField(required=False)
            dns_servers = forms.CharField(required=False)
        
        # Form for client configuration
        class ClientForm(forms.Form):
            name = forms.CharField(max_length=50)
            ip = forms.GenericIPAddressField()
        
        return render(request, 'services/vpn.html', {
            'status': status,
            'clients': clients,
            'server_form': ServerForm(initial={
                'port': 1194,
                'protocol': 'udp',
                'cipher': 'AES-256-GCM',
                'dh_bits': '2048',
                'compression': True,
                'push_dns': True,
                'dns_servers': '8.8.8.8,8.8.4.4'
            }),
            'client_form': ClientForm()
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'start_vpn':
            try:
                subprocess.run(['systemctl', 'start', 'openvpn'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'stop_vpn':
            try:
                subprocess.run(['systemctl', 'stop', 'openvpn'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})

# SNMP Views
class SNMPView(LoginRequiredMixin, View):
    def get(self, request):
        # Get SNMP configuration
        try:
            config = subprocess.check_output(['cat', '/etc/snmp/snmpd.conf']).decode('utf-8')
        except:
            config = "Unable to retrieve SNMP configuration"
        
        # Simulate communities
        communities = [
            {
                'id': 1,
                'name': 'public',
                'access': 'read-only',
                'source': '0.0.0.0/0'
            },
            {
                'id': 2,
                'name': 'private',
                'access': 'read-write',
                'source': '192.168.1.0/24'
            }
        ]
        
        # Simulate traps
        traps = [
            {
                'id': 1,
                'destination': '192.168.1.100',
                'community': 'public'
            }
        ]
        
        # Form for SNMP configuration
        class ConfigForm(forms.Form):
            syslocation = forms.CharField(required=False)
            syscontact = forms.CharField(required=False)
            sysservices = forms.IntegerField(required=False)
            trapcommunity = forms.CharField(required=False)
        
        # Form for community configuration
        class CommunityForm(forms.Form):
            name = forms.CharField(max_length=50)
            access = forms.ChoiceField(choices=[('read-only', 'Read Only'), ('read-write', 'Read Write')])
            source = forms.CharField()
        
        # Form for trap configuration
        class TrapForm(forms.Form):
            destination = forms.GenericIPAddressField()
            community = forms.CharField(max_length=50)
        
        return render(request, 'services/snmp.html', {
            'config': config,
            'communities': communities,
            'traps': traps,
            'config_form': ConfigForm(initial={
                'syslocation': 'Unknown',
                'syscontact': 'admin@example.com',
                'sysservices': 72,
                'trapcommunity': 'public'
            }),
            'community_form': CommunityForm(),
            'trap_form': TrapForm()
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'start_snmp':
            try:
                subprocess.run(['systemctl', 'start', 'snmpd'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'stop_snmp':
            try:
                subprocess.run(['systemctl', 'stop', 'snmpd'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})

# IPS/IDS Views
class IPSIDSView(LoginRequiredMixin, View):
    def get(self, request):
        # Get Snort status
        try:
            status = subprocess.check_output(['systemctl', 'status', 'snort']).decode('utf-8')
        except:
            status = "Unable to retrieve Snort status"
        
        # Simulate rules
        rules = [
            {
                'sid': 1000001,
                'action': 'alert',
                'protocol': 'tcp',
                'source': 'any',
                'destination': '$HOME_NET',
                'message': 'TEST rule',
                'enabled': True
            },
            {
                'sid': 1000002,
                'action': 'drop',
                'protocol': 'udp',
                'source': 'any',
                'destination': '$HOME_NET',
                'message': 'Block suspicious UDP',
                'enabled': False
            }
        ]
        
        # Simulate alerts
        alerts = [
            {
                'timestamp': '2023-10-15 14:30:22',
                'priority': 'high',
                'source': '192.168.1.100',
                'destination': '10.0.0.5',
                'message': 'Possible exploit attempt'
            }
        ]
        
        # Form for IPS configuration
        class ConfigForm(forms.Form):
            MODE_CHOICES = [('ips', 'IPS'), ('ids', 'IDS')]
            
            mode = forms.ChoiceField(choices=MODE_CHOICES)
            interface = forms.CharField()
            home_net = forms.CharField()
            detection = forms.BooleanField(required=False)
            prevention = forms.BooleanField(required=False)
        
        # Form for rule configuration
        class RuleForm(forms.Form):
            ACTION_CHOICES = [
                ('alert', 'Alert'),
                ('drop', 'Drop'),
                ('pass', 'Pass'),
                ('reject', 'Reject')
            ]
            PROTOCOL_CHOICES = [
                ('tcp', 'TCP'),
                ('udp', 'UDP'),
                ('icmp', 'ICMP'),
                ('ip', 'IP')
            ]
            
            action = forms.ChoiceField(choices=ACTION_CHOICES)
            protocol = forms.ChoiceField(choices=PROTOCOL_CHOICES)
            source = forms.CharField()
            destination = forms.CharField()
            message = forms.CharField()
        
        return render(request, 'services/ips_ids.html', {
            'status': status,
            'rules': rules,
            'alerts': alerts,
            'config_form': ConfigForm(initial={
                'mode': 'ips',
                'interface': 'eth0',
                'home_net': '192.168.1.0/24',
                'detection': True,
                'prevention': True
            }),
            'rule_form': RuleForm()
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'start_snort':
            try:
                subprocess.run(['systemctl', 'start', 'snort'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'stop_snort':
            try:
                subprocess.run(['systemctl', 'stop', 'snort'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})

# Risk Analysis Views
class RiskAnalysisView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'services/risk_analysis.html')

# Authentication Views
class AuthenticationView(LoginRequiredMixin, View):
    def get(self, request):
        # Current authentication method
        current_method = 'local'  # Would be from configuration
        
        # Simulate local users
        local_users = [
            {
                'id': 1,
                'username': 'admin',
                'role': 'administrator',
                'last_login': '2023-10-15 14:22:10'
            },
            {
                'id': 2,
                'username': 'operator',
                'role': 'operator',
                'last_login': '2023-10-14 09:15:33'
            }
        ]
        
        # Simulate auth logs
        auth_logs = [
            {
                'timestamp': '2023-10-15 14:30:22',
                'user': 'admin',
                'method': 'local',
                'status': 'success',
                'ip': '192.168.1.100'
            }
        ]
        
        # Form for authentication method
        class MethodForm(forms.Form):
            METHOD_CHOICES = [
                ('local', 'Local'),
                ('ldap', 'LDAP'),
                ('tacacs', 'TACACS+'),
                ('radius', 'RADIUS')
            ]
            
            method = forms.ChoiceField(choices=METHOD_CHOICES)
        
        # Form for LDAP configuration
        class LDAPForm(forms.Form):
            server = forms.CharField()
            port = forms.IntegerField()
            base_dn = forms.CharField()
            bind_dn = forms.CharField()
            bind_pw = forms.CharField(widget=forms.PasswordInput())
            user_filter = forms.CharField()
            group_filter = forms.CharField()
        
        # Form for TACACS+ configuration
        class TACACSForm(forms.Form):
            server = forms.CharField()
            port = forms.IntegerField()
            secret = forms.CharField(widget=forms.PasswordInput())
            timeout = forms.IntegerField()
        
        # Form for RADIUS configuration
        class RADIUSForm(forms.Form):
            server = forms.CharField()
            port = forms.IntegerField()
            secret = forms.CharField(widget=forms.PasswordInput())
            timeout = forms.IntegerField()
        
        # Form for user management
        class UserForm(forms.Form):
            ROLE_CHOICES = [
                ('administrator', 'Administrator'),
                ('operator', 'Operator'),
                ('viewer', 'Viewer')
            ]
            
            username = forms.CharField(max_length=50)
            password = forms.CharField(widget=forms.PasswordInput(), required=False)
            role = forms.ChoiceField(choices=ROLE_CHOICES)
        
        return render(request, 'services/authentication.html', {
            'current_method': current_method,
            'local_users': local_users,
            'auth_logs': auth_logs,
            'method_form': MethodForm(initial={'method': current_method}),
            'ldap_form': LDAPForm(initial={
                'port': 389,
                'timeout': 5
            }),
            'tacacs_form': TACACSForm(initial={
                'port': 49,
                'timeout': 5
            }),
            'radius_form': RADIUSForm(initial={
                'port': 1812,
                'timeout': 5
            }),
            'user_form': UserForm()
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'change_method':
            method = request.POST.get('method')
            # Save method to configuration
            return JsonResponse({'success': True})
        
        return JsonResponse({'success': False, 'error': 'Invalid action'})

# Configurable nDPI path
NDPI_READER_PATH = '/usr/bin/ndpiReader'

# Global variables for continuous capture
capture_thread = None
capture_stop_event = threading.Event()
current_file = None

# Global variables for session capture
session_capture_active = False
session_capture_start_time = None
session_captured_flows = []

def get_active_interfaces():
    try:
        active_ifaces = netifaces.interfaces()
        interfaces = [iface for iface in active_ifaces if netifaces.AF_INET in netifaces.ifaddresses(iface)]
        return interfaces
    except Exception:
        return ['ens224']

def run_capture():
    global current_file
    round_count = 1
    file1 = '/tmp/ndpi_temp1.json'
    file2 = '/tmp/ndpi_temp2.json'
    while not capture_stop_event.is_set():
        if round_count % 2 == 1:
            output_file = file1
        else:
            output_file = file2
        current_file = output_file
        cmd = ['sudo', NDPI_READER_PATH, '-i', 'ens224', '-k', output_file, '-s', '20', '-p', '/etc/ndpi/protos.txt']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception:
            pass
        round_count += 1
        time.sleep(2)

def start_capture(request):
    global capture_thread
    if request.method == 'POST':
        if capture_thread is None or not capture_thread.is_alive():
            capture_stop_event.clear()
            capture_thread = threading.Thread(target=run_capture, daemon=True)
            capture_thread.start()
            return JsonResponse({'status': 'success', 'message': 'Capture started successfully.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Capture is already running.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def stop_capture(request):
    global capture_thread
    if request.method == 'POST':
        if capture_thread and capture_thread.is_alive():
            capture_stop_event.set()
            capture_thread.join(timeout=5)
            capture_thread = None
            return JsonResponse({'status': 'success', 'message': 'Capture stopped successfully.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'No capture thread running.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def start_session_capture(request):
    global session_capture_active, session_capture_start_time, session_captured_flows
    if request.method == 'POST':
        if not session_capture_active:
            session_capture_active = True
            session_capture_start_time = datetime.now().astimezone()
            session_captured_flows = []
            return JsonResponse({'status': 'success', 'message': 'Session capture started successfully.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Session capture is already running.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def stop_session_capture(request):
    global session_capture_active, session_capture_start_time, session_captured_flows
    if request.method == 'POST':
        if session_capture_active:
            session_capture_active = False
            log_dir = '/root/Project2/logs'
            log_file = os.path.join(log_dir, 'captured.json')
            try:
                os.makedirs(log_dir, exist_ok=True)
                with open(log_file, 'w') as f:
                    json.dump(session_captured_flows, f, indent=2)
            except Exception:
                return JsonResponse({'status': 'error', 'message': 'Error saving captured flows.'})
            session_capture_start_time = None
            session_captured_flows = []
            return JsonResponse({'status': 'success', 'message': 'Session capture stopped and flows saved successfully.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'No session capture running.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def get_latest_flows(request):
    global session_captured_flows
    if request.method == 'GET':
        interface_filter = request.GET.get('interface', 'ens224')
        file1 = '/tmp/ndpi_temp1.json'
        file2 = '/tmp/ndpi_temp2.json'
        file_to_read = file2 if current_file == file1 else file1
        if not os.path.exists(file_to_read):
            return JsonResponse({'packets': []})
        try:
            with open(file_to_read, 'r') as f:
                content = f.read().strip()
                if not content:
                    return JsonResponse({'packets': []})
                try:
                    packet_data = json.loads(content)
                except json.JSONDecodeError:
                    packet_data = []
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line:
                            try:
                                packet_data.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                processed_packets = []
                if isinstance(packet_data, list):
                    for packet in packet_data:
                        try:
                            analyzed_packet = analyze_packet(packet)
                            processed_packets.append(analyzed_packet)
                        except Exception:
                            pass
                return JsonResponse({'packets': processed_packets})
        except Exception:
            return JsonResponse({'packets': []})
    return JsonResponse({'packets': []})

def risk_analysis_view(request):
    severe_alert = False
    retention_form = RetentionForm(request.POST or None)
    interfaces = get_active_interfaces()
    if request.method == 'POST' and 'retention_submit' in request.POST:
        if retention_form.is_valid():
            retention_minutes = retention_form.cleaned_data['log_retention_minutes']
            settings, _ = Settings.objects.get_or_create(id=1, defaults={'log_retention_minutes': 60})
            settings.log_retention_minutes = retention_minutes
            settings.save()
            messages.success(request, f"Log retention set to {retention_minutes} minutes.")
        else:
            messages.error(request, "Invalid retention duration.")
    if request.method == 'POST' and 'packet_file' in request.FILES:
        packet_file = request.FILES.get('packet_file')
        if packet_file:
            try:
                content = packet_file.read().decode('utf-8').strip()
                try:
                    packet_data = json.loads(content)
                except json.JSONDecodeError:
                    packet_data = []
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line:
                            try:
                                packet_data.append(json.loads(line))
                            except json.JSONDecodeError:
                                messages.warning(request, f"Skipping invalid line.")
                if not packet_data:
                    messages.error(request, 'No valid JSON data found in file.')
                    packets = PacketAnalysis.objects.all()
                    return render(request, 'services/risk_analysis.html', {
                        'packets': packets,
                        'severe_alert': severe_alert,
                        'retention_form': retention_form,
                        'capture_running': capture_thread is not None and capture_thread.is_alive(),
                        'interfaces': interfaces
                    })
                for packet in packet_data:
                    try:
                        analyzed_packet = analyze_packet(packet)
                        has_severe = any(risk['severity'] == 'SEVERE' for risk in analyzed_packet['risks'])
                        if has_severe:
                            severe_alert = True
                            SevereFlowLog.objects.create(
                                first_seen=analyzed_packet['first_seen'],
                                source_ip=analyzed_packet['source_ip'],
                                destination_ip=analyzed_packet['destination_ip'],
                                source_port=analyzed_packet['source_port'],
                                destination_port=analyzed_packet['destination_port'],
                                protocol=analyzed_packet['protocol'],
                                ndpi_protocol=analyzed_packet['ndpi_protocol'],
                                risks=analyzed_packet['risks'],
                                details=analyzed_packet['details']
                            )
                        PacketAnalysis.objects.create(
                            first_seen=analyzed_packet['first_seen'],
                            last_seen=analyzed_packet['last_seen'],
                            source_ip=analyzed_packet['source_ip'],
                            destination_ip=analyzed_packet['destination_ip'],
                            source_port=analyzed_packet['source_port'],
                            destination_port=analyzed_packet['destination_port'],
                            protocol=analyzed_packet['protocol'],
                            ndpi_protocol=analyzed_packet['ndpi_protocol'],
                            risks=analyzed_packet['risks'],
                            details=analyzed_packet['details'],
                            description=analyzed_packet['description']
                        )
                    except Exception:
                        messages.warning(request, f"Skipped packet due to error.")
                messages.success(request, 'Packets analyzed and saved successfully.')
            except Exception:
                messages.error(request, f'Error processing file.')
        else:
            messages.error(request, 'No file uploaded.')
    settings = Settings.objects.first()
    retention_minutes = settings.log_retention_minutes if settings else 60
    cutoff_time = datetime.now() - timedelta(minutes=retention_minutes)
    packets = PacketAnalysis.objects.filter(first_seen__gte=cutoff_time).order_by('-first_seen')
    severe_alert = SevereFlowLog.objects.filter(first_seen__gte=cutoff_time).exists()
    context = {
        'packets': packets,
        'severe_alert': severe_alert,
        'retention_form': retention_form,
        'capture_running': capture_thread is not None and capture_thread.is_alive(),
        'interfaces': interfaces
    }
    return render(request, 'services/risk_analysis.html', context)

def add_protocol_page(request):
    protos_file = '/etc/ndpi/protos.txt'
    protocols = []
    try:
        with open(protos_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    entry = line.split('=')[0]
                    protocols.append(entry)
    except Exception:
        protocols = []
    return render(request, 'services/add_protocol.html', {'protocols': protocols})

@csrf_exempt
def add_protocol(request):
    if request.method == 'POST':
        format_type = request.POST.get('format')
        value = request.POST.get('value')
        port = request.POST.get('port')
        protocol_name = request.POST.get('protocol_name')
        protocol_id = request.POST.get('protocol_id')
        if not format_type or not value or not protocol_name:
            return JsonResponse({'error': 'Format, value, and protocol name are required'}, status=400)
        if not re.match(r'^[a-zA-Z0-9_]{1,50}$', protocol_name):
            return JsonResponse({'error': 'Protocol name must be 1-50 alphanumeric characters or underscores'}, status=400)
        protos_file = '/etc/ndpi/protos.txt'
        try:
            with open(protos_file, 'r') as f:
                lines = f.readlines()
        except Exception:
            return JsonResponse({'error': f'protos.txt not found or permission denied'}, status=500)
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                existing_entry = line.split('=')[0]
                existing_name = existing_entry.split('@')[-1]
                if existing_name == protocol_name:
                    return JsonResponse({'error': 'A protocol with this name already exists'}, status=400)
        # (Validation and entry construction logic omitted for brevity, see full code for details)
        # ...
        return JsonResponse({'success': True, 'message': f'Protocol {protocol_name} added to protos.txt'})
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def delete_protocol(request):
    if request.method == 'POST':
        protocol_entry = request.POST.get('protocol_entry')
        if not protocol_entry:
            return JsonResponse({'error': 'Protocol entry is required'}, status=400)
        protos_file = '/etc/ndpi/protos.txt'
        try:
            with open(protos_file, 'r') as f:
                lines = f.readlines()
        except Exception:
            return JsonResponse({'error': f'protos.txt not found or permission denied'}, status=500)
        updated_lines = [line for line in lines if line.strip() != protocol_entry]
        if len(updated_lines) == len(lines):
            return JsonResponse({'error': 'Protocol not found in protos.txt'}, status=400)
        # (File write logic omitted for brevity, see full code for details)
        # ...
        return JsonResponse({'success': True, 'message': f'Protocol deleted from protos.txt'})
    return JsonResponse({'error': 'Invalid request method'}, status=405)