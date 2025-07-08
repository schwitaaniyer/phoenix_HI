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
import secrets
import shutil

# IPSec Views
def read_swanctl_conf():
    with open('/etc/swanctl/swanctl.conf', 'r') as file:
        return file.read()

def write_swanctl_conf(content):
    with open('/etc/swanctl/swanctl.conf', 'w') as file:
        file.write(content)

def parse_swanctl_conf():
    conf = read_swanctl_conf()
    connections = []
    connection = {}
    in_connection = False
    connection_name = ""
    
    for line in conf.splitlines():
        line = line.strip()
        
        if line.startswith('connections'):
            continue
        
        elif line.endswith('{') and not in_connection:
            in_connection = True
            connection_name = line.split()[0]
            connection = {'name': connection_name, 'local_address': '', 'remote_address': '', 'status': 'inactive'}
        
        elif line == '}' and in_connection:
            in_connection = False
            connections.append(connection)
            connection = {}
        
        elif '=' in line and in_connection:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            if key == 'local_addrs':
                connection['local_address'] = value
            elif key == 'remote_addrs':
                connection['remote_address'] = value
    
    return connections

def format_proposals(encryption_algorithm, key_length, hash_algo, dh_group):
    return f'{encryption_algorithm.lower()}-{hash_algo.lower()}-{dh_group.lower()}'

class TunnelForm(forms.Form):
    name = forms.CharField(max_length=50)
    local = forms.GenericIPAddressField(label='Local Address')
    remote = forms.GenericIPAddressField(label='Remote Address')
    ike_version = forms.ChoiceField(
        choices=[('ikev1', 'IKEv1'), ('ikev2', 'IKEv2'), ('ikev1,ikev2', 'Both')],
        initial='ikev2'
    )
    authentication_method = forms.ChoiceField(
        choices=[('Mutual PSK', 'Mutual PSK'), ('Mutual Certificate', 'Mutual Certificate')],
        initial='Mutual PSK'
    )
    preshared = forms.CharField(widget=forms.PasswordInput(), label='Pre-shared Key')
    encryption_algorithm = forms.ChoiceField(
        choices=[
            ('aes256', 'AES-256'),
            ('aes128', 'AES-128'),
            ('3des', '3DES')
        ]
    )
    key_length = forms.ChoiceField(
        choices=[
            ('128', '128 bits'),
            ('192', '192 bits'),
            ('256', '256 bits')
        ]
    )
    hash_algo = forms.ChoiceField(
        choices=[
            ('sha1', 'SHA1'),
            ('sha256', 'SHA256'),
            ('sha384', 'SHA384'),
            ('sha512', 'SHA512'),
            ('md5', 'MD5')
        ],
        label='Hash Algorithm'
    )
    dh_group = forms.ChoiceField(
        choices=[
            ('modp1024', 'Group 2 (1024 bit)'),
            ('modp1536', 'Group 5 (1536 bit)'),
            ('modp2048', 'Group 14 (2048 bit)'),
            ('modp3072', 'Group 15 (3072 bit)'),
            ('modp4096', 'Group 16 (4096 bit)')
        ],
        label='DH Group'
    )
    local_ts = forms.CharField(
        label='Local Traffic Selector',
        initial='0.0.0.0/0',
        help_text='Format: network/netmask (e.g. 192.168.1.0/24)'
    )
    remote_ts = forms.CharField(
        label='Remote Traffic Selector',
        initial='0.0.0.0/0',
        help_text='Format: network/netmask (e.g. 192.168.1.0/24)'
    )

class IPsecView(LoginRequiredMixin, View):
    def get(self, request):
        try:
            status = subprocess.check_output(['swanctl', '--list-sas']).decode('utf-8')
        except:
            status = "Unable to retrieve IPSec status"
        
        try:
            service_status = subprocess.check_output(['systemctl', 'is-active', 'strongswan']).decode().strip()
        except:
            service_status = 'inactive'

        connections = parse_swanctl_conf()
        
        # Get IPSec logs
        try:
            logs = []
            with open('/var/log/ipsec.log', 'r') as f:
                for line in f.readlines()[-20:]:  # Last 20 lines
                    parts = line.split(' ', 2)
                    if len(parts) >= 2:
                        logs.append({
                            'timestamp': f"{parts[0]} {parts[1]}",
                            'message': parts[2] if len(parts) > 2 else ''
                        })
        except:
            logs = []
        
        return render(request, 'services/ipsec.html', {
            'status': status,
            'service_status': service_status,
            'tunnels': connections,
            'logs': logs,
            'tunnel_form': TunnelForm()
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'start_tunnel':
            tunnel_id = request.POST.get('tunnel_id')
            try:
                subprocess.run(['swanctl', '--initiate', f'--child={tunnel_id}'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'stop_tunnel':
            tunnel_id = request.POST.get('tunnel_id')
            try:
                subprocess.run(['swanctl', '--terminate', f'--child={tunnel_id}'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'restart_ipsec':
            try:
                subprocess.run(['systemctl', 'restart', 'strongswan'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'reload_ipsec':
            try:
                subprocess.run(['swanctl', '--load-all'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        elif action == 'stop_ipsec':
            try:
                subprocess.run(['systemctl', 'stop', 'strongswan'], check=True)
                return JsonResponse({'success': True})
            except subprocess.CalledProcessError as e:
                return JsonResponse({'success': False, 'error': str(e)})

        form = TunnelForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            local_address = form.cleaned_data['local']
            remote_address = form.cleaned_data['remote']
            encryption_algorithm = form.cleaned_data['encryption_algorithm']
            key_length = form.cleaned_data['key_length']
            hash_algo = form.cleaned_data['hash_algo']
            dh_group = form.cleaned_data['dh_group']
            ike_version = form.cleaned_data['ike_version']
            authentication_method = form.cleaned_data['authentication_method']
            psk = form.cleaned_data['preshared']
            local_ts = form.cleaned_data['local_ts']
            remote_ts = form.cleaned_data['remote_ts']

            version = '1' if ike_version == 'ikev1' else '2'
            proposals = format_proposals(encryption_algorithm, key_length, hash_algo, dh_group)

            conf = read_swanctl_conf()
            new_conf_lines = []
            in_connection = False
            for line in conf.splitlines():
                if line.strip().startswith(f'{name} {{'):
                    in_connection = True
                if not in_connection:
                    new_conf_lines.append(line)
                if in_connection and line.strip() == '}':
                    in_connection = False

            new_connection = f"""
{name} {{
    version = {version}
    local_addrs = {local_address}
    remote_addrs = {remote_address}
    local_port = 4500
    remote_port = 4500
    proposals = {proposals}
    keyingtries = 0
    dpd_delay = 30s
    local {{
        auth = psk
        id = {local_address}
    }}
    remote {{
        auth = psk
        id = {remote_address}
    }}
    children {{
        vpn {{
            mode = tunnel
            local_ts = {local_ts}
            remote_ts = {remote_ts}
            dpd_action = start
            start_action = start
            esp_proposals = {proposals}
        }}
    }}
}}
secrets {{
    ike-1 {{
        id-1 = {local_address}
        id-2 = {remote_address}
        secret = {psk}
    }}
}}"""
            new_conf_lines.append(new_connection.strip())
            write_swanctl_conf('\n'.join(new_conf_lines).strip())

            subprocess.run(['swanctl', '--load-all'])
            messages.success(request, 'Tunnel configuration saved successfully.')
            return redirect('services:ipsec')

        return JsonResponse({'success': False, 'error': 'Invalid form data'})

def generate_psk(request):
    psk = secrets.token_hex(16)
    return JsonResponse({'psk': psk})

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
SNORT_CONF_FILE = '/etc/snort/snort.conf'

# Helper functions for Snort config management

def read_snort_config():
    config = {'HOME_NET': '', 'EXTERNAL_NET': ''}
    try:
        with open(SNORT_CONF_FILE, 'r') as f:
            for line in f:
                if line.startswith('var HOME_NET'):
                    config['HOME_NET'] = line.split('HOME_NET')[1].strip().lstrip('"').rstrip('"')
                elif line.startswith('var EXTERNAL_NET'):
                    config['EXTERNAL_NET'] = line.split('EXTERNAL_NET')[1].strip().lstrip('"').rstrip('"')
        return config
    except Exception:
        return config

def update_snort_config(home_net, external_net):
    try:
        lines = []
        with open(SNORT_CONF_FILE, 'r') as f:
            for line in f:
                if line.startswith('var HOME_NET'):
                    lines.append(f'var HOME_NET {home_net}\n')
                elif line.startswith('var EXTERNAL_NET'):
                    lines.append(f'var EXTERNAL_NET {external_net}\n')
                else:
                    lines.append(line)
        with open(SNORT_CONF_FILE, 'w') as f:
            f.writelines(lines)
        return True
    except Exception:
        return False

def restart_snort():
    try:
        subprocess.run(['systemctl', 'restart', 'snort'], check=True)
        return True
    except Exception:
        return False

class IPSIDSView(LoginRequiredMixin, View):
    def get(self, request):
        # Get Snort status
        try:
            status = subprocess.check_output(['systemctl', 'status', 'snort']).decode('utf-8')
        except:
            status = "Unable to retrieve Snort status"

        # Get real rules and alerts
        rules = read_snort_rules()
        alerts = parse_snort_alerts()
        config = read_snort_config()

        # Form for IPS configuration
        class ConfigForm(forms.Form):
            MODE_CHOICES = [('ips', 'IPS'), ('ids', 'IDS')]
            mode = forms.ChoiceField(choices=MODE_CHOICES)
            interface = forms.CharField()
            home_net = forms.CharField()
            external_net = forms.CharField()
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
                'home_net': config.get('HOME_NET', '192.168.1.0/24'),
                'external_net': config.get('EXTERNAL_NET', 'any'),
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
        elif action == 'save_config':
            home_net = request.POST.get('home_net')
            external_net = request.POST.get('external_net')
            if home_net and external_net:
                success = update_snort_config(home_net, external_net)
                if success:
                    restart_snort()
                    return JsonResponse({'success': True})
                else:
                    return JsonResponse({'success': False, 'error': 'Failed to update config'})
            else:
                return JsonResponse({'success': False, 'error': 'Missing config values'})
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

SNORT_RULES_FILE = '/etc/snort/rules/local.rules'

# Helper functions for Snort rule management

def read_snort_rules():
    rules = []
    try:
        with open(SNORT_RULES_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse rule (very basic, can be improved)
                    parts = line.split(' ', 6)
                    if len(parts) >= 6:
                        action, proto, src, src_port, direction, dst, rest = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                        sid = None
                        msg = ''
                        enabled = not line.startswith('#')
                        # Extract sid and msg from options
                        if 'sid:' in rest:
                            try:
                                sid = int(rest.split('sid:')[1].split(';')[0].strip())
                            except Exception:
                                sid = None
                        if 'msg:"' in rest:
                            try:
                                msg = rest.split('msg:"')[1].split('";')[0]
                            except Exception:
                                msg = ''
                        rules.append({
                            'sid': sid,
                            'action': action,
                            'protocol': proto,
                            'source': src,
                            'source_port': src_port,
                            'direction': direction,
                            'destination': dst,
                            'raw': line,
                            'message': msg,
                            'enabled': enabled
                        })
        return rules
    except Exception as e:
        return []

def write_snort_rules(rules):
    try:
        with open(SNORT_RULES_FILE, 'w') as f:
            for rule in rules:
                f.write(rule['raw'] + '\n')
        return True
    except Exception as e:
        return False

def add_snort_rule(rule_text):
    try:
        with open(SNORT_RULES_FILE, 'a') as f:
            f.write(rule_text + '\n')
        return True
    except Exception as e:
        return False

def delete_snort_rule(sid):
    rules = read_snort_rules()
    new_rules = [r for r in rules if r['sid'] != sid]
    return write_snort_rules(new_rules)

def update_snort_rule(sid, new_rule_text):
    rules = read_snort_rules()
    updated = False
    for i, r in enumerate(rules):
        if r['sid'] == sid:
            rules[i]['raw'] = new_rule_text
            updated = True
    if updated:
        return write_snort_rules(rules)
    return False

# API endpoints for rule management
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator

@method_decorator(csrf_exempt, name='dispatch')
class SnortRuleAPI(View):
    def get(self, request):
        # List rules
        rules = read_snort_rules()
        return JsonResponse({'rules': rules})

    def post(self, request):
        # Add rule
        data = json.loads(request.body.decode('utf-8'))
        rule_text = data.get('rule_text')
        if not rule_text:
            return JsonResponse({'success': False, 'error': 'No rule text provided'})
        success = add_snort_rule(rule_text)
        return JsonResponse({'success': success})

    def put(self, request):
        # Edit rule
        data = json.loads(request.body.decode('utf-8'))
        sid = data.get('sid')
        rule_text = data.get('rule_text')
        if not sid or not rule_text:
            return JsonResponse({'success': False, 'error': 'SID and rule text required'})
        success = update_snort_rule(sid, rule_text)
        return JsonResponse({'success': success})

    def delete(self, request):
        # Delete rule
        data = json.loads(request.body.decode('utf-8'))
        sid = data.get('sid')
        if not sid:
            return JsonResponse({'success': False, 'error': 'SID required'})
        success = delete_snort_rule(sid)
        return JsonResponse({'success': success})

SNORT_ALERT_LOG = '/var/log/snort/alert'

def parse_snort_alerts():
    alerts = []
    try:
        with open(SNORT_ALERT_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Example Snort alert log line parsing (unified2 or fast format)
                # This is a simple parser for the 'fast' format
                # [**] [1:1000001:0] TEST rule [**] [Priority: 1] 10/15-14:30:22.123456 192.168.1.100 -> 10.0.0.5
                if line.startswith('[**]'):
                    try:
                        parts = line.split(']')
                        msg = parts[1].split('[')[0].strip()
                        sid = int(parts[1].split(':')[1])
                        priority = int(parts[2].split(':')[1].strip())
                        # Next line should have timestamp and IPs
                        next_line = next(f).strip()
                        ts_ip = next_line.split()
                        timestamp = ts_ip[0] if len(ts_ip) > 0 else ''
                        src = ts_ip[1] if len(ts_ip) > 1 else ''
                        dst = ts_ip[3] if len(ts_ip) > 3 else ''
                        alerts.append({
                            'sid': sid,
                            'message': msg,
                            'priority': priority,
                            'timestamp': timestamp,
                            'source': src,
                            'destination': dst
                        })
                    except Exception:
                        continue
        return alerts
    except Exception as e:
        return []

@method_decorator(csrf_exempt, name='dispatch')
class SnortAlertAPI(View):
    def get(self, request):
        alerts = parse_snort_alerts()
        return JsonResponse({'alerts': alerts})