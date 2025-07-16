from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.urls import reverse
from django.contrib.auth.mixins import LoginRequiredMixin
from django import forms
import subprocess
import psutil
import json
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib.auth.decorators import login_required
from .models import BondInterface, BondStatistics
from .forms import BondInterfaceForm

class RuleForm(forms.Form):
    CHAIN_CHOICES = [('input', 'Input'), ('output', 'Output'), ('forward', 'Forward')]
    ACTION_CHOICES = [('accept', 'Accept'), ('drop', 'Drop'), ('reject', 'Reject')]
    PROTOCOL_CHOICES = [('tcp', 'TCP'), ('udp', 'UDP'), ('icmp', 'ICMP'), ('all', 'All')]
    
    chain = forms.ChoiceField(choices=CHAIN_CHOICES)
    source = forms.CharField()
    destination = forms.CharField()
    protocol = forms.ChoiceField(choices=PROTOCOL_CHOICES)
    action = forms.ChoiceField(choices=ACTION_CHOICES)
    options = forms.CharField(required=False)

class ZoneForm(forms.Form):
    POLICY_CHOICES = [('accept', 'Accept'), ('drop', 'Drop'), ('reject', 'Reject')]
    
    name = forms.CharField(max_length=50)
    interfaces = forms.CharField()
    policy = forms.ChoiceField(choices=POLICY_CHOICES)

class NATForm(forms.Form):
    TYPE_CHOICES = [
        ('masquerade', 'Masquerade'),
        ('src-nat', 'Source NAT'),
        ('dst-nat', 'Destination NAT')
    ]
    
    type = forms.ChoiceField(choices=TYPE_CHOICES)
    source = forms.CharField(required=False)
    destination = forms.CharField(required=False)
    translate = forms.CharField()

class LogForm(forms.Form):
    LEVEL_CHOICES = [('emerg', 'Emergency'), ('alert', 'Alert'), ('crit', 'Critical')]
    
    level = forms.ChoiceField(choices=LEVEL_CHOICES)
    prefix = forms.CharField(required=False)

class DHCPServerForm(forms.Form):
    interface = forms.CharField(label='Interface', max_length=50)
    range_start = forms.GenericIPAddressField(label='Range Start')
    range_end = forms.GenericIPAddressField(label='Range End')
    lease_time = forms.IntegerField(label='Lease Time (minutes)', min_value=1)
    router = forms.GenericIPAddressField(label='Router (Gateway)', required=False)
    dns = forms.CharField(label='DNS Servers (comma-separated)', required=False)

class DHCPServerView(LoginRequiredMixin, View):
    template_name = 'network/dhcp.html'

    def get_config(self):
        # Placeholder: Load config from file or system
        import os, json
        config_path = os.path.join(os.path.dirname(__file__), 'dhcp_config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return None

    def save_config(self, config):
        import os, json
        config_path = os.path.join(os.path.dirname(__file__), 'dhcp_config.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

    def get(self, request):
        config = self.get_config()
        form = DHCPServerForm(initial=config) if config else DHCPServerForm()
        return render(request, self.template_name, {'form': form, 'config': config})

    def post(self, request):
        form = DHCPServerForm(request.POST)
        if form.is_valid():
            config = form.cleaned_data
            # Save config to file (or apply to system)
            self.save_config(config)
            messages.success(request, 'DHCP Server configuration saved.')
            return redirect('network:dhcp')
        config = self.get_config()
        return render(request, self.template_name, {'form': form, 'config': config})

# Routing Views
class RoutingView(LoginRequiredMixin, View):
    template_name = 'network/routing.html'

    def parse_routing_table(self, output):
        routes = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 8:
                route = {
                    'destination': parts[0],
                    'gateway': parts[1],
                    'genmask': parts[2],
                    'flags': parts[3],
                    'metric': parts[4],
                    'ref': parts[5],
                    'use': parts[6],
                    'interface': parts[7]
                }
                routes.append(route)
        return routes

    def get_routing_table_data(self):
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            return self.parse_routing_table(result.stdout)
        except Exception as e:
            print(f"Error getting routing table data: {e}")
            return []

    def get_interfaces(self):
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and '@' not in line:
                    iface = line.split(':')[1].strip()
                    if iface != 'lo':  # Exclude loopback
                        interfaces.append(iface)
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []

    def get_basic_routes(self):
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            print(f"Error getting basic routes: {e}")
            return "Error retrieving routes"

    def get_advanced_routes(self):
        try:
            tables = subprocess.run(['ip', 'rule', 'show'], capture_output=True, text=True)
            vrfs = subprocess.run(['ip', 'vrf', 'show'], capture_output=True, text=True)
            return f"Policy Rules:\n{tables.stdout}\n\nVRF Configuration:\n{vrfs.stdout}"
        except Exception as e:
            print(f"Error getting advanced routes: {e}")
            return "Error retrieving advanced routing info"

    def get_app_routes(self):
        try:
            # This would typically interact with your application-aware routing system
            # For now, we'll return a placeholder
            return "Application routing rules will be displayed here"
        except Exception as e:
            print(f"Error getting app routes: {e}")
            return "Error retrieving application routes"

    def get_mesh_status(self):
        try:
            nhrp = subprocess.run(['ip', 'nhrp', 'show'], capture_output=True, text=True)
            return f"Mesh Status:\n{nhrp.stdout}"
        except Exception as e:
            print(f"Error getting mesh status: {e}")
            return "Error retrieving Mesh status"

    def get(self, request):
        active_tab = request.GET.get('tab', 'basic')
        
        # Check if it's an AJAX request for routing table data
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            routes = self.get_routing_table_data()
            return JsonResponse({'routes': routes})
        
        context = {
            'active_tab': active_tab,
            'basic_routes': self.get_basic_routes(),
            'advanced_routes': self.get_advanced_routes(),
            'app_routes': self.get_app_routes(),
            'mesh_status': self.get_mesh_status(),
            'interfaces': self.get_interfaces(),
            'routing_table_data': self.get_routing_table_data(),
        }
        return render(request, self.template_name, context)

    def post(self, request):
        action = request.POST.get('action')
        tab = request.POST.get('tab', 'basic')

        try:
            if action == 'add_route':
                network = request.POST.get('network')
                gateway = request.POST.get('gateway')
                if network and gateway:
                    subprocess.run(['ip', 'route', 'add', network, 'via', gateway], check=True)
                    messages.success(request, f'Route added successfully: {network} via {gateway}')

            elif action == 'trace_route':
                destination = request.POST.get('destination')
                max_hops = request.POST.get('max_hops', '30')
                if destination:
                    result = subprocess.run(['traceroute', '-m', max_hops, destination], 
                                         capture_output=True, text=True)
                    request.session['trace_result'] = result.stdout
                    messages.success(request, f'Trace route completed for {destination}')

            elif action == 'show_table':
                table = request.POST.get('table', 'main')
                if table == 'all':
                    result = subprocess.run(['ip', 'route', 'show', 'table', 'all'], 
                                         capture_output=True, text=True)
                else:
                    result = subprocess.run(['ip', 'route', 'show', 'table', table], 
                                         capture_output=True, text=True)
                request.session['routing_table'] = result.stdout
                messages.success(request, f'Routing table {table} displayed')

            elif action == 'add_policy':
                source = request.POST.get('source')
                table = request.POST.get('table')
                priority = request.POST.get('priority', '100')
                if source and table:
                    subprocess.run(['ip', 'rule', 'add', 'from', source, 'table', table, 'priority', priority], check=True)
                    messages.success(request, f'Policy route added successfully for {source}')

            elif action == 'add_vrf':
                vrf_name = request.POST.get('vrf_name')
                table_id = request.POST.get('table_id')
                if vrf_name and table_id:
                    subprocess.run(['ip', 'vrf', 'add', vrf_name, 'table', table_id], check=True)
                    messages.success(request, f'VRF {vrf_name} created successfully')

            elif action == 'add_app_rule':
                app = request.POST.get('application')
                interface = request.POST.get('interface')
                sla_profile = request.POST.get('sla_profile')
                if app and interface and sla_profile:
                    # This would integrate with your application-aware routing system
                    messages.success(request, f'Application rule added for {app}')

            elif action == 'add_sla':
                profile_name = request.POST.get('profile_name')
                latency = request.POST.get('latency')
                jitter = request.POST.get('jitter')
                packet_loss = request.POST.get('packet_loss')
                if all([profile_name, latency, jitter, packet_loss]):
                    # This would create an SLA profile in your monitoring system
                    messages.success(request, f'SLA profile {profile_name} created')

            elif action == 'add_mesh':
                interface = request.POST.get('interface')
                hub = request.POST.get('hub')
                secret = request.POST.get('secret')
                holding_time = request.POST.get('holding_time', '300')
                if all([interface, hub, secret]):
                    # Configure Mesh
                    subprocess.run(['ip', 'nhrp', 'add', interface, hub, 'register', 'holding-time', holding_time], check=True)
                    messages.success(request, f'Mesh configured for {interface}')

            elif action == 'configure_frr':
                primary = request.POST.get('primary_path')
                backup = request.POST.get('backup_path')
                delay = request.POST.get('failover_delay', '50')
                if primary and backup:
                    # This would configure FRR for the mesh network
                    messages.success(request, 'FRR configuration updated')

        except subprocess.CalledProcessError as e:
            messages.error(request, f'Error: {e.stderr.decode() if e.stderr else str(e)}')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')

        # Get the updated context
        context = {
            'active_tab': tab,
            'basic_routes': self.get_basic_routes(),
            'advanced_routes': self.get_advanced_routes(),
            'app_routes': self.get_app_routes(),
            'mesh_status': self.get_mesh_status(),
            'interfaces': self.get_interfaces(),
            'routing_table_data': self.get_routing_table_data(),
        }

        # Add trace route and routing table results if they exist
        if 'trace_result' in request.session:
            context['trace_result'] = request.session.pop('trace_result')
        if 'routing_table' in request.session:
            context['routing_table'] = request.session.pop('routing_table')

        return render(request, self.template_name, context)

# Firewall Views
class FirewallView(LoginRequiredMixin, View):
    def get(self, request):
        active_tab = request.GET.get('tab', 'rules')
        
        # Get firewall rules
        try:
            rules_output = subprocess.check_output(['nft', 'list', 'ruleset']).decode('utf-8')
        except:
            rules_output = "Unable to retrieve firewall rules"
        
        # Simulate rules for display
        rules = [
            {
                'id': 1,
                'chain': 'input',
                'source': 'any',
                'destination': 'any',
                'protocol': 'tcp',
                'action': 'accept',
                'options': 'dport 22'
            }
        ]
        
        # Simulate zones
        zones = [
            {
                'id': 1,
                'name': 'wan',
                'interfaces': 'eth0',
                'policy': 'drop'
            },
            {
                'id': 2,
                'name': 'lan',
                'interfaces': 'eth1',
                'policy': 'accept'
            }
        ]
        
        # Simulate NAT rules
        nats = [
            {
                'id': 1,
                'type': 'masquerade',
                'source': '192.168.1.0/24',
                'destination': 'any',
                'translate': 'eth0'
            }
        ]
        
        # Simulate firewall logs
        logs = [
            {
                'timestamp': '2023-10-15 14:30:22',
                'action': 'DROP',
                'source': '203.0.113.5',
                'destination': '192.168.1.1',
                'protocol': 'tcp'
            }
        ]
        
        # Forms
        class RuleForm(forms.Form):
            CHAIN_CHOICES = [('input', 'Input'), ('output', 'Output'), ('forward', 'Forward')]
            ACTION_CHOICES = [('accept', 'Accept'), ('drop', 'Drop'), ('reject', 'Reject')]
            PROTOCOL_CHOICES = [('tcp', 'TCP'), ('udp', 'UDP'), ('icmp', 'ICMP'), ('all', 'All')]
            
            chain = forms.ChoiceField(choices=CHAIN_CHOICES)
            source = forms.CharField()
            destination = forms.CharField()
            protocol = forms.ChoiceField(choices=PROTOCOL_CHOICES)
            action = forms.ChoiceField(choices=ACTION_CHOICES)
            options = forms.CharField(required=False)
        
        class ZoneForm(forms.Form):
            POLICY_CHOICES = [('accept', 'Accept'), ('drop', 'Drop'), ('reject', 'Reject')]
            
            name = forms.CharField(max_length=50)
            interfaces = forms.CharField()
            policy = forms.ChoiceField(choices=POLICY_CHOICES)
        
        class NATForm(forms.Form):
            TYPE_CHOICES = [
                ('masquerade', 'Masquerade'),
                ('src-nat', 'Source NAT'),
                ('dst-nat', 'Destination NAT')
            ]
            
            type = forms.ChoiceField(choices=TYPE_CHOICES)
            source = forms.CharField(required=False)
            destination = forms.CharField(required=False)
            translate = forms.CharField()
        
        class LogForm(forms.Form):
            LEVEL_CHOICES = [('emerg', 'Emergency'), ('alert', 'Alert'), ('crit', 'Critical')]
            
            level = forms.ChoiceField(choices=LEVEL_CHOICES)
            prefix = forms.CharField(required=False)
        
        return render(request, 'network/firewall.html', {
            'rules_output': rules_output,
            'rules': rules,
            'zones': zones,
            'nats': nats,
            'logs': logs,
            'active_tab': active_tab,
            'rule_form': RuleForm(),
            'zone_form': ZoneForm(),
            'nat_form': NATForm(),
            'log_form': LogForm()
        })
    
    def post(self, request):
        tab = request.POST.get('tab', 'rules')
        action = request.POST.get('action')
        
        if tab == 'rules' and action == 'add_rule':
            chain = request.POST.get('chain')
            source = request.POST.get('source')
            destination = request.POST.get('destination')
            protocol = request.POST.get('protocol')
            action_val = request.POST.get('action')
            options = request.POST.get('options', '')
            
            try:
                # Add nftables rule
                cmd = f'nft add rule ip filter {chain} ip saddr {source} ip daddr {destination} {protocol} {action_val} {options}'
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                pass
        
        return redirect(f'{reverse("network:firewall")}?tab={tab}')

# Optimisation Views
class OptimisationView(LoginRequiredMixin, View):
    def get(self, request):
        active_tab = request.GET.get('tab', 'compression')
        
        # Get current settings
        compression = 'zstd'
        fec_status = 'active'
        cc_algo = 'bbr'
        qos = 'default'
        
        # Get shaping rules
        try:
            shaping_rules = subprocess.check_output(['tc', 'qdisc', 'show']).decode('utf-8')
        except:
            shaping_rules = "Unable to retrieve shaping rules"
        
        # Get QoS rules
        try:
            qos_rules = subprocess.check_output(['nft', 'list', 'chain', 'ip', 'qos', 'qos_chain']).decode('utf-8')
        except:
            qos_rules = "Unable to retrieve QoS rules"
        
        # Forms
        class CompressionForm(forms.Form):
            ALGORITHM_CHOICES = [
                ('zstd', 'ZStandard (zstd)'),
                ('lzo', 'LZO'),
                ('deflate', 'Deflate'),
                ('none', 'None')
            ]
            
            algorithm = forms.ChoiceField(choices=ALGORITHM_CHOICES)
            level = forms.IntegerField(min_value=1, max_value=22)
        
        class FECForm(forms.Form):
            ALGORITHM_CHOICES = [
                ('raptorq', 'RaptorQ'),
                ('reed-solomon', 'Reed-Solomon'),
                ('none', 'None')
            ]
            
            algorithm = forms.ChoiceField(choices=ALGORITHM_CHOICES)
            overhead = forms.IntegerField(min_value=0, max_value=100)
        
        class CongestionForm(forms.Form):
            ALGORITHM_CHOICES = [
                ('bbr', 'BBR'),
                ('cubic', 'CUBIC'),
                ('reno', 'Reno')
            ]
            
            algorithm = forms.ChoiceField(choices=ALGORITHM_CHOICES)
        
        class ShapingForm(forms.Form):
            interface = forms.CharField()
            rate = forms.CharField()
            burst = forms.CharField()
            latency = forms.CharField()
        
        class QoSForm(forms.Form):
            class_name = forms.CharField()
            rate = forms.CharField()
            priority = forms.IntegerField()
        
        return render(request, 'network/optimisation.html', {
            'compression': compression,
            'fec_status': fec_status,
            'cc_algo': cc_algo,
            'qos': qos,
            'shaping_rules': shaping_rules,
            'qos_rules': qos_rules,
            'active_tab': active_tab,
            'compression_form': CompressionForm(initial={
                'algorithm': compression,
                'level': 6
            }),
            'fec_form': FECForm(initial={
                'algorithm': 'raptorq',
                'overhead': 10
            }),
            'congestion_form': CongestionForm(initial={
                'algorithm': cc_algo
            }),
            'shaping_form': ShapingForm(),
            'qos_form': QoSForm()
        })
    
    def post(self, request):
        tab = request.POST.get('tab', 'compression')
        
        if tab == 'compression':
            algorithm = request.POST.get('algorithm')
            level = request.POST.get('level')
            try:
                # Configure compression
                pass
            except:
                pass
        
        return redirect(f'{reverse("network:optimisation")}?tab={tab}')

# Bonding Views
class BondingView(LoginRequiredMixin, View):
    def get(self, request):
        # Check if it's an AJAX request for bond status
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            print("Received AJAX request for bond status")
            bonds = BondInterface.objects.all()
            stats = []
            for bond in bonds:
                try:
                    # Get bond statistics from /proc/net/bonding/
                    with open(f'/proc/net/bonding/{bond.name}', 'r') as f:
                        content = f.read()
                        # Parse statistics from the file
                        transmit = 0
                        receive = 0
                        failures = 0
                        active = ''
                        
                        for line in content.split('\n'):
                            if 'Transmit' in line:
                                transmit = int(line.split(':')[1].strip())
                            elif 'Receive' in line:
                                receive = int(line.split(':')[1].strip())
                            elif 'Slave Interface' in line:
                                active = line.split(':')[1].strip()
                            elif 'Link Failure Count' in line:
                                failures = int(line.split(':')[1].strip())
                        
                        stats.append({
                            'interface': bond.name,
                            'transmit': transmit,
                            'receive': receive,
                            'failures': failures,
                            'active': active,
                            'status': bond.status
                        })
                except FileNotFoundError:
                    print(f"Could not find bonding file for {bond.name}")
                    continue
                except Exception as e:
                    print(f"Error reading bonding file for {bond.name}: {str(e)}")
                    continue
            
            response_data = {
                'bonds': list(bonds.values('name', 'mode', 'slaves', 'status')),
                'stats': stats
            }
            print("Sending response:", response_data)
            return JsonResponse(response_data)

        # Regular page load
        form = BondInterfaceForm()
        bonds = BondInterface.objects.all()
        
        # Get bonding statistics
        stats = []
        for bond in bonds:
            try:
                # Get bond statistics from /proc/net/bonding/
                with open(f'/proc/net/bonding/{bond.name}', 'r') as f:
                    content = f.read()
                    # Parse statistics from the file
                    transmit = 0
                    receive = 0
                    failures = 0
                    active = ''
                    
                    for line in content.split('\n'):
                        if 'Transmit' in line:
                            transmit = int(line.split(':')[1].strip())
                        elif 'Receive' in line:
                            receive = int(line.split(':')[1].strip())
                        elif 'Slave Interface' in line:
                            active = line.split(':')[1].strip()
                        elif 'Link Failure Count' in line:
                            failures = int(line.split(':')[1].strip())
                    
                    stats.append({
                        'interface': bond.name,
                        'transmit': transmit,
                        'receive': receive,
                        'failures': failures,
                        'active': active
                    })
            except FileNotFoundError:
                print(f"Could not find bonding file for {bond.name}")
                continue
            except Exception as e:
                print(f"Error reading bonding file for {bond.name}: {str(e)}")
                continue
        
        return render(request, 'network/bonding.html', {
            'form': form,
            'bonds': bonds,
            'stats': stats
        })
    
    def post(self, request, bond_name=None):
        print("POST request received")
        print("POST data:", request.POST)
        
        if bond_name:
            # Handle delete operation
            try:
                bond = BondInterface.objects.get(name=bond_name)
                
                # Remove bond interface using system commands
                try:
                    subprocess.run(['sudo', 'ip', 'link', 'set', bond.name, 'down'], 
                                 capture_output=True, text=True, check=True)
                    subprocess.run(['sudo', 'ip', 'link', 'del', bond.name], 
                                 capture_output=True, text=True, check=True)
                except subprocess.CalledProcessError as e:
                    return JsonResponse({
                        'success': False, 
                        'error': f'Error removing bond interface: {e.stderr}'
                    })
                
                bond.delete()
                return JsonResponse({'success': True})
            except BondInterface.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Bond interface not found'})
            except Exception as e:
                return JsonResponse({'success': False, 'error': str(e)})
        
        # Handle form submissions
        form_type = request.POST.get('form_type')
        print("Form type:", form_type)
        
        if form_type == 'create_bond':
            print("Processing create_bond form")
            form = BondInterfaceForm(request.POST)
            print("Form is valid:", form.is_valid())
            if not form.is_valid():
                print("Form validation errors:", form.errors)
                return JsonResponse({
                    'success': False,
                    'error': 'Form validation failed',
                    'errors': form.errors
                })
            
            print("Form validation passed")
            bond = form.save(commit=False)
            try:
                # Create bond interface using system commands
                try:
                    # First check if the bond interface already exists
                    print(f"Checking if bond interface {bond.name} exists")
                    result = subprocess.run(['ip', 'link', 'show', bond.name], 
                                         capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"Bond interface {bond.name} already exists")
                        return JsonResponse({
                            'success': False,
                            'error': f'Bond interface {bond.name} already exists'
                        })

                    print(f"Creating bond interface {bond.name}")
                    # Create the bond interface
                    result = subprocess.run(['sudo', 'ip', 'link', 'add', bond.name, 'type', 'bond'], 
                                         capture_output=True, text=True, check=True)
                    print("Bond interface created")
                    
                    print(f"Setting bonding mode to {bond.mode}")
                    # Set the bonding mode
                    result = subprocess.run(['sudo', 'ip', 'link', 'set', bond.name, 'type', 'bond', 'mode', bond.mode], 
                                         capture_output=True, text=True, check=True)
                    print("Bonding mode set")
                    
                    # Add slaves to bond
                    for slave in bond.slaves.split(','):
                        slave = slave.strip()
                        print(f"Processing slave interface {slave}")
                        # Check if slave interface exists
                        result = subprocess.run(['ip', 'link', 'show', slave], 
                                             capture_output=True, text=True)
                        if result.returncode != 0:
                            print(f"Slave interface {slave} does not exist")
                            return JsonResponse({
                                'success': False,
                                'error': f'Slave interface {slave} does not exist'
                            })
                        
                        print(f"Adding slave {slave} to bond {bond.name}")
                        # Add slave to bond
                        result = subprocess.run(['sudo', 'ip', 'link', 'set', slave, 'master', bond.name], 
                                             capture_output=True, text=True, check=True)
                        print(f"Slave {slave} added to bond")
                    
                    print(f"Bringing up bond interface {bond.name}")
                    # Bring up the bond interface
                    result = subprocess.run(['sudo', 'ip', 'link', 'set', bond.name, 'up'], 
                                         capture_output=True, text=True, check=True)
                    print("Bond interface brought up")
                    
                    # Save the bond to the database
                    bond.status = 'up'
                    bond.save()
                    print("Bond interface saved to database")
                    
                    return JsonResponse({
                        'success': True,
                        'message': f'Bond interface {bond.name} created successfully'
                    })
                
                except subprocess.CalledProcessError as e:
                    print(f"Error in system command: {e.stderr}")
                    # Clean up if something goes wrong
                    try:
                        subprocess.run(['sudo', 'ip', 'link', 'set', bond.name, 'down'], 
                                     capture_output=True, text=True)
                        subprocess.run(['sudo', 'ip', 'link', 'del', bond.name], 
                                     capture_output=True, text=True)
                    except:
                        pass
                    return JsonResponse({
                        'success': False,
                        'error': f'Error creating bond interface: {e.stderr}'
                    })
            except Exception as e:
                print(f"Unexpected error: {str(e)}")
                return JsonResponse({
                    'success': False,
                    'error': f'Unexpected error: {str(e)}'
                })
        
        return JsonResponse({
            'success': False,
            'error': 'Invalid form type'
        })

# Monitor Views
class MonitorView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'network/monitor.html')

# DPI Views
class DPIView(LoginRequiredMixin, View):
    def get(self, request):
        # Get nDPI statistics
        try:
            stats_output = subprocess.check_output(['ndpi_stats']).decode('utf-8')
        except:
            stats_output = "Unable to retrieve nDPI statistics"
        
        # Simulate protocols
        protocols = [
            {
                'id': 1,
                'name': 'HTTP',
                'category': 'Web',
                'risk': 'low',
                'enabled': True
            },
            {
                'id': 2,
                'name': 'SSH',
                'category': 'Remote Access',
                'risk': 'medium',
                'enabled': True
            }
        ]
        
        # Simulate stats
        stats = [
            {
                'protocol': 'HTTP',
                'packets': 12500,
                'bytes': 52428800,
                'flows': 1200,
                'percent': 45
            },
            {
                'protocol': 'SSH',
                'packets': 300,
                'bytes': 1048576,
                'flows': 15,
                'percent': 5
            }
        ]
        
        # Simulate flows
        flows = [
            {
                'time': '14:30:22',
                'source': '192.168.1.100',
                'destination': '203.0.113.5',
                'protocol': 'HTTP',
                'duration': '5m 22s',
                'bytes': '2.5 MB'
            }
        ]
        
        # Form for DPI configuration
        class ConfigForm(forms.Form):
            interface = forms.CharField()
            sampling_rate = forms.IntegerField()
            max_flows = forms.IntegerField()
        
        return render(request, 'network/dpi.html', {
            'stats_output': stats_output,
            'protocols': protocols,
            'stats': stats,
            'flows': flows,
            'config_form': ConfigForm(initial={
                'interface': 'eth0',
                'sampling_rate': 100,
                'max_flows': 10000
            })
        })
    
    def post(self, request):
        action = request.POST.get('action')
        
        if action == 'toggle_protocol':
            protocol_id = request.POST.get('protocol_id')
            enabled = request.POST.get('enabled') == 'true'
            
            try:
                # Enable/disable protocol detection
                pass
            except:
                pass
        
        return redirect('network:dpi')

@login_required
@require_http_methods(["GET"])
def mptcp_endpoint_show(request):
    try:
        result = subprocess.run(['ip', 'mptcp', 'endpoint', 'show'], 
                              capture_output=True, text=True, check=True)
        endpoints = []
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.split()
                endpoint = {
                    'id': parts[0],
                    'ifaddr': parts[1],
                    'port': parts[2] if len(parts) > 2 and parts[2].isdigit() else None,
                    'dev': parts[-1] if len(parts) > 3 else None,
                    'flags': [f for f in parts[3:-1] if f not in ['dev']] if len(parts) > 3 else []
                }
                endpoints.append(endpoint)
        return JsonResponse({'success': True, 'endpoints': endpoints})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def mptcp_endpoint_add(request):
    try:
        data = json.loads(request.body)
        cmd = ['ip', 'mptcp', 'endpoint', 'add', data['ifaddr']]
        
        if data.get('port'):
            cmd.extend(['port', str(data['port'])])
        if data.get('dev'):
            cmd.extend(['dev', data['dev']])
        if data.get('id'):
            cmd.extend(['id', str(data['id'])])
        
        cmd.extend(data.get('flags', []))
        
        subprocess.run(cmd, check=True)
        return JsonResponse({'success': True})
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def mptcp_endpoint_delete(request, endpoint_id):
    try:
        subprocess.run(['ip', 'mptcp', 'endpoint', 'delete', 'id', str(endpoint_id)], check=True)
        return JsonResponse({'success': True})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def mptcp_endpoint_change(request, endpoint_id):
    try:
        data = json.loads(request.body)
        cmd = ['ip', 'mptcp', 'endpoint', 'change', 'id', str(endpoint_id)]
        
        if data.get('ifaddr'):
            cmd.append(data['ifaddr'])
        if data.get('port'):
            cmd.extend(['port', str(data['port'])])
        
        flags = []
        if data.get('backup'):
            flags.append('backup')
        if data.get('fullmesh'):
            flags.append('fullmesh')
        cmd.extend(flags)
        
        subprocess.run(cmd, check=True)
        return JsonResponse({'success': True})
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["GET"])
def mptcp_limits_show(request):
    try:
        result = subprocess.run(['ip', 'mptcp', 'limits', 'show'], 
                              capture_output=True, text=True, check=True)
        limits = {}
        for line in result.stdout.split('\n'):
            if 'subflow' in line:
                limits['subflow'] = int(line.split()[-1])
            elif 'add_addr_accepted' in line:
                limits['add_addr'] = int(line.split()[-1])
        return JsonResponse({'success': True, **limits})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
def mptcp_limits_set(request):
    try:
        data = json.loads(request.body)
        cmd = ['ip', 'mptcp', 'limits', 'set']
        
        if data.get('subflow') is not None:
            cmd.extend(['subflow', str(data['subflow'])])
        if data.get('add_addr') is not None:
            cmd.extend(['add_addr_accepted', str(data['add_addr'])])
        
        subprocess.run(cmd, check=True)
        return JsonResponse({'success': True})
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["GET"])
def mptcp_monitor(request):
    try:
        result = subprocess.run(['ip', 'mptcp', 'monitor'], 
                              capture_output=True, text=True, check=True)
        return JsonResponse({'success': True, 'output': result.stdout})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'success': False, 'error': str(e)})

class MPTCPView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'network/mptcp.html')

def firewall_view(request):
    context = {
        'rule_form': RuleForm(),
        'zone_form': ZoneForm(),
        'nat_form': NATForm(),
        'log_form': LogForm(),
        'rules': [],
        'zones': [],
        'nats': [],
        'logs': [],
        'active_tab': request.GET.get('tab', 'rules'),
    }
    return render(request, 'network/firewall.html', context)