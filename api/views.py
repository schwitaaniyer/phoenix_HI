from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponseForbidden
from .models import AuthenticationMethod, PrivilegeLevel, UserProfile
from .forms import AuthMethodForm, LDAPConfigForm, TACACSConfigForm, RADIUSConfigForm, PrivilegeLevelForm, UserCreateForm, UserEditForm
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.conf import settings
import subprocess
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
import platform
import psutil
import re
from datetime import datetime

User = get_user_model()

def is_super_admin(user):
    # For development/local auth, always grant super admin rights if authenticated
    return user.is_authenticated

@login_required
def authentication_config(request):
    print(f"[DEBUG] authentication_config called for user: {request.user} (is_authenticated={request.user.is_authenticated})")
    if not is_super_admin(request.user):
        print("[DEBUG] Not super admin, returning not_authorized.html")
        return render(request, 'not_authorized.html', status=403)
    method_obj = AuthenticationMethod.objects.filter(is_global=True).first()
    if request.method == 'POST':
        form = AuthMethodForm(request.POST, instance=method_obj)
        if form.is_valid():
            form.save()
            return redirect('services:authentication')
    else:
        form = AuthMethodForm(instance=method_obj)
    ldap_form = LDAPConfigForm(initial=settings.LDAP_CONFIG)
    tacacs_form = TACACSConfigForm(initial=settings.TACACS_CONFIG)
    radius_form = RADIUSConfigForm(initial=settings.RADIUS_CONFIG)
    print("[DEBUG] Returning authentication.html for user")
    return render(request, 'services/authentication.html', {
        'form': form,
        'ldap_form': ldap_form,
        'tacacs_form': tacacs_form,
        'radius_form': radius_form,
        'current_method': method_obj.method if method_obj else 'local',
    })

@login_required
@user_passes_test(is_super_admin)
@require_POST
@csrf_exempt
def set_auth_method(request):
    method = request.POST.get('method')
    method_obj, _ = AuthenticationMethod.objects.get_or_create(is_global=True)
    method_obj.method = method
    method_obj.save()
    return JsonResponse({'success': True})

@login_required
@user_passes_test(is_super_admin)
@require_POST
@csrf_exempt
def set_ldap_config(request):
    form = LDAPConfigForm(request.POST)
    if form.is_valid():
        settings.LDAP_CONFIG.update(form.cleaned_data)
        return JsonResponse({'success': True})
    return JsonResponse({'success': False, 'errors': form.errors}, status=400)

@login_required
@user_passes_test(is_super_admin)
@require_POST
@csrf_exempt
def set_tacacs_config(request):
    form = TACACSConfigForm(request.POST)
    if form.is_valid():
        settings.TACACS_CONFIG.update(form.cleaned_data)
        return JsonResponse({'success': True})
    return JsonResponse({'success': False, 'errors': form.errors}, status=400)

@login_required
@user_passes_test(is_super_admin)
@require_POST
@csrf_exempt
def set_radius_config(request):
    form = RADIUSConfigForm(request.POST)
    if form.is_valid():
        settings.RADIUS_CONFIG.update(form.cleaned_data)
        return JsonResponse({'success': True})
    return JsonResponse({'success': False, 'errors': form.errors}, status=400)

@login_required
def get_privilege_levels(request):
    if not is_super_admin(request.user):
        return HttpResponseForbidden()
    levels = list(PrivilegeLevel.objects.values('id', 'name', 'level', 'description'))
    return JsonResponse({'levels': levels})

@login_required
def get_users(request):
    if not is_super_admin(request.user):
        return HttpResponseForbidden()
    users = list(User.objects.all().values('id', 'username', 'email'))
    return JsonResponse({'users': users})

@login_required
@user_passes_test(is_super_admin)
@require_POST
@csrf_exempt
def set_user_privilege(request):
    user_id = request.POST.get('user_id')
    level_id = request.POST.get('level_id')
    user = get_object_or_404(User, pk=user_id)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.privilege_level_id = level_id
    profile.save()
    return JsonResponse({'success': True})

def is_service_manager(user):
    # For development/local auth, always grant service manager rights if authenticated
    return user.is_authenticated

@login_required
@user_passes_test(is_service_manager)
@require_GET
def snmp_status(request):
    try:
        result = subprocess.run(['systemctl', 'status', 'snmpd'], capture_output=True, text=True)
        return JsonResponse({'status': result.stdout})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_service_manager)
@require_POST
@csrf_exempt
def snmp_control(request):
    action = request.POST.get('action')
    if action not in ['start', 'stop', 'restart']:
        return JsonResponse({'error': 'Invalid action'}, status=400)
    try:
        result = subprocess.run(['systemctl', action, 'snmpd'], capture_output=True, text=True)
        return JsonResponse({'output': result.stdout})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_service_manager)
@require_GET
def ips_status(request):
    try:
        result = subprocess.run(['systemctl', 'status', 'snort'], capture_output=True, text=True)
        return JsonResponse({'status': result.stdout})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_service_manager)
@require_POST
@csrf_exempt
def ips_control(request):
    action = request.POST.get('action')
    if action not in ['start', 'stop', 'restart']:
        return JsonResponse({'error': 'Invalid action'}, status=400)
    try:
        result = subprocess.run(['systemctl', action, 'snort'], capture_output=True, text=True)
        return JsonResponse({'output': result.stdout})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_service_manager)
@require_GET
def ipsec_status(request):
    try:
        result = subprocess.run(['systemctl', 'status', 'ipsec'], capture_output=True, text=True)
        return JsonResponse({'status': result.stdout})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_service_manager)
@require_POST
@csrf_exempt
def ipsec_control(request):
    action = request.POST.get('action')
    if action not in ['start', 'stop', 'restart', 'reload']:
        return JsonResponse({'error': 'Invalid action'}, status=400)
    try:
        result = subprocess.run(['systemctl', action, 'ipsec'], capture_output=True, text=True)
        return JsonResponse({'output': result.stdout})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

class SystemInfoAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        hardware = {
            'model': subprocess.getoutput('cat /sys/firmware/devicetree/base/model').strip() or 'Unknown',
            'serial': subprocess.getoutput('cat /sys/firmware/devicetree/base/serial-number').strip() or 'Unknown',
            'cpu': platform.processor(),
            'cores': psutil.cpu_count(logical=False),
            'memory': f"{round(psutil.virtual_memory().total / (1024 ** 3), 1)} GB",
            'storage': f"{round(psutil.disk_usage('/').total / (1024 ** 3), 1)} GB",
            'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
        }
        software = {
            'os': platform.system(),
            'kernel': platform.release(),
            'sdwan_version': '2.0.1',
            'last_updated': '2023-10-15',
            'license_valid': True,
            'license_expiry': '2024-10-15'
        }
        cpu_usage = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        memory_usage = mem.percent
        memory_used = round(mem.used / (1024 ** 2))
        memory_total = round(mem.total / (1024 ** 2))
        disks = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    'mount': part.mountpoint,
                    'percent': usage.percent,
                    'used': round(usage.used / (1024 ** 3), 1),
                    'total': round(usage.total / (1024 ** 3), 1)
                })
            except Exception:
                continue
        return Response({
            'hardware': hardware,
            'software': software,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'memory_used': memory_used,
            'memory_total': memory_total,
            'disks': disks
        })

class NetworkInterfacesAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        interfaces = []
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                match = re.match(r'^\d+:\s+(\w+):\s+<(.+)>\s+mtu\s+(\d+).*', line)
                if match:
                    name = match.group(1)
                    flags = match.group(2)
                    mtu = match.group(3)
                    status = 'up' if 'UP' in flags else 'down'
                    try:
                        ip_result = subprocess.run(['ip', 'addr', 'show', name], capture_output=True, text=True)
                        mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', ip_result.stdout)
                        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
                        mac_address = mac_match.group(1) if mac_match else 'N/A'
                        ip_address = ip_match.group(1) if ip_match else 'N/A'
                    except:
                        mac_address = 'N/A'
                        ip_address = 'N/A'
                    try:
                        ethtool_result = subprocess.run(['ethtool', name], capture_output=True, text=True)
                        speed_match = re.search(r'Speed:\s+(\d+)\s+Mbps', ethtool_result.stdout)
                        duplex_match = re.search(r'Duplex:\s+(\w+)', ethtool_result.stdout)
                        speed = speed_match.group(1) if speed_match else 'N/A'
                        duplex = duplex_match.group(1).lower() if duplex_match else 'N/A'
                    except:
                        speed = 'N/A'
                        duplex = 'N/A'
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
        except Exception as e:
            return Response({'error': str(e)}, status=500)
        return Response({'interfaces': interfaces})

class ServicesListAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # List of common services to check
        services = ['strongswan', 'snmpd', 'snort', 'openvpn', 'ssh', 'nginx', 'apache2']
        service_status = []
        for service in services:
            try:
                result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
                status = result.stdout.strip()
            except Exception as e:
                status = f'Error: {str(e)}'
            service_status.append({'service': service, 'status': status})
        return Response({'services': service_status})

class FirewallStatusAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            rules_output = subprocess.check_output(['nft', 'list', 'ruleset']).decode('utf-8')
        except Exception as e:
            rules_output = f"Unable to retrieve firewall rules: {str(e)}"
        return Response({'rules': rules_output})

class SystemLogsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            logs = subprocess.check_output(['journalctl', '--no-pager', '-n', '100']).decode('utf-8')
        except Exception as e:
            logs = f"Unable to retrieve logs: {str(e)}"
        return Response({'logs': logs})

class ProcessListAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
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
        processes = sorted(processes, key=lambda p: p['cpu'], reverse=True)[:50]
        return Response({'processes': processes})
