from django.shortcuts import render, HttpResponse, redirect
from datetime import datetime
from home.models import Contact
from django.contrib import messages
from django.http import JsonResponse
import subprocess
import os
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
# from django_auth_ldap.backend import LDAPBackend
from django.contrib.auth.backends import ModelBackend

from django.contrib.auth import authenticate, login
# from django_auth_ldap.backend import LDAPBackend
from django.shortcuts import render, redirect
from django.contrib import messages
from home.utils.permissions import check_page_permissions


def authentication(request):
    
    return render(request, 'authentication.html')

def configure_radius(request):
    
    return render(request, 'radius.html')
def configure_tacas(request):
    
    return render(request, 'tacas.html')


# from django.shortcuts import render, redirect
# from .forms import LDAPConfigForm
# from .models import LDAPConfig

# def configure_ldap(request):
#     ldap_config = LDAPConfig.objects.first()
#     if request.method == "POST":
#         form = LDAPConfigForm(request.POST, instance=ldap_config)
#         if form.is_valid():
#             form.save()
#             return redirect("success_page")
#     else:
#         form = LDAPConfigForm(instance=ldap_config)
#     return render(request, "configure_ldap.html", {"form": form})



# import ldap
from django.shortcuts import render
from socket import timeout

# Keep track of connection results
connection_results = {}

def configure_ldap(request):
    global connection_results
    if request.method == 'POST':
        ldap_ip = request.POST.get('ldap_ip')
        bind_dn = request.POST.get('bind_dn')
        bind_password = request.POST.get('bind_password')

        # Debug: Log received data
        print("LDAP IP:", ldap_ip)
        print("Bind DN:", bind_dn)
        print("Bind Password:", bind_password)

        # Initialize connection status
        status_message = "Not Connected"

        try:
            # Set the timeout value to avoid long waiting times
            ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)  # Timeout in seconds
            ldap_connection = ldap.initialize(ldap_ip)
            
            # Attempt to bind with provided credentials
            ldap_connection.simple_bind_s(bind_dn, bind_password)
            status_message = "Connected Successfully"
        except ldap.LDAPError as e:
            status_message = f"Connection Failed"
        except timeout:
            status_message = "Connection Timed Out"
        except Exception as e:
            status_message = f"Unexpected Error: {str(e)}"
        finally:
            if 'ldap_connection' in locals():
                ldap_connection.unbind()

        # Debug: Log status message
        print("Connection Status for", ldap_ip, ":", status_message)

        # Update connection results
        connection_results[ldap_ip] = status_message

    # Debug: Log connection results
    print("Connection Results:", connection_results)

    return render(request, 'ldap.html', {'connection_results': connection_results})





# from django.core.cache import cache
# from django.http import HttpResponse
# from django.shortcuts import render

# def configure_ldap(request):
#     if request.method == 'POST':
#         ldap_ip = request.POST.get('ldap_ip')
#         bind_dn = request.POST.get('bind_dn')
#         bind_password = request.POST.get('bind_password')
#         # Manually invalidate cache before updating
#         cache.delete('LDAP_SERVER_URI')
#         cache.delete('LDAP_BIND_DN')
#         cache.delete('LDAP_BIND_PASSWORD')
#         # Save the configuration dynamically
#         cache.set('LDAP_SERVER_URI', f'ldap://{ldap_ip}', timeout=60)
#         cache.set('LDAP_BIND_DN', bind_dn, timeout=60)
#         cache.set('LDAP_BIND_PASSWORD', bind_password, timeout=60)

#         # Debugging statements
#         print("LDAP IP received:", ldap_ip)
#         print("Bind DN received:", bind_dn)
#         print("Bind Password received:", bind_password)
#         print("Cache for LDAP_SERVER_URI:", cache.get('LDAP_SERVER_URI'))
#         print("Cache for LDAP_BIND_DN:", cache.get('LDAP_BIND_DN'))
#         print("Cache for LDAP_BIND_PASSWORD:", cache.get('LDAP_BIND_PASSWORD'))

#         return HttpResponse("LDAP configuration saved successfully.")
#     return render(request, 'ldap.html')













def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Attempt authentication
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            print(f"Authentication Passed for {username}")  # Console message
            return redirect('home')
        else:
            print(f"Authentication Failed for {username}")  # Console message
            messages.error(request, "Invalid username or password.")
            return redirect('login')

    return render(request, 'login.html')

# def user_login(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')

#         # Attempt LDAP authentication first
#         ldap_backend = LDAPBackend()
#         user = ldap_backend.authenticate(request, username=username, password=password)

#         if user is not None:
#             user.backend = 'django_auth_ldap.backend.LDAPBackend'  # Explicitly specify backend
#             login(request, user)
#             print(f"LDAP Authentication Passed for {username}")  # Console message
#             return redirect('home')
#         else:
#             print(f"LDAP Authentication Failed for {username}")  # Console message

#         # Fallback to local authentication
#         user = authenticate(request, username=username, password=password)
        
#         if user is not None:
#             user.backend = 'django.contrib.auth.backends.ModelBackend'  # Explicitly specify backend
#             login(request, user)F
#             print(f"Django Local Authentication Passed for {username}")  # Console message
#             return redirect('home')
#         else:
#             print(f"Django Local Authentication Failed for {username}")  # Console message
#             messages.error(request, "Invalid username or password.")
#             return redirect('login')

#     return render(request, 'login.html')






def user_logout(request):
    logout(request)  # Logs out the user
    return redirect('login')


 
@login_required
# def ldap(request):
    
#     return render(request, 'ldap.html')
@login_required
def snort(request):
    
    return render(request, 'snort.html')
@login_required
def home(request):
    
    return render(request, 'home.html')
 
    # return HttpResponse("this is homepage")
@login_required
def networkmanagment(request):
    
    return render(request, 'networkmanagment.html')
@login_required
# Create your views here.
def firewall(request):
     
    return render(request, 'firewall.html')
    # return HttpResponse("this is homepage")

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from home.models import Page, PagePermission
import subprocess


@login_required
@check_page_permissions('blocklist')

def blocklist(request):

    result = None

    if request.method == 'POST':
        action = request.POST.get('action', '')
        ip_host_group = request.POST.get('ip_host_group', '')

        if action == 'block':
            try:
                result = subprocess.check_output(f"vuurmuur_script --block {ip_host_group}", shell=True).decode()
                messages.success(request, f'Blocked: {ip_host_group}')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error blocking {ip_host_group}: {e.output.decode()}')

        elif action == 'unblock':
            try:
                result = subprocess.check_output(f"vuurmuur_script --unblock {ip_host_group}", shell=True).decode()
                messages.success(request, f'Unblocked: {ip_host_group}')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error unblocking {ip_host_group}: {e.output.decode()}')

    return render(request, 'blocklist.html', {'result': result})


################################################################## RULES BLOCK###################################################################################################################
@login_required

def rules(request):
    page = get_object_or_404(Page, name="rules")
    user_group = request.user.groups.first()

    # Fetch permissions for the user's group and the page
    permission = PagePermission.objects.filter(group=user_group, page=page).first()

    # If no permissions, show the no permission page
    if not permission:
        return render(request, 'no_permission.html', {'message': "You do not have permissions for this page."})

    # If the user has read-only permission, display the error on the `less_priv.html` page
    if permission.can_read and not permission.can_write:
        return render(request, 'less_priv.html', {
            'message': "You do not have permission to perform this action. Please contact the administrator."
        })
    if permission.can_write:
        if request.method == 'POST':
            selected_action = request.POST.get('selectedAction')
            selected_service = request.POST.get('selectedService')
            selected_source = request.POST.get('selectedSource')
            selected_destination = request.POST.get('selectedDestination')
            comment = request.POST.get('comment')
            in_max =  request.POST.get('in_max')
            out_max = request.POST.get('out_max')
            in_min = request.POST.get('in_min')
            out_min = request.POST.get('out_min')
            
            if all([selected_action , selected_service , selected_source , selected_destination]):
                generated_rule = f'RULE="{selected_action} service {selected_service} from {selected_source} to {selected_destination} options log,loglimit=\"30\",comment=\"good\""'
                
                # Use local configuration directory
                config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
                rules_dir = os.path.join(config_dir, 'vuurmuur', 'rules')
                os.makedirs(rules_dir, exist_ok=True)
                
                # Write to the rules.conf file
                with open(os.path.join(rules_dir, 'rules.conf'), 'a') as rules_file:
                    rules_file.write(generated_rule + '\n')

                return JsonResponse({'status': 'success', 'message': 'Rule added successfully'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid form data'})
        else:
            # Use local configuration directory
            config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
            directory_path_services = os.path.join(config_dir, 'vuurmuur', 'services')
            directory_path_zones = os.path.join(config_dir, 'vuurmuur', 'zones')
            os.makedirs(directory_path_services, exist_ok=True)
            os.makedirs(directory_path_zones, exist_ok=True)

            # Default service options
            default_services = ['http', 'https', 'ssh', 'dns', 'ftp', 'smtp', 'pop3', 'imap']
            service_options = []
            try:
                service_options = [f for f in os.listdir(directory_path_services) if os.path.isfile(os.path.join(directory_path_services, f))]
                if not service_options:
                    # Create default service files if none exist
                    for service in default_services:
                        with open(os.path.join(directory_path_services, service), 'w') as f:
                            f.write(f'# {service} service configuration\n')
                    service_options = default_services
            except Exception as e:
                service_options = default_services

            # Default zone options
            default_zones = ['lan', 'wan', 'dmz']
            source_options = []
            try:
                source_options = [f for f in os.listdir(directory_path_zones) if os.path.isdir(os.path.join(directory_path_zones, f))]
                if not source_options:
                    # Create default zone directories if none exist
                    for zone in default_zones:
                        os.makedirs(os.path.join(directory_path_zones, zone), exist_ok=True)
                    source_options = default_zones
            except Exception as e:
                source_options = default_zones

            destination_options = source_options  # Assuming the same options for source and destination
            actions = ['Accept', 'Drop', 'Reject', 'Log', 'Portfw', 'Redirect', 'Snat', 'Masq', 'Dnat', 'NFQueue', 'NFLog', 'Chain', 'Bounce']

            return render(request, 'rules.html', {
                'static_service_options': service_options,
                'static_source_options': source_options,
                'static_destination_options': destination_options,
                'static_action_options': actions
            })
    return render(request, 'no_permission.html', {'message': "You do not have permissions for this page."})
 
##################################################################SERVICE BLOCK####################################################################################################################

@login_required
@check_page_permissions('services')
def services(request):
    result = None

    if request.method == 'POST':
        command = request.POST.get('command', '')
        delete = request.POST.get('delete', '')
        old_name = request.POST.get('old_name', '')
        new_name = request.POST.get('new_name', '')

        if command:
            try:
                result = subprocess.check_output(f"vuurmuur_script -C --service {command}", shell=True).decode()
                messages.success(request, f'Service {command} created!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error creating service {command}: {e.output.decode()}')

        elif delete:
            try:
                result = subprocess.check_output(f"vuurmuur_script -D --service {delete}", shell=True).decode()
                messages.success(request, f'Service {delete} deleted!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error deleting service {delete}: {e.output.decode()}')

        elif old_name and new_name:
            try:
                result = subprocess.check_output(f"vuurmuur_script -R --service {old_name} -S {new_name}", shell=True).decode()
                messages.success(request, f'Service {old_name} renamed to {new_name}!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error renaming service {old_name} to {new_name}: {e.output.decode()}')

    return render(request, 'services.html', {'result': result})


##################################################################ZONES BLOCK###################################################################################################################

@login_required
@check_page_permissions('zones')

def zones(request):
    result = None

    if request.method == 'POST':
        command = request.POST.get('command', '')
        delete = request.POST.get('delete', '')
        old_name = request.POST.get('old_name', '')
        new_name = request.POST.get('new_name', '')
        comment_zone = request.POST.get('comment_zone', '')
        status_zone = request.POST.get('status_zone', '')
        status_message = request.POST.get('status_message', '')

        if command:
            try:
                result = subprocess.check_output(f"vuurmuur_script -C --zone {command}", shell=True).decode()
                messages.success(request, f'Zone {command} created!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error creating zone {command}: {e.output.decode()}')

        elif delete:
            try:
                result = subprocess.check_output(f"vuurmuur_script -D --zone {delete}", shell=True).decode()
                messages.success(request, f'Zone {delete} deleted!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error deleting zone {delete}: {e.output.decode()}')

        elif old_name and new_name:
            try:
                result = subprocess.check_output(f"vuurmuur_script -R --zone {old_name} -S {new_name}", shell=True).decode()
                messages.success(request, f'Zone {old_name} renamed to {new_name}!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error renaming zone {old_name} to {new_name}: {e.output.decode()}')

        elif comment_zone and status_message:
            try:
                result = subprocess.check_output(f"vuurmuur_script -M --zone {comment_zone} -V COMMENT -S '{status_message}' --overwrite", shell=True).decode()
                messages.success(request, f'Comment added to zone {comment_zone}: {status_message}')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error adding comment to zone {comment_zone}: {e.output.decode()}')

        elif status_zone and status_message:
            try:
                result = subprocess.check_output(f"vuurmuur_script -M --zone {status_zone} -V Active -S '{status_message}' --overwrite", shell=True).decode()
                messages.success(request, f'Status changed for zone {status_zone} to Active: {status_message}')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error changing status for zone {status_zone}: {e.output.decode()}')
        elif status_message:
            try:
                result = subprocess.check_output(f"vuurmuur_script -P --zone {status_message}", shell=True).decode()
                messages.success(request, f'Zone {status_message} deleted!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error in status {status_message}: {e.output.decode()}')
    return render(request, 'zones.html', {'result': result})




@login_required
@check_page_permissions('interfaces')

def interfaces(request):
    result = None

    if request.method == 'POST':
        
        
        delete = request.POST.get('delete', '')
        old_name = request.POST.get('old_name', '')
        new_name = request.POST.get('new_name', '')

        if command:
            try:
                result = subprocess.check_output(f"vuurmuur_script -C -i {command}", shell=True).decode()
                messages.success(request, f'Interface {command} created!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error creating interface {command}: {e.output.decode()}')

        elif delete:
            try:
                result = subprocess.check_output(f"vuurmuur_script -D -i {delete}", shell=True).decode()
                messages.success(request, f'Interface {delete} deleted!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error deleting interface {delete}: {e.output.decode()}')

        elif old_name and new_name:
            try:
                result = subprocess.check_output(f"vuurmuur_script -R -i {old_name} -S {new_name}", shell=True).decode()
                messages.success(request, f'Interface {old_name} renamed to {new_name}!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error renaming interface {old_name} to {new_name}: {e.output.decode()}')

    return render(request, 'interfaces.html', {'result': result})


@login_required
@check_page_permissions('services')

def checker(request):
    if request.method == 'POST':
        selected_action = request.POST.get('selectedAction')
        selected_service = request.POST.get('selectedService')
        selected_source = request.POST.get('selectedSource')
        selected_destination = request.POST.get('selectedDestination')
        
        
        if all([selected_action , selected_service , selected_source , selected_destination]):
            generated_rule = f'RULE="{selected_action} service {selected_service} from {selected_source} to {selected_destination} options log,loglimit=\"30\",comment=\"good\""'
            
            # Write to the rules.conf file
            with open('/etc/vuurmuur/rules/rules.conf', 'a') as rules_file:
                rules_file.write(generated_rule + '\n')

            return JsonResponse({'status': 'success', 'message': 'Rule added successfully'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid form data'})
        return JsonResponse(response_data)
    else:
        directory_path_services = '/etc/vuurmuur/services/'
        directory_path_zones = '/etc/vuurmuur/zones/'
        actions = ['Accept', 'Drop', 'Reject', 'Log', 'Portfw', 'Redirect', 'Snat', 'Masq', 'Dnat', 'NFQueue', 'NFLog', 'Chain', 'Bounce']

        # Get a list of file 
        service_options = [f for f in os.listdir(directory_path_services) if os.path.isfile(os.path.join(directory_path_services, f)) ]


        source_options = [f for f in os.listdir(directory_path_zones) if os.path.isdir(os.path.join(directory_path_zones, f))]
        destination_options = source_options  # Assuming the same options for source and destination

        return render(request, 'checker.html', {
            'static_service_options': service_options,
            'static_source_options': source_options,
            'static_destination_options': destination_options,
            'static_action_options': actions
        })







@login_required
@check_page_permissions('log')

def log(request):
    log_type = request.GET.get('log_type')

    if not log_type:
        return render(request, 'log.html', {'error': 'Log type not specified'})

    try:
        if log_type == 'traffic':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/traffic.log"], universal_newlines=True)
        elif log_type == 'connection':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/connections.log"], universal_newlines=True)
        elif log_type == 'connNew':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/connnew.log"], universal_newlines=True)
        elif log_type == 'vuurmuur':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/vuurmuur.log"], universal_newlines=True)
        elif log_type == 'audit':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/audit.log"], universal_newlines=True)
        elif log_type == 'error':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/error.log"], universal_newlines=True)
        elif log_type == 'debug':
            result = subprocess.check_output(["cat", "/var/log/vuurmuur/debug.log"], universal_newlines=True)
        else:
            return render(request, 'log.html', {'error': 'Invalid log type'})
        
        return render(request, 'log.html', {'output': result, 'log_type': log_type})
    except subprocess.CalledProcessError as e:
        return render(request, 'log.html', {'error': f'Error executing subprocess: {str(e)}', 'log_type': log_type})
    except Exception as e:
        return render(request, 'log.html', {'error': f'Unexpected error: {str(e)}', 'log_type': log_type})

@login_required
@check_page_permissions('apply')

def apply(request):
    if request.method == 'POST':
        apply = request.POST.get('apply', '')
        reload_apply = request.POST.get('reload_apply', '')


        if apply:  

            try:
                result = subprocess.check_output(f"vuurmuur_script --apply", shell=True).decode()
                messages.success(request, f'Changes applied')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error in applying changes')

        elif reload_apply:
            try:
                result = subprocess.check_output(f"systemctl start vuurmuur", shell=True).decode()
                messages.success(request, f'Reloaded and applied!')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error in reloading and applying {e.output.decode()}')


    return render(request, 'apply.html')

@login_required
@check_page_permissions('config')

def config(request):
    if request.method == 'POST':
        new_interval = request.POST.get('new_interval')
        log_no_syn = request.POST.get('log_no_syn')
        if new_interval:
            
            subprocess.run(['sudo', 'sed', '-i', f's/DYN_INT_INTERVAL="[0-9]*"/DYN_INT_INTERVAL="{new_interval}"/g', '/etc/vuurmuur/config.conf'])

            return JsonResponse({'message': 'Interval updated successfully'})
        # elif log_no_syn:
        #      subprocess.run(['sudo', 'sed', '-i', f's/LOG_NO_SYN="[^"]*"/LOG_NO_SYN="{log_no_syn}"/g', '/etc/vuurmuur/config.conf'])
        #     return JsonResponse({'message': 'updated successfully'})

        else:
            return JsonResponse({'error': 'Invalid data'})
    else:
        return render(request, 'config.html')
    
@login_required
@check_page_permissions('capabilities')

def capabilities(request):
    return render(request, 'capabilities.html')

@login_required
@check_page_permissions('plugins')

def plugins(request):
    if request.method == 'POST':
        service_backend = request.POST.get('service_backend')
        zones_backend = request.POST.get('zones_backend')
        interfaces_backend = request.POST.get('interfaces_backend')
        rules_backend = request.POST.get('rules_backend')

        if service_backend:
            subprocess.run(['sudo', 'sed', '-i', f's/SERVICES_BACKEND="[^"]*"/SERVICES_BACKEND="{service_backend}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        elif zones_backend:
            subprocess.run(['sudo', 'sed', '-i', f's/ZONES_BACKEND="[^"]*"/ZONES_BACKEND="{zones_backend}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        elif interfaces_backend:
            subprocess.run(['sudo', 'sed', '-i', f's/INTERFACES_BACKEND="[^"]*"/INTERFACES_BACKEND="{interfaces_backend}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        elif rules_backend:
            subprocess.run(['sudo', 'sed', '-i', f's/RULES_BACKEND="[^"]*"/RULES_BACKEND="{rules_backend}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

    return render(request, 'plugins.html')

@login_required
@check_page_permissions('modules')

def modules(request):
    if request.method == 'POST':
        load_modules = request.POST.get('load_modules')
        waittime = request.POST.get('waittime')

        if load_modules:
            subprocess.run(['sudo', 'sed', '-i', f's/LOAD_MODULES="[^"]*"/LOAD_MODULES="{load_modules}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        elif waittime:
            subprocess.run(['sudo', 'sed', '-i', f's/MODULES_WAIT_TIME="[^"]*"/MODULES_WAIT_TIME="{waittime}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})
    return render(request, 'modules.html')

@login_required
@check_page_permissions('logging')

def logging(request):
    if request.method == 'POST':
        netfilter = request.POST.get('netfilter')
        log_policy = request.POST.get('log_policy')
        log_policy_limit = request.POST.get('log_policy_limit')
        log_blocklist = request.POST.get('log_blocklist')
        log_invalid = request.POST.get('log_invalid')
        log_no_syn = request.POST.get('log_no_syn')
        log_probes = request.POST.get('log_probes')
        log_frag = request.POST.get('log_frag')

        # Update netfilter group
        if netfilter:
            subprocess.run(['sudo', 'sed', '-i', f's/NFGRP="[^"]*"/NFGRP="{netfilter}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_policy
        elif log_policy:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_POLICY="[^"]*"/LOG_POLICY="{log_policy}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_policy_limit
        elif log_policy_limit:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_POLICY_LIMIT="[0-9]*"/LOG_POLICY_LIMIT="{log_policy_limit}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_blocklist
        elif log_blocklist:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_BLOCKLIST="[^"]*"/LOG_BLOCKLIST="{log_blocklist}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_invalid
        elif log_invalid:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_INVALID="[^"]*"/LOG_INVALID="{log_invalid}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_no_syn
        elif log_no_syn:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_NO_SYN="[^"]*"/LOG_NO_SYN="{log_no_syn}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_probes
        elif log_probes:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_PROBES="[^"]*"/LOG_PROBES="{log_probes}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update log_frag
        elif log_frag:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_FRAG="[^"]*"/LOG_FRAG="{log_frag}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

    return render(request, 'logging.html')

@login_required
@check_page_permissions('conntrack')
def conntrack(request):
    if request.method == 'POST':
        drop_invalid = request.POST.get('drop_invalid')
        conntrack_accounting = request.POST.get('conntrack_accounting')

        # Update drop_invalid
        if drop_invalid:
            subprocess.run(['sudo', 'sed', '-i', f's/DROP_INVALID="[^"]*"/DROP_INVALID="{drop_invalid}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update conntrack_accounting
        elif conntrack_accounting:
            subprocess.run(['sudo', 'sed', '-i', f's/CONNTRACK_ACCOUNTING="[^"]*"/CONNTRACK_ACCOUNTING="{conntrack_accounting}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

    return render(request, 'conntrack.html')

@login_required
@check_page_permissions('system_protection')

def system_protection(request):
    if request.method == 'POST':
        protect_syncookie = request.POST.get('protect_syncookie')
        protect_echobroadcast = request.POST.get('protect_echobroadcast')

        # Update protect_syncookie
        if protect_syncookie:
            subprocess.run(['sudo', 'sed', '-i', f's/PROTECT_SYNCOOKIE="[^"]*"/PROTECT_SYNCOOKIE="{protect_syncookie}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update protect_echobroadcast
        elif protect_echobroadcast:
            subprocess.run(['sudo', 'sed', '-i', f's/PROTECT_ECHOBROADCAST="[^"]*"/PROTECT_ECHOBROADCAST="{protect_echobroadcast}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

    return render(request, 'system_protection.html')

@login_required
@check_page_permissions('interface2')

def interface2(request):
    if request.method == 'POST':
        dyn_int_check = request.POST.get('dyn_int_check')
        dyn_int_interval = request.POST.get('dyn_int_interval')

        # Update dyn_int_check
        if dyn_int_check:
            subprocess.run(['sudo', 'sed', '-i', f's/DYN_INT_CHECK="[^"]*"/DYN_INT_CHECK="{dyn_int_check}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update dyn_int_interval
        elif dyn_int_interval:
            subprocess.run(['sudo', 'sed', '-i', f's/DYN_INT_INTERVAL="[^"]*"/DYN_INT_INTERVAL="{dyn_int_interval}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

    return render(request, 'interface2.html')

@login_required
@check_page_permissions('connections')

def connections(request):
    if request.method == 'POST':
        log_no_syn = request.POST.get('log_no_syn')
        use_syn_limit = request.POST.get('use_syn_limit')
        syn_limit = request.POST.get('syn_limit')
        syn_limit_burst = request.POST.get('syn_limit_burst')
        use_udp_limit = request.POST.get('use_udp_limit')
        udp_limit = request.POST.get('udp_limit')
        udp_limit_burst = request.POST.get('udp_limit_burst')

        # Update log_no_syn
        if log_no_syn:
            subprocess.run(['sudo', 'sed', '-i', f's/LOG_NO_SYN="[^"]*"/LOG_NO_SYN="{log_no_syn}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update SYN rate limiting
        elif use_syn_limit and syn_limit and syn_limit_burst:
            subprocess.run(['sudo', 'sed', '-i', f's/USE_SYN_LIMIT="[^"]*"/USE_SYN_LIMIT="{use_syn_limit}"/g', '/etc/vuurmuur/config.conf'])
            subprocess.run(['sudo', 'sed', '-i', f's/SYN_LIMIT="[^"]*"/SYN_LIMIT="{syn_limit}"/g','/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

        # Update UDP rate limiting
        elif use_udp_limit and udp_limit and udp_limit_burst:
            subprocess.run(['sudo', 'sed', '-i', f's/USE_UDP_LIMIT="[^"]*"/USE_UDP_LIMIT="{use_udp_limit}"/g', '/etc/vuurmuur/config.conf'])
            subprocess.run(['sudo', 'sed', '-i', f's/UDP_LIMIT="[^"]*"/UDP_LIMIT="{udp_limit}"/g', '/etc/vuurmuur/config.conf'])
            subprocess.run(['sudo', 'sed', '-i', f's/UDP_LIMIT_BURST="[^"]*"/UDP_LIMIT_BURST="{udp_limit_burst}"/g', '/etc/vuurmuur/config.conf'])
            return JsonResponse({'message': 'Updated successfully'})

    return render(request, 'connections.html')

####################################SNMP######################################################################################3

from django.shortcuts import render
from django.http import HttpResponse
from subprocess import run, PIPE
@login_required
@check_page_permissions('interface2')

def update_snmp_config(location, contact):
    config_file_path = "/etc/snmp/snmpd.conf"
    new_config_lines = []

    # Read existing configuration and update sysLocation and sysContact
    with open(config_file_path, 'r') as file:
        for line in file:
            if line.startswith('sysLocation'):
                line = f"sysLocation    {location}\n"
            elif line.startswith('sysContact'):
                line = f"sysContact     {contact}\n"
            new_config_lines.append(line)

    # Write updated configuration back to file
    with open(config_file_path, 'w') as file:
        file.writelines(new_config_lines)

def start_snmp_service():
    result = run(["systemctl", "restart", "snmpd.service"], stdout=PIPE, stderr=PIPE) 

    if result.returncode != 0:
        # Handle error
        print("Failed to start SNMP service:", result.stderr.decode('utf-8'))

@login_required
@check_page_permissions('snmp')
def snmp_config(request):
    if request.method == 'POST':
        enable_snmp = request.POST.get('enable_snmp')
        location = request.POST.get('location')
        contact = request.POST.get('contact')

        if enable_snmp:
            start_snmp_service()

        update_snmp_config(location, contact)

        return render(request, 'snmp.html', {'location': location, 'contact': contact})
    elif request.method == 'GET':
        # Handle GET request (e.g., display form)
        return render(request, 'snmp.html')  
    else:
        return HttpResponse("Method Not Allowed", status=405)


# import os
# from django.shortcuts import render
# from django.views.decorators.http import require_POST
# import subprocess

# # Global variable to hold the subprocess
# running_process = None
# exit_signal_file = "/tmp/network_monitor_exit_signal"

# def pie(request):
#     global running_process

#     if request.method == 'POST':
#         form = request.POST
#         dpi_service = form.get('dpiService')
#         interface = form.get('interface')
#         ip = form.get('ip')
#         port = form.get('port')

#         if dpi_service == 'enabled':
#             if running_process is None or running_process.poll() is not None:
#                 # Start the script as a subprocess
#                 script_content = f"""
# #!/bin/bash

# trap 'rm -f {exit_signal_file}' EXIT

# while true; do
#     if [ -f {exit_signal_file} ]; then
#         break
#     fi

#     ndpiReader -i {interface} -k /tmp/ndpi1.json -s 10
#     ndpiReader -i {interface} -k /tmp/ndpi2.json -s 10

#     hostname=$(hostname)
#     timestamp=$(date)

#     jq --arg hostname "$hostname" --arg timestamp "$timestamp" \\
#        '. + {{hostname: $hostname, timestamp: $timestamp, index: {{"_index": "in500testing"}}}}' /tmp/ndpi1.json \\
#        | jq -c '. | {{"index": {{"_index": "in500testing"}}}}, .' > /tmp/ndpi1_with_index.json

#     jq --arg hostname "$hostname" --arg timestamp "$timestamp" \\
#        '. + {{hostname: $hostname, timestamp: $timestamp, index: {{"_index": "in500testing"}}}}' /tmp/ndpi2.json \\
#        | jq -c '. | {{"index": {{"_index": "in500testing"}}}}, .' > /tmp/ndpi2_with_index.json

#     curl -s -H "Content-Type: application/x-ndjson" -XPOST "http://{ip}:{port}/_bulk" \\
#          --data-binary @/tmp/ndpi1_with_index.json
#     curl -s -H "Content-Type: application/x-ndjson" -XPOST "http://{ip}:{port}/_bulk" \\
#          --data-binary @/tmp/ndpi2_with_index.json

    
# done &>> /tmp/network_monitor.log
#                 """

#                 # Ensure the exit signal file does not exist
#                 if os.path.exists(exit_signal_file):
#                     os.remove(exit_signal_file)

#                 # Start the subprocess
#                 running_process = subprocess.Popen(['bash', '-c', script_content], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

#                 return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Script started.'})
#             else:
#                 return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Script is already running.'})
#         elif dpi_service == 'disabled':
#             if running_process and running_process.poll() is None:
#                 # Create the exit signal file
#                 with open(exit_signal_file, 'w') as f:
#                     f.write('exit')

#                 # Terminate the subprocess if it is running
#                 running_process.terminate()
#                 running_process = None
#                 return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Script terminated and exit signal sent.'})
#             else:
#                 return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'No script running.'})
#         else:
#             return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Invalid dpiService value.'})

#     # For non-POST requests, just show the form
#     return render(request, 'pie.html', {'interfaces': get_network_interfaces()})

# def get_network_interfaces():
#     # Function to fetch available network interfaces from /sys/class/net
#     return os.listdir('/sys/class/net')








import os
import subprocess
from django.shortcuts import render
from django.views.decorators.http import require_POST

running_process = None
exit_signal_file = "/tmp/network_monitor_exit_signal"
@login_required
@check_page_permissions('pie')

def pie(request):
    global running_process

    has_full_access = request.user.groups.filter(name='Full Access').exists()


    if request.method == 'POST':
        form = request.POST
        dpi_service = form.get('dpiService')
        interfaces = form.getlist('interface')  # Allow multiple interfaces
        ip = form.get('ip')
        port = form.get('port')

        # Validate IP address and port if the DPI service is enabled
        if dpi_service == 'enabled':
            if not ip or not port:
                return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'IP and Port are required.', 'message_type': 'error'})

            try:
                # Validate IP address format
                ip_parts = [int(part) for part in ip.split('.')]
                if len(ip_parts) != 4 or not all(0 <= part < 256 for part in ip_parts):
                    raise ValueError("Invalid IP address")

                # Validate port range
                port_number = int(port)
                if not 1 <= port_number <= 65535:
                    raise ValueError("Invalid port number")
            except ValueError:
                return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Enter a valid IP and port number.', 'message_type': 'error'})

            if running_process is None or running_process.poll() is not None:
                # Prepare script content with multiple interfaces
                interfaces_str = ' '.join(f"-i {interface}" for interface in interfaces)
                script_content = f"""
#!/bin/bash

trap 'rm -f {exit_signal_file}' EXIT

while true; do
    if [ -f {exit_signal_file} ]; then
        break
    fi

    ndpiReader {interfaces_str} -k /tmp/ndpi1.json -s 10
    ndpiReader {interfaces_str} -k /tmp/ndpi2.json -s 10

    hostname=$(hostname)
    timestamp=$(date)

    jq --arg hostname "$hostname" --arg timestamp "$timestamp" '. + {{hostname: $hostname, timestamp: $timestamp}}' /tmp/ndpi1.json | jq -c '. | {{"index": {{"_index": "in500testing"}}}}, .' > /tmp/ndpi1_with_index.json
    jq --arg hostname "$hostname" --arg timestamp "$timestamp" '. + {{hostname: $hostname, timestamp: $timestamp}}' /tmp/ndpi2.json | jq -c '. | {{"index": {{"_index": "in500testing"}}}}, .' > /tmp/ndpi2_with_index.json

    curl -s -H "Content-Type: application/x-ndjson" -XPOST "http://{ip}:{port}/_bulk" --data-binary @/tmp/ndpi1_with_index.json
    curl -s -H "Content-Type: application/x-ndjson" -XPOST "http://{ip}:{port}/_bulk" --data-binary @/tmp/ndpi2_with_index.json

done &>> /tmp/network_monitor.log
                """

                # Ensure the exit signal file does not exist
                if os.path.exists(exit_signal_file):
                    os.remove(exit_signal_file)

                # Start the subprocess
                running_process = subprocess.Popen(['bash', '-c', script_content], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Dpi started successfully.', 'message_type': 'success'})
            else:
                return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Dpi is already running.', 'message_type': 'error'})

        elif dpi_service == 'disabled':
            if running_process and running_process.poll() is None:
                # Create the exit signal file
                with open(exit_signal_file, 'w') as f:
                    f.write('exit')

                # Terminate the subprocess if it is running
                running_process.terminate()
                running_process = None
                return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Dpi terminated.', 'message_type': 'success'})
            else:
                return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'No Dpi running.', 'message_type': 'error'})

        else:
            return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'message': 'Invalid DPI service value.', 'message_type': 'error'})

    # For non-POST requests, just show the form
    print(f"User groups: {request.user.groups.all()}")
    print(f"Has Full Access: {has_full_access}")

    return render(request, 'pie.html', {'interfaces': get_network_interfaces(), 'has_full_access': has_full_access})


def get_network_interfaces():
    # Function to fetch available network interfaces from /sys/class/net
    return os.listdir('/sys/class/net')












    

# views.py
import re
from django.shortcuts import render
# import re
# from django.shortcuts import render
# import re
# from django.shortcuts import render

# def rulesfig(request):
#     file_path = '/etc/vuurmuur/rules/rules.conf'  # Update with your file path

#     # Read the file and extract information from each rule
#     with open(file_path, 'r') as file:
#         file_content = file.read()

#     # Define regular expressions for each keyword
#     action_pattern = re.compile(r'="(\w+)', re.IGNORECASE)
#     service_pattern = re.compile(r'service (\w+)', re.IGNORECASE)
#     source_pattern = re.compile(r'from (\w+)', re.IGNORECASE)
#     destination_pattern = re.compile(r'to (\w+)', re.IGNORECASE)
#     options_pattern = re.compile(r'options (.+)$', re.IGNORECASE)

#     # Split content into individual rules
#     rules = file_content.split('\n')

#     all_rules_info = []
#     for rule in rules:
#         # Extract keywords from each rule
#         action_match = action_pattern.search(rule)
#         service_match = service_pattern.search(rule)
#         source_match = source_pattern.search(rule)
#         destination_match = destination_pattern.search(rule)
#         options_match = options_pattern.search(rule)

#         # Prepare data for the current rule
#         rule_info = {
#             'action': action_match.group(1) if action_match else '',
#             'service_name': service_match.group(1) if service_match else '',
#             'source': source_match.group(1) if source_match else '',
#             'destination': destination_match.group(1) if destination_match else '',
#             'options': options_match.group(1) if options_match else ''
#         }

#         all_rules_info.append(rule_info)

#     # Add rule numbers to the rule information
#     all_rules_info_with_numbers = [(index + 1, rule_info) for index, rule_info in enumerate(all_rules_info)]

#     if request.method == 'POST':
#         delete_rule_numbers = request.POST.getlist('delete_rule')
#         print("Delete Rule Numbers:", delete_rule_numbers)  # Debug statement
#         if delete_rule_numbers:
#             # Read the file content
#             with open(file_path, 'r') as file:
#                 lines = file.readlines()

#             # Write the non-deleted lines back to the file
#             with open(file_path, 'w') as file:
#                 for index, line in enumerate(lines, start=1):
#                     if str(index) not in delete_rule_numbers:
#                         file.write(line)
#                     else:
#                         print("Deleted Rule:", line.strip())  # Debug statement

#             # Reload the rules after deletion
#             return render(request, 'rulesfig.html', {'rules': all_rules_info_with_numbers})

#     return render(request, 'rulesfig.html', {'rules': all_rules_info_with_numbers})













import re
from django.shortcuts import render
from django.http import JsonResponse
import os
@login_required
@check_page_permissions('rulesfig')

def rulesfig(request):
    file_path = '/etc/vuurmuur/rules/rules.conf'  # Update with your file path

    # Read the file and extract information from each rule
    with open(file_path, 'r') as file:
        file_content = file.read()

    # Define regular expressions for each keyword
    action_pattern = re.compile(r'="(\w+)', re.IGNORECASE)
    service_pattern = re.compile(r'service (\w+)', re.IGNORECASE)
    source_pattern = re.compile(r'from (\w+)', re.IGNORECASE)
    destination_pattern = re.compile(r'to (\w+)', re.IGNORECASE)
    options_pattern = re.compile(r'options (.+)$', re.IGNORECASE)

    # Split content into individual rules
    rules = file_content.split('\n')

    all_rules_info = []
    for rule in rules:
        # Extract keywords from each rule
        action_match = action_pattern.search(rule)
        service_match = service_pattern.search(rule)
        source_match = source_pattern.search(rule)
        destination_match = destination_pattern.search(rule)
        options_match = options_pattern.search(rule)

        # Prepare data for the current rule
        rule_info = {
            'action': action_match.group(1) if action_match else '',
            'service_name': service_match.group(1) if service_match else '',
            'source': source_match.group(1) if source_match else '',
            'destination': destination_match.group(1) if destination_match else '',
            'options': options_match.group(1) if options_match else '',
            'raw': rule  # Save the raw rule for easy reordering
        }

        # Exclude empty rules
        if any(rule_info.values()):
            all_rules_info.append(rule_info)

    # Add rule numbers to the rule information
    all_rules_info_with_numbers = [(index + 1, rule_info) for index, rule_info in enumerate(all_rules_info)]

    if request.method == 'POST':
        delete_rule_numbers = request.POST.getlist('delete_rule')
        reordered_ids = request.POST.getlist('order[]')

        # Handle deletion
        if delete_rule_numbers:
            all_rules_info_with_numbers = [
                (index + 1, rule_info) 
                for index, (number, rule_info) in enumerate(all_rules_info_with_numbers) 
                if str(number) not in delete_rule_numbers
            ]
            # Write the non-deleted lines back to the file
            with open(file_path, 'w') as file:
                for _, rule_info in all_rules_info_with_numbers:
                    file.write(rule_info['raw'] + '\n')

        # Handle reordering
        if reordered_ids:
            reordered_rules = []
            for rule_id in reordered_ids:
                for number, rule_info in all_rules_info_with_numbers:
                    if str(number) == rule_id:
                        reordered_rules.append(rule_info['raw'])
                        break

            # Write the reordered rules back to the file
            with open(file_path, 'w') as file:
                for rule in reordered_rules:
                    file.write(rule + '\n')

        return JsonResponse({'status': 'success'})

    return render(request, 'rulesfig.html', {'rules': all_rules_info_with_numbers})

























# import re
# from django.shortcuts import render

# def rulesfig(request):
#     file_path = '/etc/vuurmuur/rules/rules.conf'  # Update with your file path

#     # Read the file and extract information from each rule
#     with open(file_path, 'r') as file:
#         file_content = file.read()

#     # Define regular expressions for each keyword
#     action_pattern = re.compile(r'="(\w+)', re.IGNORECASE)
#     service_pattern = re.compile(r'service (\w+)', re.IGNORECASE)
#     source_pattern = re.compile(r'from (\w+)', re.IGNORECASE)
#     destination_pattern = re.compile(r'to (\w+)', re.IGNORECASE)
#     options_pattern = re.compile(r'options (.+)$', re.IGNORECASE)

#     # Split content into individual rules
#     rules = file_content.split('\n')

#     all_rules_info = []
#     for rule in rules:
#         # Extract keywords from each rule
#         action_match = action_pattern.search(rule)
#         service_match = service_pattern.search(rule)
#         source_match = source_pattern.search(rule)
#         destination_match = destination_pattern.search(rule)
#         options_match = options_pattern.search(rule)

#         # Prepare data for the current rule
#         rule_info = {
#             'action': action_match.group(1) if action_match else '',
#             'service_name': service_match.group(1) if service_match else '',
#             'source': source_match.group(1) if source_match else '',
#             'destination': destination_match.group(1) if destination_match else '',
#             'options': options_match.group(1) if options_match else ''
#         }

#         # Exclude empty rules
#         if any(rule_info.values()):
#             all_rules_info.append(rule_info)

#     # Add rule numbers to the rule information
#     all_rules_info_with_numbers = [(index + 1, rule_info) for index, rule_info in enumerate(all_rules_info)]

#     if request.method == 'POST':
#         delete_rule_numbers = request.POST.getlist('delete_rule')
#         move_rule_number = request.POST.get('move_rule')

#         if delete_rule_numbers:
#             # Read the file content
#             with open(file_path, 'r') as file:
#                 lines = file.readlines()

#             # Write the non-deleted lines back to the file
#             with open(file_path, 'w') as file:
#                 for index, line in enumerate(lines, start=1):
#                     if str(index) not in delete_rule_numbers:
#                         file.write(line)
#                     else:
#                         print("Deleted Rule:", line.strip())  # Debug statement

#             # Reload the rules after deletion


#         if move_rule_number:
#             new_position = int(request.POST.get('new_position'))
#             if new_position != int(move_rule_number):
#                 move_rule_index = int(move_rule_number) - 1
#                 moved_rule = all_rules_info_with_numbers.pop(move_rule_index)
#                 if new_position > move_rule_index:
#                     all_rules_info_with_numbers.insert(new_position - 1, moved_rule)
#                 else:
#                     all_rules_info_with_numbers.insert(new_position, moved_rule)

#         # Reload the rules after any changes
#         return render(request, 'rulesfig.html', {'rules': all_rules_info_with_numbers})

#     return render(request, 'rulesfig.html', {'rules': all_rules_info_with_numbers})







####################################################ROUTING######################################################################################





import subprocess
from django.shortcuts import render, redirect
@login_required
@check_page_permissions('routing')
def routing(request):
    routing_table = []
    traceroute_output = None
    ping_output = None

    # Get routing information using subprocess with ip route
    route_output = subprocess.run(['ip', 'route'], capture_output=True, text=True).stdout

    # Parse routing information
    if route_output:
        lines = route_output.split('\n')
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    route = {
                        'destination': parts[0],
                        'via': parts[2] if 'via' in parts else '',
                        'dev': parts[-1] if 'dev' in parts else '',
                        'flags': ' '.join(parts[1:-1]) if len(parts) > 3 else '',
                    }
                    routing_table.append(route)

    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'add_route':
            destination = request.POST.get('destination')
            netmask = request.POST.get('netmask')
            gateway = request.POST.get('gateway')
            if destination and netmask and gateway:
                subprocess.run(['sudo', 'ip', 'route', 'add', f'{destination}/{netmask}', 'via', gateway])
            return redirect('routing')
        
        elif action == 'delete_route':
            destination = request.POST.get('destination')
            netmask = request.POST.get('netmask')
            gateway = request.POST.get('gateway')
            if destination and netmask and gateway:
                subprocess.run(['sudo', 'ip', 'route', 'del', f'{destination}/{netmask}', 'via', gateway])
            return redirect('routing')
        
        elif action == 'traceroute':
            target = request.POST.get('target')
            if target:
                print("Please wait, we are processing...")
                traceroute_output = subprocess.run(['traceroute', target], capture_output=True, text=True).stdout

    return render(request, 'routing.html', {
        'routing_table': routing_table,
        'traceroute_output': traceroute_output,
    })


@login_required
@check_page_permissions('terminal')

def terminal(request):
    # Start the ttyd process if not already running
    if not subprocess.run(['pgrep', 'ttyd'], capture_output=True).stdout:
        subprocess.Popen(['ttyd', '-W', 'vtysh'])
    
    
    return render(request, 'terminal.html')



#####################################################IPSEC#######################################


from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
import subprocess
import re
import secrets


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
        
        # Check for start of connections section
        if line.startswith('connections'):
            continue
        
        # Detect start of a new connection block
        elif line.endswith('{') and not in_connection:
            in_connection = True
            connection_name = line.split()[0]
            connection = {'name': connection_name, 'local_address': '', 'remote_address': '', 'status': 'inactive'}
        
        # Detect end of a connection block
        elif line == '}' and in_connection:
            in_connection = False
            connections.append(connection)
            connection = {}
        
        # Parse key-value pairs within the connection block
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

@login_required
@check_page_permissions('ipsec')

def ipsec(request):
    result = None
    active_status_line = None
    inactive_status_line = None
    service_status = None

    if request.method == 'POST':
        action = request.POST.get('action', '')

        if action == 'enable_service':
            try:
                subprocess.check_output("sudo systemctl start ipsec", shell=True)
                messages.success(request, 'IPsec service enabled successfully.')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error enabling IPsec service: {e.output.decode()}')
        
        elif action == 'disable_service':
            try:
                subprocess.check_output("sudo systemctl stop ipsec", shell=True)
                messages.success(request, 'IPsec service disabled successfully.')
            except subprocess.CalledProcessError as e:
                messages.error(request, f'Error disabling IPsec service: {e.output.decode()}')
        
        elif action in ['add_connection', 'edit_connection']:
            name = request.POST['name']
            local_address = request.POST['local_address']
            remote_address = request.POST['remote_address']
            encryption_algorithm = request.POST.get('encryption_algorithm')
            key_length = request.POST.get('key_length')
            hash_algo = request.POST.get('hash')
            dh_group = request.POST.get('dh_group')
            local_auth = request.POST.get('local_auth', 'psk')
            local_id = request.POST.get('local_id', local_address)
            remote_auth = request.POST.get('remote_auth', 'psk')
            remote_id = request.POST.get('remote_id', remote_address)
            ike_version = request.POST.get('ike_version', 'IKEv2')
            psk = request.POST.get('psk', '')

            # Certificate fields
            authentication_method = request.POST.get('authentication_method', 'psk')  # Could be 'Mutual PSK' or 'Mutual Certificate'
            my_certificate = request.POST.get('my_certificate', '')
            myca_certificate = request.POST.get('myca_certificate', '')
            private_key = request.POST.get('private_key', '')

            local_ts = request.POST.get('local_traffic_selector')
            remote_ts = request.POST.get('remote_traffic_selector')

            version = '1' if ike_version == 'IKEv1' else '2'
            proposals = format_proposals(encryption_algorithm, key_length, hash_algo, dh_group) if encryption_algorithm and key_length and hash_algo and dh_group else 'aes256-sha2_256-modp2048'

            # Basic validation
            if not name or not local_address or not remote_address:
                messages.error(request, 'All fields are required to add/edit a connection.')
            else:
                conf = read_swanctl_conf()
                new_conf_lines = []
                connections_added = False

                in_connection = False
                for line in conf.splitlines():
                    if line.strip().startswith(f'{name} {{'):
                        in_connection = True
                    if not in_connection:
                        new_conf_lines.append(line)
                    if in_connection and line.strip() == '}':
                        in_connection = False
                        connections_added = True
                        continue

                # Add the new or edited connection
                if authentication_method == 'Mutual Certificate':
                    new_connection = f"""
{name} {{
    version = {version}
    local_addrs = {local_address}
    remote_addrs = {remote_address}
    local {{
        auth = pubkey
        certs = {my_certificate}
        id = {local_id}
    }}
    remote {{
        auth = pubkey
        id = {remote_id}
    }}
    children {{
        vpn {{
            mode = tunnel
            local_ts = {local_ts}
            remote_ts = {remote_ts}
            dpd_action = start
            start_action = start
            esp_proposals = aes256-sha2_256
        }}
    }}
}}"""
                    # Add secrets and authority blocks for certificates
                    secret_block = f"""
secrets {{
    private {{
        file = {private_key}
    }}
}}
authorities {{
    myca {{
        cacert = {myca_certificate}
    }}
}}"""
                    new_conf_lines.append(new_connection.strip())
                    new_conf_lines.append(secret_block.strip())

                else:  # PSK configuration (existing logic)
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
        auth = {local_auth}
        id = {local_id}
    }}
    remote {{
        auth = {remote_auth}
        id = {remote_id}
    }}
    children {{
        vpn {{
            mode = tunnel
            local_ts = {local_ts}
            remote_ts = {remote_ts}
            dpd_action = start
            start_action = start
            esp_proposals = aes256-sha2_256
        }}
    }}
}}"""
                    # PSK block
                    secret_block = f"""
secrets {{
    ike-1 {{
        id-1 = {local_address}
        id-2 = {remote_address}
        secret = {psk}
    }}
}}"""
                    new_conf_lines.append(new_connection.strip())
                    new_conf_lines.append(secret_block.strip())

                write_swanctl_conf('\n'.join(new_conf_lines).strip())

                subprocess.run(['swanctl', '--load-all'])
                messages.success(request, f'Connection {"edited" if action == "edit_connection" else "added"} successfully.')


        elif action == 'delete_connection':
            connection_name = request.POST['connection_name']
            conf = read_swanctl_conf()
            new_conf_lines = []
            skip = False
            for line in conf.splitlines():
                if line.strip().startswith(f'{connection_name} {{'):
                    skip = True
                if not skip:
                    new_conf_lines.append(line)
                if skip and line.strip() == "}":
                    skip = False

            write_swanctl_conf('\n'.join(new_conf_lines).strip())

            subprocess.run(['swanctl', '--load-all'])
            messages.success(request, 'Connection deleted successfully.')

        elif action == 'toggle_connection':
            connection_name = request.POST['connection_name']
            try:
                subprocess.check_output(f"swanctl --unload-conn {connection_name}", shell=True)
                messages.success(request, f'Connection {connection_name} disabled successfully.')
            except subprocess.CalledProcessError as e:
                try:
                    subprocess.check_output(f"swanctl --load-conn {connection_name}", shell=True)
                    messages.success(request, f'Connection {connection_name} enabled successfully.')
                except subprocess.CalledProcessError as e:
                    messages.error(request, f'Error toggling connection {connection_name}: {e.output.decode()}')

    try:
        status_output = subprocess.check_output("sudo systemctl status ipsec", shell=True, stderr=subprocess.STDOUT).decode().strip()
    except subprocess.CalledProcessError as e:
        status_output = e.output.decode().strip()

    active_match = re.search(r'Active: active \(running\) since .+ ago', status_output)
    inactive_match = re.search(r'Active: inactive \(dead\) since .+ ago', status_output)

    if active_match:
        active_status_line = active_match.group(0)
        service_status = 'active'
    elif inactive_match:
        inactive_status_line = inactive_match.group(0)
        service_status = 'inactive'
    else:
        service_status = 'unknown'

    connections = parse_swanctl_conf()
    for connection in connections:
        connection['status'] = 'inactive'

    return render(request, 'ipsec.html', {
        'result': result,
        'service_status': service_status,
        'active_status_line': active_status_line,
        'inactive_status_line': inactive_status_line,
        'connections': connections,
    })

def get_ipsec_options(request):
    # Fixed list of encryption algorithms
    encryption_algorithms = [
        "AES128",
        "AES192",
        "AES256",
        "AES16-GCM",
        "AES12-GCM",
        "AES8-GCM",
        "AES16-CCM",
        "AES12-CCM",
        "AES8-CCM",
        "CHACHA20_POLY1305"
    ]
    
    # Key lengths for the specified encryption algorithms
    key_lengths = {
        "AES128": [128, 96, 64],
        "AES192": [128, 96, 64],
        "AES256": [128, 96, 64],
        "AES16-GCM": [256, 192, 128],
        "AES12-GCM": [256, 192, 128],
        "AES8-GCM": [256, 192, 128],
        "AES16-CCM": [256, 192, 128],
        "AES12-CCM": [256, 192, 128],
        "AES8-CCM": [256, 192, 128],
        "CHACHA20_POLY1305": [256]
    }

    # Hash options
    hash_options = [
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512"
    ]

    # DH group options
    dh_groups = [
        "MODP3072",
        "MODP4096",
        "MODP6144",
        "MODP8192",
        "MODP2048",
        "MODP1024",
        "MODP768",
        "CURVE25519",
        "CURVE448",
        "ECP_256",
        "ECP_384",
        "ECP_521",
        "ECP_224",
        "ECP_192"
    ]

    options = {
        'encryption_algorithms': encryption_algorithms,
        'key_lengths': key_lengths,
        'hash_options': hash_options,
        'dh_groups': dh_groups
    }

    return JsonResponse(options)

def generate_psk(request):
    psk = secrets.token_urlsafe(56)
    return JsonResponse({'psk': psk})

def save_ike2_certificate(request):
    # Implementation of save_ike2_certificate based on your requirements
    return JsonResponse({'status': 'success'})



###################################################### LINK Switch ###############################




from django.shortcuts import render
from django.http import JsonResponse
# import pandas as pd
from datetime import datetime, timedelta

# Constants
MAX_DURATION = 60  # Maximum duration in minutes
LOSS_FILE_LTE1 = "path/to/LTE1_pckt_loss.csv"
LOSS_FILE_LTE2 = "path/to/LTE2_pckt_loss.csv"
PARAMS_FILE_LTE1 = "path/to/LTE1_parameters.csv"
PARAMS_FILE_LTE2 = "path/to/LTE2_parameters.csv"

# View to render the link conditions page
@login_required
@check_page_permissions('link_conditions')

def link_conditions(request):
    return render(request, 'link_conditions.html')

# View to fetch data for the graph and RF parameters
def get_link_data(request):
    try:
        duration = int(request.GET.get('duration', MAX_DURATION))
        duration = min(duration, MAX_DURATION)

        now = datetime.now()
        start_time = now - timedelta(minutes=duration)

        # Load data from CSV files
        lte1_loss = pd.read_csv(LOSS_FILE_LTE1)
        lte2_loss = pd.read_csv(LOSS_FILE_LTE2)
        lte1_params = pd.read_csv(PARAMS_FILE_LTE1)
        lte2_params = pd.read_csv(PARAMS_FILE_LTE2)

        # Ensure Timestamp is in datetime format
        for df in [lte1_loss, lte2_loss, lte1_params, lte2_params]:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'])

        # Filter data within the selected duration
        lte1_loss_filtered = lte1_loss[lte1_loss['Timestamp'] >= start_time]
        lte2_loss_filtered = lte2_loss[lte2_loss['Timestamp'] >= start_time]
        lte1_params_filtered = lte1_params[lte1_params['Timestamp'] >= start_time]
        lte2_params_filtered = lte2_params[lte2_params['Timestamp'] >= start_time]

        response_data = {
            'lte1_loss': lte1_loss_filtered.to_dict(orient='records'),
            'lte2_loss': lte2_loss_filtered.to_dict(orient='records'),
            'lte1_params': lte1_params_filtered.to_dict(orient='records'),
            'lte2_params': lte2_params_filtered.to_dict(orient='records'),
        }
        return JsonResponse(response_data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
