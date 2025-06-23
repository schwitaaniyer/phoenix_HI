from django.shortcuts import render, HttpResponse, redirect
from datetime import datetime
from home.models import Contact
from django.contrib import messages
from django.http import JsonResponse
import subprocess
import os



def login(request):
    if request.method == 'POST':  
        username = request.POST.get('username')
        password = request.POST.get('password')

        
        if username == "root" and password == "root":
            return redirect('home')  
        else:
            return redirect('login')  
    else:
        return render(request, 'login.html')  


def home(request):
    
    return render(request, 'home.html')
    # return HttpResponse("this is homepage")


# Create your views here.
def firewall(request):
     
    return render(request, 'firewall.html')
    # return HttpResponse("this is homepage")

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



    return render(request, 'blocklist.html') 



################################################################## RULES BLOCK###################################################################################################################

def rules(request):
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

        return render(request, 'rules.html', {
            'static_service_options': service_options,
            'static_source_options': source_options,
            'static_destination_options': destination_options,
            'static_action_options': actions
        })

 
##################################################################SERVICE BLOCK####################################################################################################################


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
    
def interfaces(request):
    result = None

    if request.method == 'POST':
        command = request.POST.get('command', '')
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
def capabilities(request):
    return render(request, 'capabilities.html')


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


