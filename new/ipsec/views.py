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