#23/04/25

# from datetime import datetime
# import pytz

# def analyze_packet(packet):
#     source_ip = packet.get('src_ip', 'Unknown')
#     destination_ip = packet.get('dest_ip', 'Unknown')
#     source_port = packet.get('src_port')
#     destination_port = packet.get('dst_port')
#     protocol = packet.get('proto', 'Unknown')
#     ndpi_data = packet.get('ndpi', {})
#     ndpi_protocol = ndpi_data.get('proto', 'Unknown')
#     flow_risk = ndpi_data.get('flow_risk', {})
    
#     # Convert Unix timestamps to datetime, fallback to None
#     first_seen = packet.get('first_seen')
#     last_seen = packet.get('last_seen')
#     first_seen = datetime.fromtimestamp(first_seen, tz=pytz.UTC) if first_seen else None
#     last_seen = datetime.fromtimestamp(last_seen, tz=pytz.UTC) if last_seen else None
    
#     risks = []
#     for risk_id, risk_info in flow_risk.items():
#         risk_name = risk_info.get('risk', 'Unknown')
#         risk_severity = risk_info.get('severity', 'LOW')
#         risks.append({'id': risk_id, 'name': risk_name, 'severity': risk_severity})
    
#     # Format description for splitting in template
#     description = '\n'.join([f"{r['name']}    {r['severity']}" for r in risks]) if risks else 'No risks detected'
    
#     return {
#         'source_ip': source_ip,
#         'destination_ip': destination_ip,
#         'source_port': source_port,
#         'destination_port': destination_port,
#         'protocol': protocol,
#         'ndpi_protocol': ndpi_protocol,
#         'first_seen': first_seen,
#         'last_seen': last_seen,
#         'risks': risks,
#         'details': packet,
#         'description': description
#     }





#25/04/25


from datetime import datetime
import pytz
import ipaddress

def analyze_packet(packet):
    # Validate required fields
    if not isinstance(packet, dict):
        raise ValueError("Packet must be a dictionary")
    
    source_ip = packet.get('src_ip', 'Unknown')
    destination_ip = packet.get('dest_ip', 'Unknown')
    
    # Validate IP addresses
    try:
        ipaddress.ip_address(source_ip)
        ipaddress.ip_address(destination_ip)
    except ValueError:
        raise ValueError("Invalid source or destination IP address")

    source_port = packet.get('src_port')
    destination_port = packet.get('dst_port')
    # Validate ports if present
    if source_port is not None:
        if not isinstance(source_port, int) or source_port < 0 or source_port > 65535:
            raise ValueError("Invalid source port")
    if destination_port is not None:
        if not isinstance(destination_port, int) or destination_port < 0 or destination_port > 65535:
            raise ValueError("Invalid destination port")

    protocol = packet.get('proto', 'Unknown')
    if not isinstance(protocol, str):
        raise ValueError("Protocol must be a string")

    ndpi_data = packet.get('ndpi', {})
    if not isinstance(ndpi_data, dict):
        raise ValueError("ndpi data must be a dictionary")
    
    ndpi_protocol = ndpi_data.get('proto', 'Unknown')
    flow_risk = ndpi_data.get('flow_risk', {})
    if not isinstance(flow_risk, dict):
        raise ValueError("flow_risk must be a dictionary")

    first_seen = packet.get('first_seen')
    last_seen = packet.get('last_seen')
    if first_seen is None:
        raise ValueError("first_seen is required")
    try:
        first_seen = float(first_seen)
        if first_seen < 0:
            raise ValueError
        first_seen = datetime.fromtimestamp(first_seen, tz=pytz.UTC)
    except (ValueError, TypeError):
        raise ValueError("Invalid first_seen timestamp")
    
    if last_seen is not None:
        try:
            last_seen = float(last_seen)
            if last_seen < 0:
                raise ValueError
            last_seen = datetime.fromtimestamp(last_seen, tz=pytz.UTC)
        except (ValueError, TypeError):
            raise ValueError("Invalid last_seen timestamp")

    risks = []
    for risk_id, risk_info in flow_risk.items():
        if not isinstance(risk_info, dict):
            raise ValueError(f"Risk {risk_id} must be a dictionary")
        risk_name = risk_info.get('risk', 'Unknown')
        risk_severity = risk_info.get('severity', 'LOW')
        if not isinstance(risk_name, str) or not isinstance(risk_severity, str):
            raise ValueError(f"Invalid risk data for {risk_id}")
        risks.append({'id': risk_id, 'name': risk_name, 'severity': risk_severity})
    
    description = '\n'.join([f"{r['name']}    {r['severity']}" for r in risks]) if risks else 'No risks detected'
    
    return {
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'source_port': source_port,
        'destination_port': destination_port,
        'protocol': protocol,
        'ndpi_protocol': ndpi_protocol,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'risks': risks,
        'details': packet,
        'description': description
    }