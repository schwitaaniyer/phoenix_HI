import json
from datetime import datetime

def analyze_packet(packet_data):
    """
    Analyze nDPI packet JSON and classify severity.
    Args:
        packet_data (str or dict): JSON string or dict from nDPI.
    Returns:
        dict: Analyzed packet with severity and risk details.
    """
    if isinstance(packet_data, str):
        packet = json.loads(packet_data)
    else:
        packet = packet_data

    # Extract key fields
    result = {
        'source_ip': packet.get('src_ip', ''),
        'destination_ip': packet.get('dest_ip', ''),
        'source_port': packet.get('src_port'),
        'destination_port': packet.get('dst_port'),
        'protocol': packet.get('proto', ''),
        'ndpi_protocol': packet.get('ndpi', {}).get('proto', 'Unknown'),
        'severity': 'LOW',
        'risk_score': 0,
        'risks': packet.get('ndpi', {}).get('flow_risk', {}),
        'details': packet,
        'description': ''
    }

    # Compute risk score and severity
    flow_risk = packet.get('ndpi', {}).get('flow_risk', {})
    total_score = 0
    risk_descriptions = []
    highest_severity = 'LOW'

    for risk_id, risk_info in flow_risk.items():
        severity = risk_info.get('severity', 'LOW').upper()
        score = risk_info.get('risk_score', {}).get('total', 0)
        total_score += score
        risk_name = risk_info.get('risk', 'Unknown Risk')
        risk_descriptions.append(f"{risk_name} ({severity}, Score: {score})")

        # Update highest severity
        if severity == 'SEVERE':
            highest_severity = 'HIGH'  # Map Severe to High for UI
        elif severity == 'HIGH' and highest_severity != 'HIGH':
            highest_severity = 'HIGH'
        elif severity == 'MEDIUM' and highest_severity == 'LOW':
            highest_severity = 'MEDIUM'

    result['risk_score'] = total_score
    result['description'] = '; '.join(risk_descriptions) if risk_descriptions else 'No risks detected'

    # Assign severity based on highest severity or score thresholds
    if highest_severity == 'HIGH' or total_score > 100:
        result['severity'] = 'HIGH'
    elif highest_severity == 'MEDIUM' or total_score >= 50:
        result['severity'] = 'MEDIUM'
    else:
        result['severity'] = 'LOW'

    return result