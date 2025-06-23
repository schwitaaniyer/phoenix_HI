
from django.shortcuts import render
from django.contrib import messages
from django.http import JsonResponse
from .models import PacketAnalysis, SevereFlowLog, Settings
from .utils import analyze_packet
from .forms import RetentionForm
from .logging_config import setup_logger
import json
import logging
import subprocess
import threading
import os
import time
import netifaces
from datetime import datetime, timedelta

setup_logger()
logger = logging.getLogger('risk_analysis')

# Configurable nDPI path
NDPI_READER_PATH = '/usr/bin/ndpiReader'  # Updated to correct path

# Global variables for continuous capture
capture_thread = None
capture_stop_event = threading.Event()
current_file = None

# Global variables for session capture
session_capture_active = False
session_capture_start_time = None
session_captured_flows = []

def get_active_interfaces():
    """Get list of active network interfaces."""
    try:
        active_ifaces = netifaces.interfaces()
        interfaces = [iface for iface in active_ifaces if netifaces.AF_INET in netifaces.ifaddresses(iface)]
        logger.info(f"Detected active interfaces: {interfaces}")
        return interfaces
    except Exception as e:
        logger.error(f"Error getting interfaces: {str(e)}")
        return ['ens224']  # Default to ens224 for testing

def run_capture():
    """Background thread to run ndpiReader alternately on two files."""
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

        cmd = ['sudo', NDPI_READER_PATH, '-i', 'ens224', '-k', output_file, '-s', '20']
        logger.info(f"Round {round_count}: Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Round {round_count}: Flows written to {output_file}")
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        content = f.read().strip()
                        logger.debug(f"Round {round_count}: Content of {output_file}: {content[:500]}...")
                else:
                    logger.warning(f"Round {round_count}: {output_file} does not exist")
            else:
                logger.error(f"Round {round_count}: ndpiReader failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"Round {round_count}: ndpiReader timed out")
        except Exception as e:
            logger.error(f"Round {round_count}: ndpiReader error: {str(e)}")

        round_count += 1
        time.sleep(2)

def start_capture(request):
    """Start the continuous capture thread."""
    global capture_thread
    if request.method == 'POST':
        if capture_thread is None or not capture_thread.is_alive():
            capture_stop_event.clear()
            capture_thread = threading.Thread(target=run_capture, daemon=True)
            capture_thread.start()
            logger.info("Started nDPI capture thread")
            return JsonResponse({'status': 'success', 'message': 'Capture started successfully.'})
        else:
            logger.warning("Capture thread already running")
            return JsonResponse({'status': 'error', 'message': 'Capture is already running.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def stop_capture(request):
    """Stop the continuous capture thread."""
    global capture_thread
    if request.method == 'POST':
        if capture_thread and capture_thread.is_alive():
            capture_stop_event.set()
            capture_thread.join(timeout=5)
            capture_thread = None
            logger.info("Stopped nDPI capture thread")
            return JsonResponse({'status': 'success', 'message': 'Capture stopped successfully.'})
        else:
            logger.warning("No capture thread running")
            return JsonResponse({'status': 'error', 'message': 'No capture thread running.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def start_session_capture(request):
    """Start a session capture to store flows in captured.json."""
    global session_capture_active, session_capture_start_time, session_captured_flows
    if request.method == 'POST':
        if not session_capture_active:
            session_capture_active = True
            session_capture_start_time = datetime.now().astimezone()
            session_captured_flows = []
            logger.info(f"Started session capture at {session_capture_start_time}")
            return JsonResponse({'status': 'success', 'message': 'Session capture started successfully.'})
        else:
            logger.warning("Session capture already running")
            return JsonResponse({'status': 'error', 'message': 'Session capture is already running.'})
    logger.error("Invalid request method for start_session_capture")
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def stop_session_capture(request):
    """Stop session capture and save flows to captured.json."""
    global session_capture_active, session_capture_start_time, session_captured_flows
    if request.method == 'POST':
        if session_capture_active:
            session_capture_active = False
            log_dir = '/root/Project2/logs'
            log_file = os.path.join(log_dir, 'captured.json')
            try:
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Saving {len(session_captured_flows)} flows to {log_file}")
                with open(log_file, 'w') as f:
                    json.dump(session_captured_flows, f, indent=2)
                logger.info(f"Successfully saved {len(session_captured_flows)} flows to {log_file}")
            except Exception as e:
                logger.error(f"Error saving to {log_file}: {str(e)}")
                return JsonResponse({'status': 'error', 'message': f'Error saving captured flows: {str(e)}'})

            session_capture_start_time = None
            session_captured_flows = []
            return JsonResponse({'status': 'success', 'message': 'Session capture stopped and flows saved successfully.'})
        else:
            logger.warning("No session capture running")
            return JsonResponse({'status': 'error', 'message': 'No session capture running.'})
    logger.error("Invalid request method for stop_session_capture")
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def get_latest_flows(request):
    """Read flows from the non-writing file and process them."""
    global session_captured_flows
    if request.method == 'GET':
        interface_filter = request.GET.get('interface', 'ens224')
        file1 = '/tmp/ndpi_temp1.json'
        file2 = '/tmp/ndpi_temp2.json'
        file_to_read = file2 if current_file == file1 else file1
        logger.debug(f"Reading flows from {file_to_read} for interface {interface_filter}")

        if not os.path.exists(file_to_read):
            logger.warning(f"No flow file found at {file_to_read}")
            return JsonResponse({'packets': []})

        try:
            with open(file_to_read, 'r') as f:
                content = f.read().strip()
                if not content:
                    logger.warning(f"Empty flow file: {file_to_read}")
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
                            except json.JSONDecodeError as e:
                                logger.warning(f"Skipping invalid JSON line in {file_to_read}: {str(e)}")

                log_details = {'packets_processed': 0, 'severe_flows': 0, 'errors': []}
                processed_packets = []
                if isinstance(packet_data, list):
                    for packet in packet_data:
                        try:
                            analyzed_packet = analyze_packet(packet)
                            has_severe = any(risk['severity'] == 'SEVERE' for risk in analyzed_packet['risks'])
                            if has_severe:
                                log_details['severe_flows'] += 1
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
                            packet_obj = PacketAnalysis.objects.create(
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
                            log_details['packets_processed'] += 1
                            packet_info = {
                                'id': packet_obj.id,
                                'interface': 'ens224',
                                'first_seen': packet_obj.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                'source_ip': packet_obj.source_ip,
                                'source_port': packet_obj.source_port,
                                'destination_ip': packet_obj.destination_ip,
                                'destination_port': packet_obj.destination_port,
                                'protocol': packet_obj.protocol,
                                'ndpi_protocol': packet_obj.ndpi_protocol,
                                'risks': packet_obj.risks,
                                'severe': has_severe
                            }
                            processed_packets.append(packet_info)
                            if session_capture_active:
                                session_captured_flows.append(packet_info)
                                logger.debug(f"Added packet {packet_obj.id} to session_captured_flows. Total: {len(session_captured_flows)}")
                        except ValueError as e:
                            log_details['errors'].append(str(e))
                            logger.warning(f"Invalid packet data: {str(e)}")
                else:
                    try:
                        analyzed_packet = analyze_packet(packet_data)
                        has_severe = any(risk['severity'] == 'SEVERE' for risk in analyzed_packet['risks'])
                        if has_severe:
                            log_details['severe_flows'] += 1
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
                        packet_obj = PacketAnalysis.objects.create(
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
                        log_details['packets_processed'] += 1
                        packet_info = {
                            'id': packet_obj.id,
                            'interface': 'ens224',
                            'first_seen': packet_obj.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                            'source_ip': packet_obj.source_ip,
                            'source_port': packet_obj.source_port,
                            'destination_ip': packet_obj.destination_ip,
                            'destination_port': packet_obj.destination_port,
                            'protocol': packet_obj.protocol,
                            'ndpi_protocol': packet_obj.ndpi_protocol,
                            'risks': packet_obj.risks,
                            'severe': has_severe
                        }
                        processed_packets.append(packet_info)
                        if session_capture_active:
                            session_captured_flows.append(packet_info)
                            logger.debug(f"Added packet {packet_obj.id} to session_captured_flows. Total: {len(session_captured_flows)}")
                    except ValueError as e:
                        log_details['errors'].append(str(e))
                        logger.warning(f"Invalid packet data: {str(e)}")

                logger.info(f"Processed {log_details['packets_processed']} packets, {log_details['severe_flows']} severe, {len(log_details['errors'])} errors")
                return JsonResponse({'packets': processed_packets})
        except Exception as e:
            logger.error(f"Error reading flow file {file_to_read}: {str(e)}")
            return JsonResponse({'packets': []})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

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
            logger.info(f"Updated log retention to {retention_minutes} minutes")
            messages.success(request, f"Log retention set to {retention_minutes} minutes.")
        else:
            logger.warning(f"Invalid retention form data: {retention_form.errors}")
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
                            except json.JSONDecodeError as e:
                                logger.warning(f"Skipping invalid JSON line: {str(e)}")
                                messages.warning(request, f"Skipping invalid line: {str(e)}")

                if not packet_data:
                    logger.error("No valid JSON data found in file")
                    messages.error(request, 'No valid JSON data found in file.')
                    packets = PacketAnalysis.objects.all()
                    return render(request, 'risk_analysis/analysis.html', {
                        'packets': packets,
                        'severe_alert': severe_alert,
                        'retention_form': retention_form,
                        'capture_running': capture_thread is not None and capture_thread.is_alive(),
                        'interfaces': interfaces
                    })

                log_details = {'packets_processed': 0, 'severe_flows': 0, 'errors': []}
                if isinstance(packet_data, list):
                    for packet in packet_data:
                        try:
                            analyzed_packet = analyze_packet(packet)
                            has_severe = any(risk['severity'] == 'SEVERE' for risk in analyzed_packet['risks'])
                            if has_severe:
                                severe_alert = True
                                log_details['severe_flows'] += 1
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
                            log_details['packets_processed'] += 1
                        except ValueError as e:
                            log_details['errors'].append(str(e))
                            logger.warning(f"Invalid packet data: {str(e)}")
                            messages.warning(request, f"Skipped packet: {str(e)}")
                else:
                    try:
                        analyzed_packet = analyze_packet(packet_data)
                        has_severe = any(risk['severity'] == 'SEVERE' for risk in analyzed_packet['risks'])
                        if has_severe:
                            severe_alert = True
                            log_details['severe_flows'] += 1
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
                        log_details['packets_processed'] += 1
                    except ValueError as e:
                        log_details['errors'].append(str(e))
                        logger.warning(f"Invalid packet data: {str(e)}")
                        messages.warning(request, f"Skipped packet: {str(e)}")

                logger.info(f"Processed {log_details['packets_processed']} packets, {log_details['severe_flows']} severe, {len(log_details['errors'])} errors")
                messages.success(request, 'Packets analyzed and saved successfully.')
            except Exception as e:
                logger.error(f"Error processing file: {str(e)}")
                messages.error(request, f'Error processing file: {str(e)}')
        else:
            logger.error("No file uploaded")
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
    return render(request, 'risk_analysis/analysis.html', context)