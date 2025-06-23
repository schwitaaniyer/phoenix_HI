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
from datetime import datetime, timedelta

setup_logger()
logger = logging.getLogger('risk_analysis')

# Global variables for capture thread and control
capture_thread = None
capture_stop_event = threading.Event()
current_file = None  # Tracks which file is being written to

def run_capture():
    """Background thread to run ndpiReader alternately on two files."""
    global current_file
    round_count = 1
    file1 = '/tmp/ndpi_temp1.json'
    file2 = '/tmp/ndpi_temp2.json'

    while not capture_stop_event.is_set():
        # Alternate between files
        if round_count % 2 == 1:
            output_file = file1
        else:
            output_file = file2
        current_file = output_file

        # Run ndpiReader
        cmd = ['sudo', 'ndpiReader', '-i', 'ens224', '-k', output_file, '-s', '5']
        logger.info(f"Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"Round {round_count}: Flows written to {output_file}")
            else:
                logger.error(f"Round {round_count}: ndpiReader failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"Round {round_count}: ndpiReader timed out")
        except Exception as e:
            logger.error(f"Round {round_count}: ndpiReader error: {str(e)}")

        round_count += 1
        # Sleep to allow file to be read before next capture
        time.sleep(2)

def start_capture(request):
    """Start the capture thread."""
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
    """Stop the capture thread."""
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

def get_latest_flows(request):
    """Read flows from the non-writing file and process them."""
    if request.method == 'GET':
        # Determine non-writing file
        file1 = '/tmp/ndpi_temp1.json'
        file2 = '/tmp/ndpi_temp2.json'
        file_to_read = file2 if current_file == file1 else file1

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
                            processed_packets.append({
                                'id': packet_obj.id,
                                'first_seen': packet_obj.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                                'source_ip': packet_obj.source_ip,
                                'source_port': packet_obj.source_port,
                                'destination_ip': packet_obj.destination_ip,
                                'destination_port': packet_obj.destination_port,
                                'protocol': packet_obj.protocol,
                                'ndpi_protocol': packet_obj.ndpi_protocol,
                                'risks': packet_obj.risks,
                                'severe': has_severe
                            })
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
                        processed_packets.append({
                            'id': packet_obj.id,
                            'first_seen': packet_obj.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                            'source_ip': packet_obj.source_ip,
                            'source_port': packet_obj.source_port,
                            'destination_ip': packet_obj.destination_ip,
                            'destination_port': packet_obj.destination_port,
                            'protocol': packet_obj.protocol,
                            'ndpi_protocol': packet_obj.ndpi_protocol,
                            'risks': packet_obj.risks,
                            'severe': has_severe
                        })
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

    # Handle retention duration form
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

    # Handle packet file upload
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
                        'retention_form': retention_form
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

    # Get retention period
    settings = Settings.objects.first()
    retention_minutes = settings.log_retention_minutes if settings else 60
    cutoff_time = datetime.now() - timedelta(minutes=retention_minutes)

    # Filter packets by retention period
    packets = PacketAnalysis.objects.filter(first_seen__gte=cutoff_time).order_by('-first_seen')

    # Check for severe flows within retention period
    severe_alert = SevereFlowLog.objects.filter(first_seen__gte=cutoff_time).exists()

    context = {
        'packets': packets,
        'severe_alert': severe_alert,
        'retention_form': retention_form,
        'capture_running': capture_thread is not None and capture_thread.is_alive()
    }
    return render(request, 'risk_analysis/analysis.html', context)