from django.shortcuts import render

# # Create your views here.


# # 23/04/25



# from django.shortcuts import render
# from django.contrib import messages
# from .models import PacketAnalysis
# from .utils import analyze_packet
# import json

# def risk_analysis_view(request):
#     if request.method == 'POST':
#         packet_file = request.FILES.get('packet_file')
#         if packet_file:
#             try:
#                 # Read the file contents
#                 content = packet_file.read().decode('utf-8').strip()
#                 # Try parsing as a single JSON document
#                 try:
#                     packet_data = json.loads(content)
#                 except json.JSONDecodeError:
#                     # Handle JSONL or concatenated objects
#                     packet_data = []
#                     lines = content.split('\n')
#                     for line in lines:
#                         line = line.strip()
#                         if line:
#                             try:
#                                 packet_data.append(json.loads(line))
#                             except json.JSONDecodeError as e:
#                                 messages.warning(request, f"Skipping invalid line: {str(e)}")

#                 if not packet_data:
#                     messages.error(request, 'No valid JSON data found in file.')
#                     packets = PacketAnalysis.objects.all()
#                     return render(request, 'risk_analysis/analysis.html', {'packets': packets})

#                 # Process packets
#                 if isinstance(packet_data, list):
#                     for packet in packet_data:
#                         analyzed_packet = analyze_packet(packet)
#                         PacketAnalysis.objects.create(
#                             source_ip=analyzed_packet['source_ip'],
#                             destination_ip=analyzed_packet['destination_ip'],
#                             source_port=analyzed_packet['source_port'],
#                             destination_port=analyzed_packet['destination_port'],
#                             protocol=analyzed_packet['protocol'],
#                             ndpi_protocol=analyzed_packet['ndpi_protocol'],
#                             severity=analyzed_packet['severity'],
#                             risk_score=analyzed_packet['risk_score'],
#                             risks=analyzed_packet['risks'],
#                             details=analyzed_packet['details'],
#                             description=analyzed_packet['description']
#                         )
#                 else:
#                     analyzed_packet = analyze_packet(packet_data)
#                     PacketAnalysis.objects.create(
#                         source_ip=analyzed_packet['source_ip'],
#                         destination_ip=analyzed_packet['destination_ip'],
#                         source_port=analyzed_packet['source_port'],
#                         destination_port=analyzed_packet['destination_port'],
#                         protocol=analyzed_packet['protocol'],
#                         ndpi_protocol=analyzed_packet['ndpi_protocol'],
#                         severity=analyzed_packet['severity'],
#                         risk_score=analyzed_packet['risk_score'],
#                         risks=analyzed_packet['risks'],
#                         details=analyzed_packet['details'],
#                         description=analyzed_packet['description']
#                     )
#                 messages.success(request, 'Packets analyzed and saved successfully.')
#             except Exception as e:
#                 messages.error(request, f'Error processing file: {str(e)}')
#         else:
#             messages.error(request, 'No file uploaded.')

#     packets = PacketAnalysis.objects.all()
#     context = {'packets': packets}
#     return render(request, 'risk_analysis/analysis.html', context)







# 24/04.25


from django.shortcuts import render
from django.contrib import messages
from .models import PacketAnalysis, AnalysisLog, SevereFlowLog
from .utils import analyze_packet
import json

def risk_analysis_view(request):
    severe_alert = False
    if request.method == 'POST':
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
                                messages.warning(request, f"Skipping invalid line: {str(e)}")

                if not packet_data:
                    AnalysisLog.objects.create(
                        message="No valid JSON data found in file",
                        details={'error': 'Invalid JSON'}
                    )
                    messages.error(request, 'No valid JSON data found in file.')
                    packets = PacketAnalysis.objects.all().order_by('first_seen')
                    return render(request, 'risk_analysis/analysis.html', {'packets': packets, 'severe_alert': severe_alert})

                log_details = {'packets_processed': 0, 'severe_flows': 0}
                if isinstance(packet_data, list):
                    for packet in packet_data:
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
                else:
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

                AnalysisLog.objects.create(
                    message=f"Processed {log_details['packets_processed']} packets, {log_details['severe_flows']} severe",
                    details=log_details
                )
                messages.success(request, 'Packets analyzed and saved successfully.')
            except Exception as e:
                AnalysisLog.objects.create(
                    message=f"Error processing file: {str(e)}",
                    details={'error': str(e)}
                )
                messages.error(request, f'Error processing file: {str(e)}')
        else:
            AnalysisLog.objects.create(message="No file uploaded")
            messages.error(request, 'No file uploaded.')

    packets = PacketAnalysis.objects.all().order_by('first_seen')
    context = {'packets': packets, 'severe_alert': severe_alert}
    return render(request, 'risk_analysis/analysis.html', context)