from django.shortcuts import render
from django.http import JsonResponse, HttpResponseBadRequest
from django.utils import timezone
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import os
from .models import RFParameters, PacketLoss, PredictedParameters, PacketLossRecord
# Import or adapt services as needed (e.g., data_fetcher, predictor, etc.)
# from .services import ...

# Path for config file - adjust as needed
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')

def monitor_config_view(request):
    """Render the network monitor configuration page"""
    try:
        # Load existing config if available
        config = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
        return render(request, 'network/monitor_config.html', {'config': config})
    except Exception as e:
        return render(request, 'network/monitor_config.html', {'error': str(e)})

# Example: Dashboard/Analysis view

def monitor_analysis_view(request):
    # Fetch latest actual values
    lte1_actual = RFParameters.objects.filter(lte_type='LTE1').order_by('-timestamp').first()
    lte2_actual = RFParameters.objects.filter(lte_type='LTE2').order_by('-timestamp').first()
    # Fetch predicted parameters (stub)
    lte1_pred = PredictedParameters.objects.filter(lte_type='LTE1').order_by('-timestamp').first()
    lte2_pred = PredictedParameters.objects.filter(lte_type='LTE2').order_by('-timestamp').first()
    # Fetch recommended action (stub)
    recommended_action = 'No Switch'  # Replace with logic
    context = {
        'lte1_actual': lte1_actual,
        'lte2_actual': lte2_actual,
        'lte1_pred': lte1_pred,
        'lte2_pred': lte2_pred,
        'recommended_action': recommended_action,
        'last_updated': timezone.now()
    }
    return render(request, "network/monitor_analysis.html", context)

@csrf_exempt
@require_http_methods(['GET', 'POST'])
def get_monitor_config(request):
    """Handle configuration loading and saving"""
    if request.method == 'GET':
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, 'r') as f:
                    config = json.load(f)
                return JsonResponse({'status': 'success', 'config': config})
            else:
                # Return default config
                default_config = {
                    'sampling_interval': 2,
                    'test_repetition': 12,
                    'num_instances': 5,
                    'packets_per_test': 100,
                    'num_test_instances': 5,
                    'time_between': 1,
                    'loss_threshold': 5.0,
                    'network_interface': 'ens224',
                    'test_ips': [
                        {'type': 'LTE1', 'ip': '8.8.8.8'},
                        {'type': 'LTE2', 'ip': '8.8.4.4'}
                    ],
                    'latency_enabled': False,
                    'latency_threshold': 100.0,
                    'jitter_enabled': False,
                    'jitter_threshold': 50.0
                }
                return JsonResponse({'status': 'success', 'config': default_config})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Error loading config: {str(e)}'}, status=500)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Validate required fields
            required_fields = {
                'sampling_interval': int,
                'test_repetition': int,
                'num_instances': int,
                'packets_per_test': int,
                'num_test_instances': int,
                'time_between': int,
                'loss_threshold': float,
                'network_interface': str
            }
            
            # Validate field types and values
            for field, field_type in required_fields.items():
                if field not in data:
                    return JsonResponse({
                        'status': 'error',
                        'message': f'Missing required field: {field}'
                    }, status=400)
                
                try:
                    if field_type in (int, float):
                        value = field_type(data[field])
                        if value <= 0:
                            return JsonResponse({
                                'status': 'error',
                                'message': f'{field} must be greater than 0'
                            }, status=400)
                        data[field] = value
                except (ValueError, TypeError):
                    return JsonResponse({
                        'status': 'error',
                        'message': f'Invalid value for {field}'
                    }, status=400)
            
            # Validate test_ips
            if 'test_ips' not in data or not isinstance(data['test_ips'], list) or len(data['test_ips']) < 2:
                return JsonResponse({
                    'status': 'error',
                    'message': 'At least two IP addresses (LTE1 and LTE2) are required'
                }, status=400)
            
            for ip_entry in data['test_ips']:
                if not isinstance(ip_entry, dict) or 'type' not in ip_entry or 'ip' not in ip_entry:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Invalid IP entry format'
                    }, status=400)
            
            # Validate latency and jitter settings
            latency_enabled = data.get('latency_enabled', False)
            jitter_enabled = data.get('jitter_enabled', False)
            
            if latency_enabled:
                try:
                    latency_threshold = float(data.get('latency_threshold', 0))
                    if latency_threshold <= 0:
                        return JsonResponse({
                            'status': 'error',
                            'message': 'Latency threshold must be greater than 0'
                        }, status=400)
                except (ValueError, TypeError):
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Invalid latency threshold value'
                    }, status=400)
            
            if jitter_enabled:
                try:
                    jitter_threshold = float(data.get('jitter_threshold', 0))
                    if jitter_threshold <= 0:
                        return JsonResponse({
                            'status': 'error',
                            'message': 'Jitter threshold must be greater than 0'
                        }, status=400)
                except (ValueError, TypeError):
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Invalid jitter threshold value'
                    }, status=400)
            
            # Save the validated config
            with open(CONFIG_PATH, 'w') as f:
                json.dump(data, f, indent=4)
            
            return JsonResponse({
                'status': 'success',
                'message': 'Configuration saved successfully!'
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error saving config: {str(e)}'
            }, status=500)

def get_monitor_status(request):
    """Get current monitoring status"""
    try:
        # Get config to determine which LTE types exist
        lte_types = []
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
                lte_types = [ip_config['type'] for ip_config in config.get('test_ips', [])]
        
        if not lte_types:
            lte_types = ['LTE1', 'LTE2']
        
        # Get status for each LTE type
        status_data = {}
        for lte_type in lte_types:
            latest_record = PacketLossRecord.objects.filter(
                lte_type=lte_type
            ).order_by('-timestamp').first()
            
            if latest_record:
                status_data[lte_type] = {
                    'timestamp': latest_record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'packet_loss': f'{latest_record.packet_loss}%',
                    'latency': latest_record.latency,
                    'jitter': latest_record.jitter
                }
        
        if status_data:
            return JsonResponse({'status': 'success', 'data': status_data})
        else:
            return JsonResponse({
                'status': 'warning',
                'message': 'No monitoring data available yet'
            })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'Error fetching status: {str(e)}'
        }, status=500)

# Add more endpoints as needed, following the structure in new/network_monitoring/views.py 