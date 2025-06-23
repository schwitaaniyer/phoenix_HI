from django.shortcuts import render

# Create your views here.
from django.shortcuts import render

# Create your views here.
# network_monitoring/views.py
from django.http import JsonResponse
from .services.data_fetcher import ZabbixDataFetcher
from .models import RFParameters, PacketLoss

def test_fetch(request):
    try:
        # Create fetcher instance
        fetcher = ZabbixDataFetcher()
        
        # Fetch data
        print("Fetching data from Zabbix...")
        data = fetcher.fetch_zabbix_data()
        print(f"Fetched data: {data}")
        
        # Process and save data
        print("Processing and saving data...")
        fetcher.process_and_save_data(data)
        
        # Verify saved data
        latest_params = RFParameters.objects.all().order_by('-timestamp')[:5]
        latest_losses = PacketLoss.objects.all().order_by('-timestamp')[:5]
        
        return JsonResponse({
            'success': True,
            'rf_parameters': [
                {
                    'timestamp': param.timestamp,
                    'lte_type': param.lte_type,
                    'rsrp': param.rsrp,
                    'rsrq': param.rsrq,
                    'rssi': param.rssi,
                    'sinr': param.sinr
                } for param in latest_params
            ],
            'packet_losses': [
                {
                    'timestamp': loss.timestamp,
                    'lte_type': loss.lte_type,
                    'packet_loss': loss.packet_loss
                } for loss in latest_losses
            ]
        })
    except Exception as e:
        print(f"Error: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })
    


# network_monitoring/views.py

from django.http import JsonResponse
from django.shortcuts import render
from .services.data_fetcher import ZabbixDataFetcher
from .models import RFParameters, PacketLoss
from django.utils import timezone
from datetime import timedelta

def verify_data(request):
    # Initialize fetcher and get data
    fetcher = ZabbixDataFetcher()
    raw_data = fetcher.fetch_zabbix_data()
    
    # Fetch the latest data from database
    latest_rf = RFParameters.objects.all().order_by('-timestamp')[:10]
    latest_pl = PacketLoss.objects.all().order_by('-timestamp')[:10]
    
    context = {
        'zabbix_data': {
            'raw_data': raw_data,
            'item_count': len(raw_data) if raw_data else 0,
        },
        'database_data': {
            'rf_parameters': [{
                'timestamp': rf.timestamp,
                'lte_type': rf.lte_type,
                'rsrp': rf.rsrp,
                'rsrq': rf.rsrq,
                'rssi': rf.rssi,
                'sinr': rf.sinr,
            } for rf in latest_rf],
            'packet_loss': [{
                'timestamp': pl.timestamp,
                'lte_type': pl.lte_type,
                'packet_loss': pl.packet_loss,
            } for pl in latest_pl],
        },
        'counts': {
            'total_rf_records': RFParameters.objects.count(),
            'total_pl_records': PacketLoss.objects.count(),
        }
    }
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse(context)
    return render(request, 'network_monitoring/verify.html', context)

def fetch_and_save(request):
    try:
        fetcher = ZabbixDataFetcher()
        raw_data = fetcher.fetch_zabbix_data()
        
        if raw_data:
            fetcher.process_and_save_data(raw_data)
            message = "Data fetched and saved successfully"
            success = True
        else:
            message = "No data received from Zabbix"
            success = False
            
        return JsonResponse({
            'success': success,
            'message': message,
            'data_received': bool(raw_data),
            'items_count': len(raw_data) if raw_data else 0
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        })
    


##############################


# network_monitoring/views.py
from django.http import JsonResponse
from django.utils import timezone
from .models import RFParameters
# from .services.predicton import NetworkPredictor
from .tasks import fetch_and_predict_data
from django.shortcuts import render

def monitor_dashboard(request):
    """Dashboard showing latest data and predictions"""
    try:
        # Get latest actual values
        lte1_actual = RFParameters.objects.filter(lte_type='LTE1').order_by('-timestamp').first()
        lte2_actual = RFParameters.objects.filter(lte_type='LTE2').order_by('-timestamp').first()
        
        # Get predictions
        predictor = NetworkPredictor()
        lte1_prediction = predictor.predict_next_values('LTE1')
        lte2_prediction = predictor.predict_next_values('LTE2')
        
        context = {
            'lte1_actual': lte1_actual,
            'lte2_actual': lte2_actual,
            'lte1_prediction': lte1_prediction,
            'lte2_prediction': lte2_prediction,
            'last_updated': timezone.now()
        }
        
        return render(request, 'network_monitoring/dashboard.html', context)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def trigger_fetch_predict(request):
    """Manually trigger fetch and predict task"""
    try:
        result = fetch_and_predict_data.delay()
        return JsonResponse({
            'status': 'success',
            'task_id': result.id
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)



########################### configuration #################################################################





from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import subprocess
import json
import os

CONFIG_PATH = ("config.json")

def network_monitoring(request):
    return render(request, "network_monitoring/config.html")


def save_config(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            new_interval = data.get("celery_interval")

            if not new_interval or not str(new_interval).isdigit():
                return JsonResponse({"error": "Invalid interval"}, status=400)

            # Read existing config
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r") as file:
                    config = json.load(file)
            else:
                config = {}

            # Update interval
            config["celery_interval"] = int(new_interval)

            # Save back to file
            with open(CONFIG_PATH, "w") as file:
                json.dump(config, file, indent=4)

            return JsonResponse({"message": f"Updated interval to {new_interval} minutes"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

    return JsonResponse({"error": "Invalid request"}, status=405)

def restart_celery_beat():
    """Function to restart Celery Beat after changing the config."""
    try:

        print("Stopping Celery Beat...")
        # Kill existing Celery Beat process
        subprocess.run(["pkill", "-f", "celery -A Hello beat"], check=True)
        
        print("Starting Celery Beat...")
        # Restart Celery Beat
        subprocess.run(["celery", "-A", "Hello", "beat", "-l", "info"], check=True)
        
        print("Celery Beat restarted successfully!")

    except subprocess.CalledProcessError as e:
        print("Error restarting Celery Beat:", e)