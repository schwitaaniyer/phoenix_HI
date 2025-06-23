from django.shortcuts import render

# Create your views here.
from django.shortcuts import render



# network_monitoring/views.py
from django.shortcuts import render

def network_monitoring(request):
    return render(request, "network_monitoring/network_monitoring.html")

def configuration_view(request):
    return render(request, "network_monitoring/config.html")

def lte_view(request):
    return render(request, "network_monitoring/lte.html")

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
import json
import os

CONFIG_PATH = "config.json"

# def network_monitoring(request):
#     return render(request, "network_monitoring/config.html")

@csrf_exempt
def save_config(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            # Validate input
            required_keys = ["celery_interval", "num_test_instances", "packets_per_test", "time_between_instances", "test_repetition_frequency", "loss_threshold"]
            for key in required_keys:
                if key not in data or not str(data[key]).isdigit():
                    return JsonResponse({"error": f"Invalid value for {key}"}, status=400)

            # Read existing config
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r") as file:
                    config = json.load(file)
            else:
                config = {}

            # Update config with new values
            config.update({
                "celery_interval": int(data["celery_interval"]),
                "num_test_instances": int(data["num_test_instances"]),
                "packets_per_test": int(data["packets_per_test"]),
                "time_between_instances": int(data["time_between_instances"]),
                "test_repetition_frequency": int(data["test_repetition_frequency"]),
                "loss_threshold": int(data["loss_threshold"]),
            })

            # Save back to file
            with open(CONFIG_PATH, "w") as file:
                json.dump(config, file, indent=4)

            return JsonResponse({"message": "Configuration updated successfully!"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

    return JsonResponse({"error": "Invalid request"}, status=405)




###################################### LINK SWITCH ########################################################


import json
from django.shortcuts import render
from django.http import JsonResponse
from django.utils.timezone import now, timedelta
from .models import RFParameters, PacketLoss

# Load config.json settings
def load_config():
    with open("config.json", "r") as f:
        config = json.load(f)

    # Default values to prevent KeyError
    defaults = {
        "num_test_instances": 5,
        "loss_threshold": 20,
        "time_between_instances": 1
    }

    # Fill missing keys with default values
    for key, value in defaults.items():
        if key not in config:
            config[key] = value

    return config

# Calculate RSRP, RSRQ, SINR Index
def calculate_indices(rsrp, rsrq, sinr):
    def rsrp_index(value):
        return 1.0 if value >= -80 else 0.75 if value >= -90 else 0.5 if value >= -100 else 0.25

    def rsrq_index(value):
        return 1.0 if value >= -10 else 0.75 if value >= -15 else 0.5 if value >= -20 else 0.25

    def sinr_index(value):
        return 1.0 if value >= 20 else 0.75 if value >= 10 else 0.5 if value >= 0 else 0.25

    return rsrp_index(rsrp), rsrq_index(rsrq), sinr_index(sinr)

# Apply switching logic
def apply_switching_logic():
    config = load_config()
    n = config["num_test_instances"]
    lt = config["loss_threshold"]

    results = []
    calculated_indices = []
    switch_decision = "No Switch Needed"
    link_data = {}

    for lte_type in ["LTE1", "LTE2"]:
        # Get latest `n` RF samples
        rf_values = RFParameters.objects.filter(lte_type=lte_type).order_by("-timestamp")[:n]
        loss_values = PacketLoss.objects.filter(lte_type=lte_type).order_by("-timestamp")[:n]

        if len(rf_values) < n:
            continue  # Skip if not enough samples

        avg_lqi = 0
        prl_flag = 0

        for rf in rf_values:
            rsrp_idx, rsrq_idx, sinr_idx = calculate_indices(rf.rsrp, rf.rsrq, rf.sinr)
            lqi = rsrq_idx if rsrq_idx >= 0.25 else rsrp_idx
            avg_lqi += lqi

            # Determine Link Condition
            if lqi >= 0.75:
                condition = "Good"
            elif lqi >= 0.5:
                condition = "Weak"
            elif lqi >= 0.25:
                condition = "Very Low"
            else:
                condition = "Critical"

            calculated_indices.append({
                "timestamp": rf.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "lte_type": lte_type,
                "rsrp": rf.rsrp, "rsrp_index": rsrp_idx,
                "rsrq": rf.rsrq, "rsrq_index": rsrq_idx,
                "sinr": rf.sinr, "sinr_index": sinr_idx,
                "lqi": round(lqi, 2), "link_condition": condition
            })

        avg_lqi /= n

        # Get average packet loss
        total_packet_loss = sum([loss.packet_loss for loss in loss_values])
        avg_packet_loss = total_packet_loss / len(loss_values) if len(loss_values) > 0 else 0

        # Set PRL flag based on threshold
        if avg_packet_loss > lt:
            prl_flag = 1

        # Apply Switching Logic
        lqia = 1 if avg_lqi <= 0.25 else 0
        si = 1 if (lqia == 1 and prl_flag == 1) else 0

        link_data[lte_type] = {
            "avg_lqi": round(avg_lqi, 2),
            "packet_loss": avg_packet_loss,
            "LQIa": lqia,
            "PRL": prl_flag,
            "SI": si
        }

    # **Final Decision**
    if "LTE1" in link_data and "LTE2" in link_data:
        if link_data["LTE1"]["SI"] == 1 and link_data["LTE2"]["SI"] == 1:
            switch_decision = "No Switch Needed"
        elif link_data["LTE1"]["SI"] == 1 and link_data["LTE2"]["SI"] == 0:
            switch_decision = "Switch to LTE1"
        elif link_data["LTE1"]["SI"] == 0 and link_data["LTE2"]["SI"] == 1:
            switch_decision = "Switch to LTE2"
        else:
            switch_decision = "Both links are degraded"

    # Store final decision
    results = [
        {"lte_type": "LTE1", **link_data.get("LTE1", {})},
        {"lte_type": "LTE2", **link_data.get("LTE2", {})}
    ]

    return {"indices": calculated_indices, "switching_result": results, "switch_decision": switch_decision}

# API Endpoint
def lte_view(request):
    data = apply_switching_logic()
    return render(request, "network_monitoring/lte.html", data)

