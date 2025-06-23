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



# from django.shortcuts import render
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# import json
# import os

# CONFIG_PATH = "config.json"

# # def network_monitoring(request):
# #     return render(request, "network_monitoring/config.html")

# @csrf_exempt
# def save_config(request):
#     if request.method == "POST":
#         try:
#             data = json.loads(request.body)
#             required_fields = ["celery_interval", "test_instances", "packets_per_test", "time_between_instances", "test_repetition", "loss_threshold"]
            
#             # Validate inputs
#             for field in required_fields:
#                 if field not in data or not str(data[field]).isdigit():
#                     return JsonResponse({"error": f"Invalid value for {field}"}, status=400)

#             # Read existing config
#             config = {}
#             if os.path.exists(CONFIG_PATH):
#                 with open(CONFIG_PATH, "r") as file:
#                     config = json.load(file)

#             # Update config values
#             config.update({
#                 "celery_interval": int(data["celery_interval"]),
#                 "num_test_instances": int(data["test_instances"]),
#                 "packets_per_test": int(data["packets_per_test"]),
#                 "time_between_instances": int(data["time_between_instances"]),
#                 "test_repetition_frequency": int(data["test_repetition"]),
#                 "loss_threshold": int(data["loss_threshold"]),
#             })

#             # Save updated config
#             with open(CONFIG_PATH, "w") as file:
#                 json.dump(config, file, indent=4)

#             return JsonResponse({"message": "Configuration updated successfully!"})

#         except json.JSONDecodeError:
#             return JsonResponse({"error": "Invalid JSON format"}, status=400)

#     return JsonResponse({"error": "Invalid request"}, status=405)







# 27/02/25




# network_monitoring/views.py
import json
import os
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import PacketLossRecord

CONFIG_PATH = "config.json"

def network_monitoring(request):
    return render(request, "network_monitoring/network_monitoring.html")

def configuration_view(request):
    return render(request, "network_monitoring/config.html")

def get_config(request):
    """Get the current configuration from the config file"""
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as file:
                config = json.load(file)
            return JsonResponse({"status": "success", "config": config})
        else:
            # Create default config if not exists
            default_config = {
                "celery_interval": 2,
                "num_test_instances": 5,
                "packets_per_test": 100,
                "loss_per_instance": 5,
                "time_between_instances": 1,
                "test_repetition_frequency": 12,
                "loss_threshold": 5.0,
                "interface": "ens224",
                "test_ips": [
                    {"type": "LTE1", "ip": "8.8.8.8"},
                    {"type": "LTE2", "ip": "8.8.4.4"}
                ]
            }
            with open(CONFIG_PATH, "w") as file:
                json.dump(default_config, file, indent=4)
            return JsonResponse({"status": "success", "config": default_config})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Error reading config: {str(e)}"}, status=500)

def current_status(request):
    """Get the current monitoring status from the database for all LTE types"""
    try:
        # Get config to determine which LTE types exist
        lte_types = []
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as file:
                config = json.load(file)
                # Extract all LTE types from config
                lte_types = [ip_config.get("type") for ip_config in config.get("test_ips", [])]
        
        # If no LTE types found in config, use a default list
        if not lte_types:
            lte_types = ["LTE1", "LTE2"]
            
        # Get status for each LTE type
        status_data = {}
        for lte_type in lte_types:
            # Get the most recent record for this LTE type
            latest_record = PacketLossRecord.objects.filter(
                lte_type=lte_type
            ).order_by('-timestamp').first()
            
            if latest_record:
                status_data[lte_type] = {
                    "timestamp": latest_record.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "packet_loss": f"{latest_record.packet_loss}%",
                    "latency": latest_record.latency,
                    "jitter": latest_record.jitter
                }
        
        if status_data:
            return JsonResponse({"status": "success", "data": status_data})
        else:
            return JsonResponse({"status": "warning", "message": "No monitoring data available yet"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Error fetching status: {str(e)}"}, status=500)
    

@csrf_exempt
@require_http_methods(["POST"])
def save_config(request):
    """Save the configuration to the config file"""
    try:
        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = [
            "celery_interval", "num_test_instances", "packets_per_test", 
            "loss_per_instance", "time_between_instances", 
            "test_repetition_frequency", "loss_threshold"
        ]
        
        for field in required_fields:
            if field not in data or not str(data[field]).replace(".", "", 1).isdigit():
                return JsonResponse({
                    "status": "error", 
                    "message": f"Invalid value for {field}"
                }, status=400)
        
        # Collect IP entries
        if "test_ips" not in data or not isinstance(data["test_ips"], list) or len(data["test_ips"]) < 2:
            return JsonResponse({
                "status": "error",
                "message": "At least two IP addresses (LTE1 and LTE2) are required"
            }, status=400)
        
        # Create config dict with all values
        config = {
            "celery_interval": int(data["celery_interval"]),
            "num_test_instances": int(data["num_test_instances"]),
            "packets_per_test": int(data["packets_per_test"]),
            "loss_per_instance": int(data["loss_per_instance"]),
            "time_between_instances": int(data["time_between_instances"]),
            "test_repetition_frequency": int(data["test_repetition_frequency"]),
            "loss_threshold": float(data["loss_threshold"]),
            "interface": data.get("interface", "ens224"),
            "test_ips": data["test_ips"]
        }
        
        # For backward compatibility, also set test_ip to the first LTE1 IP
        lte1_ips = [ip for ip in data["test_ips"] if ip["type"] == "LTE1"]
        if lte1_ips:
            config["test_ip"] = lte1_ips[0]["ip"]
        else:
            config["test_ip"] = data["test_ips"][0]["ip"]
        
        # Save the config to file
        with open(CONFIG_PATH, "w") as file:
            json.dump(config, file, indent=4)
        
        return JsonResponse({"status": "success", "message": "Configuration saved successfully!"})
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Error saving config: {str(e)}"}, status=500)
    
    
# Keep the lte_view function as it is in your existing code
def lte_view(request):
    rf_data, predicted_data = fetch_rf_and_predicted_data()
    switching_result = apply_switching_logic()

    return render(request, "network_monitoring/lte.html", {
        "rf_data": rf_data,  
        "predicted_data": predicted_data,  
        "switching_result": switching_result["switching_result"],  
        "switch_decision": switching_result["switch_decision"]
    })

# Import these functions from your existing code 
# The implementations remain unchanged
from .models import RFParameters, PacketLoss, PredictedParameters
from django.utils.timezone import now, timedelta

def load_config():
    with open("config.json", "r") as f:
        config = json.load(f)

    defaults = {
        "num_test_instances": 5,
        "loss_threshold": 10,
        "time_between_instances": 1
    }

    for key, value in defaults.items():
        if key not in config:
            config[key] = value

    return config

def calculate_indices(rsrp, rsrq):
    if rsrp >= -80:
        rsrp_idx = 1.0
    elif -80 > rsrp >= -90:
        rsrp_idx = 0.75
    elif -90 > rsrp >= -100:
        rsrp_idx = 0.5
    else:
        rsrp_idx = 0.25

    if rsrq >= -10:
        rsrq_idx = 1.0
    elif -10 > rsrq >= -15:
        rsrq_idx = 0.75
    elif -15 > rsrq >= -20:
        rsrq_idx = 0.5
    else:
        rsrq_idx = 0.25

    return rsrp_idx, rsrq_idx

def get_link_condition(lqi):
    if lqi >= 0.75:
        return "Excellent"
    elif lqi >= 0.5:
        return "Good"
    elif lqi >= 0.25:
        return "Weak"
    else:
        return "Very Low"

def fetch_rf_and_predicted_data():
    config = load_config()
    n = config["num_test_instances"]

    rf_data = []
    predicted_data = []

    for lte_type in ["LTE1", "LTE2"]:
        # Get the most recent record for LTE1 and LTE2 separately
        latest_rf = RFParameters.objects.filter(lte_type=lte_type).order_by("-timestamp").first()
        rf_records = RFParameters.objects.filter(lte_type=lte_type).order_by("-timestamp")[1:n]  # Exclude most recent
        
        # Ensure we get one LTE1 and one LTE2 row
        if latest_rf:
            rsrp_idx, rsrq_idx = calculate_indices(latest_rf.rsrp, latest_rf.rsrq)
            rf_data.append({
                "timestamp": latest_rf.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "lte_type": lte_type,
                "rsrp": latest_rf.rsrp, "rsrp_index": rsrp_idx,
                "rsrq": latest_rf.rsrq, "rsrq_index": rsrq_idx,
                "sinr": latest_rf.sinr,
                "lqi": round(rsrq_idx if rsrq_idx >= 0.25 else rsrp_idx, 2),
                "link_condition": get_link_condition(rsrq_idx)
            })

        # Store older values for "View All"
        for rf in rf_records:
            rsrp_idx, rsrq_idx = calculate_indices(rf.rsrp, rf.rsrq)
            rf_data.append({
                "timestamp": rf.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "lte_type": lte_type,
                "rsrp": rf.rsrp, "rsrp_index": rsrp_idx,
                "rsrq": rf.rsrq, "rsrq_index": rsrq_idx,
                "sinr": rf.sinr,
                "lqi": round(rsrq_idx if rsrq_idx >= 0.25 else rsrp_idx, 2),
                "link_condition": get_link_condition(rsrq_idx)
            })

        # Predicted Parameters
        latest_pred = PredictedParameters.objects.filter(lte_type=lte_type).order_by("-timestamp").first()
        pred_records = PredictedParameters.objects.filter(lte_type=lte_type).order_by("-timestamp")[1:n]  # Exclude most recent
        
        if latest_pred:
            rsrp_idx, rsrq_idx = calculate_indices(latest_pred.predicted_rsrp, latest_pred.predicted_rsrq)
            predicted_data.append({
                "timestamp": latest_pred.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "lte_type": lte_type,
                "rsrp": latest_pred.predicted_rsrp, "rsrp_index": rsrp_idx,
                "rsrq": latest_pred.predicted_rsrq, "rsrq_index": rsrq_idx,
                "sinr": latest_pred.predicted_sinr,
                "lqi": round(rsrq_idx if rsrq_idx >= 0.25 else rsrp_idx, 2),
                "link_condition": get_link_condition(rsrq_idx)
            })

        for pred in pred_records:
            rsrp_idx, rsrq_idx = calculate_indices(pred.predicted_rsrp, pred.predicted_rsrq)
            predicted_data.append({
                "timestamp": pred.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "lte_type": lte_type,
                "rsrp": pred.predicted_rsrp, "rsrp_index": rsrp_idx,
                "rsrq": pred.predicted_rsrq, "rsrq_index": rsrq_idx,
                "sinr": pred.predicted_sinr,
                "lqi": round(rsrq_idx if rsrq_idx >= 0.25 else rsrp_idx, 2),
                "link_condition": get_link_condition(rsrq_idx)
            })

    return rf_data, predicted_data

# # def apply_switching_logic():
#     config = load_config()
#     n = config["num_test_instances"]
#     lt = config["loss_threshold"]

#     link_data = {}

#     for lte_type in ["LTE1", "LTE2"]:
#         predicted_values = PredictedParameters.objects.filter(lte_type=lte_type).order_by("-timestamp")[:n]
#         loss_values = PacketLoss.objects.filter(lte_type=lte_type).order_by("-timestamp")[:n]

#         if len(predicted_values) < n:
#             continue

#         # Calculate Avg LQI
#         avg_lqi = sum(calculate_indices(pred.predicted_rsrp, pred.predicted_rsrq)[1] for pred in predicted_values) / n

#         # Assign LQI category based on index
#         if avg_lqi >= 0.75:
#             lqi_category = "Excellent"
#         elif avg_lqi >= 0.25:
#             lqi_category = "Good"
#         else:
#             lqi_category = "Weak"

#         # Calculate Avg Packet Loss
#         avg_packet_loss = sum(loss.packet_loss for loss in loss_values) / len(loss_values) if loss_values else 0
#         prl_flag = 1 if avg_packet_loss > lt else 0

#         # Switching Logic (SI)
#         lqia = 1 if avg_lqi < 0.25 else 0
#         si = 1 if (lqia == 1 and prl_flag == 1) else 0

#         # Recommended Action
#         recommended_action = "No Switch" if si == 0 else "Switch to Alternate"

#         link_data[lte_type] = {
#             "lte_type": lte_type,
#             "avg_lqi": lqi_category,  
#             "packet_loss": avg_packet_loss,
#             "LQIa": lqia,
#             "PRL": prl_flag,
#             "SI": si,
#             "recommended_action": recommended_action
#         }

#     # Convert dictionary to list for template iteration
#     switching_result = list(link_data.values())

#     # Final Switching Recommendation
#     if "LTE1" in link_data and "LTE2" in link_data:
#         if link_data["LTE1"]["SI"] == 1 and link_data["LTE2"]["SI"] == 1:
#             switch_decision = "No Switch Needed"
#         elif link_data["LTE1"]["SI"] == 1 and link_data["LTE2"]["SI"] == 0:
#             switch_decision = "Switch to LTE1"
#         elif link_data["LTE1"]["SI"] == 0 and link_data["LTE2"]["SI"] == 1:
#             switch_decision = "Switch to LTE2"
#         else:
#             switch_decision = "Both links are degraded"
#     else:
#         switch_decision = "Insufficient Data"

#     return {"switching_result": switching_result, "switch_decision": switch_decision}

def apply_switching_logic():
    """
    Switching Logic that uses loss_per_instance to calculate average packet loss
    
    Key Steps:
    1. Read loss_per_instance from config
    2. Filter records with packet loss greater than loss_per_instance
    3. Calculate average packet loss only for those filtered records
    4. Determine PRL flag based on this average
    """
    config = load_config()
    n = config["num_test_instances"]
    lt = config["loss_threshold"]
    loss_per_instance = config.get("loss_per_instance", 5)  # Default to 5 if not specified

    link_data = {}

    for lte_type in ["LTE1", "LTE2"]:
        # Get the most recent n records for each LTE type
        packet_loss_records = PacketLossRecord.objects.filter(
            lte_type=lte_type
        ).order_by('-timestamp')[:n]

        if len(packet_loss_records) < n:
            continue

        # Filter records with packet loss greater than loss_per_instance
        high_loss_records = [
            record for record in packet_loss_records 
            if record.packet_loss > loss_per_instance
        ]

        # Calculate average packet loss for records above loss_per_instance
        # If no records exceed loss_per_instance, avg_packet_loss will be 0
        avg_packet_loss = (
            sum(record.packet_loss for record in high_loss_records) / len(high_loss_records) 
            if high_loss_records else 0
        )

        # PRL Flag: 1 if average packet loss is greater than loss threshold, 0 otherwise
        prl_flag = 1 if avg_packet_loss > lt else 0

        # Get the most recent RF and Predicted data for context
        latest_predicted = PredictedParameters.objects.filter(
            lte_type=lte_type
        ).order_by('-timestamp').first()

        if latest_predicted:
            # Calculate LQI based on predicted parameters
            rsrp_idx, rsrq_idx = calculate_indices(
                latest_predicted.predicted_rsrp, 
                latest_predicted.predicted_rsrq
            )
            avg_lqi = round(rsrq_idx if rsrq_idx >= 0.25 else rsrp_idx, 2)

            # Assign LQI category
            if avg_lqi >= 0.75:
                lqi_category = "Excellent"
            elif avg_lqi >= 0.25:
                lqi_category = "Good"
            else:
                lqi_category = "Weak"

            # Switching Logic
            lqia = 1 if avg_lqi < 0.25 else 0
            si = 1 if (lqia == 1 and prl_flag == 1) else 0

            # Recommended Action
            recommended_action = "No Switch" if si == 0 else "Switch to Alternate"

            link_data[lte_type] = {
                "lte_type": lte_type,
                "avg_lqi": lqi_category,
                "packet_loss": avg_packet_loss,
                "LQIa": lqia,
                "PRL": prl_flag,
                "SI": si,
                "recommended_action": recommended_action,
                "latency": packet_loss_records[0].latency,
                "jitter": packet_loss_records[0].jitter,
                "high_loss_count": len(high_loss_records)  # Added for transparency
            }

    # Convert dictionary to list for template iteration
    switching_result = list(link_data.values())

    # Final Switching Recommendation
    if "LTE1" in link_data and "LTE2" in link_data:
        if link_data["LTE1"]["SI"] == 1 and link_data["LTE2"]["SI"] == 1:
            switch_decision = "Both links are degraded"
        elif link_data["LTE1"]["SI"] == 1 and link_data["LTE2"]["SI"] == 0:
            switch_decision = "Switch to LTE2"
        elif link_data["LTE1"]["SI"] == 0 and link_data["LTE2"]["SI"] == 1:
            switch_decision = "Switch to LTE1"
        else:
            switch_decision = "No Switch Needed"
    else:
        switch_decision = "Insufficient Data"

    return {"switching_result": switching_result, "switch_decision": switch_decision}



# API Endpoint
def lte_view(request):
    rf_data, predicted_data = fetch_rf_and_predicted_data()  # ✅ Fetch RF & Predicted Data
    switching_result = apply_switching_logic()

    return render(request, "network_monitoring/lte.html", {
        "rf_data": rf_data,  
        "predicted_data": predicted_data,  
        "switching_result": switching_result["switching_result"],  
        "switch_decision": switching_result["switch_decision"]
    })
