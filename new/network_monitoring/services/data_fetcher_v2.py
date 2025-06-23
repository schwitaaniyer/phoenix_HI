# network_monitoring/services/data_fetcher.py
from django.conf import settings
from django.utils import timezone
from ..models import RFParameters, PacketLoss
import requests
import logging
from datetime import timedelta
import json

logger = logging.getLogger(__name__)

class ZabbixDataFetcher:
    def __init__(self):
        self.api_url = settings.ZABBIX_API_URL
        self.auth_token = settings.ZABBIX_AUTH_TOKEN
        self.interval = settings.ZABBIX_FETCH_INTERVAL
        print(f"Initialized ZabbixDataFetcher with URL: {self.api_url}")

    def fetch_zabbix_data(self):
        """Fetch data from Zabbix API"""
        print("Starting data fetch from Zabbix...")
        payload = {
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "output": ["itemid", "name", "lastvalue", "lastclock"],
                "host": "TESTSITE1",
                "filter": {
                    "name": [
                        "Interface LTE_Inbuilt1(): LTE modem RSRP",
                        "Interface LTE_Inbuilt1(): LTE modem RSRQ",
                        "Interface LTE_Inbuilt1(): LTE modem SINR",
                        "LTE_Inbuilt1LTE modem RSSI",
                        "PacketLoss:[SNMPPingLatencyResultSIM1.6]",
                        "Interface LTE_Inbuilt2(): LTE modem RSRP",
                        "Interface LTE_Inbuilt2(): LTE modem RSRQ",
                        "Interface LTE_Inbuilt2(): LTE modem SINR",
                        "LTE_Inbuilt2LTE modem RSSI",
                        "PacketLoss:[SNMPPingLatencyResultSIM2.7]"
                    ]
                }
            },
            "auth": self.auth_token,
            "id": 1
        }

        try:
            print(f"Sending request to Zabbix API with payload: {json.dumps(payload, indent=2)}")
            response = requests.post(self.api_url, json=payload, timeout=10)
            print(f"Received response with status code: {response.status_code}")
            
            response.raise_for_status()
            data = response.json()
            print(f"Parsed response data: {json.dumps(data, indent=2)}")
            
            result = data.get("result", [])
            print(f"Number of items received: {len(result)}")
            return result
        except requests.exceptions.RequestException as e:
            print(f"Error fetching Zabbix data: {str(e)}")
            logger.error(f"Error fetching Zabbix data: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {str(e)}")
            logger.error(f"Error parsing JSON response: {e}")
            return None

    def process_and_save_data(self, data):
        """Process and save data to Django models"""
        print(f"Starting to process data. Received {len(data) if data else 0} items")
        if not data:
            print("No data received to process")
            return

        lte1_params = {}
        lte2_params = {}
        
        for item in data:
            print(f"\nProcessing item: {item['name']}")
            timestamp = timezone.datetime.fromtimestamp(
                int(item["lastclock"])
            ) + timedelta(hours=5, minutes=30)
            print(f"Timestamp for item: {timestamp}")
            
            try:
                if "LTE_Inbuilt1" in item["name"] or "SIM1" in item["name"]:
                    print("Processing as LTE1 item")
                    if self._is_new_data("LTE1", timestamp):
                        self._process_lte_item(item, lte1_params, timestamp, "LTE1")
                    
                elif "LTE_Inbuilt2" in item["name"] or "SIM2" in item["name"]:
                    print("Processing as LTE2 item")
                    if self._is_new_data("LTE2", timestamp):
                        self._process_lte_item(item, lte2_params, timestamp, "LTE2")
            except Exception as e:
                    
                print(f"Error processing item {item['name']}: {str(e)}")
                continue

        # Save the collected data
        print("\nSaving collected parameters:")
        print(f"LTE1 params: {lte1_params}")
        print(f"LTE2 params: {lte2_params}")
        
        self._save_parameters(lte1_params, "LTE1")
        self._save_parameters(lte2_params, "LTE2")

    def _is_new_data(self, lte_type, timestamp):
        latest_entry = RFParameters.objects.filter(lte_type=lte_type).order_by('-timestamp').first()
        if latest_entry and latest_entry.timestamp >= timestamp:
            print(f"Data for {lte_type} at {timestamp} is stale. Skipping.")
            return False
        return True
            


   

    def _process_lte_item(self, item, params_dict, timestamp, lte_type):
        """Helper method to process individual LTE items"""
        print(f"Processing {lte_type} item: {item['name']}")
        try:
            if "RSRP" in item["name"]:
                params_dict["rsrp"] = float(item["lastvalue"])
            elif "RSRQ" in item["name"]:
                params_dict["rsrq"] = float(item["lastvalue"])
            elif "RSSI" in item["name"]:
                params_dict["rssi"] = float(item["lastvalue"])
            elif "SINR" in item["name"]:
                params_dict["sinr"] = float(item["lastvalue"])
            elif "PacketLoss" in item["name"]:
                print(f"Creating PacketLoss record for {lte_type}")
                PacketLoss.objects.create(
                    timestamp=timestamp,
                    lte_type=lte_type,
                    packet_loss=float(item["lastvalue"])
                )
            params_dict["timestamp"] = timestamp
            print(f"Current params_dict: {params_dict}")
        except ValueError as e:
            print(f"Error converting value for {item['name']}: {str(e)}")
            raise

    def _save_parameters(self, params, lte_type):
        """Helper method to save RF parameters"""
        print(f"\nAttempting to save parameters for {lte_type}")
        required_keys = ["timestamp", "rsrp", "rsrq", "rssi", "sinr"]
        missing_keys = [key for key in required_keys if key not in params]
        
        if missing_keys:
            print(f"Missing required keys for {lte_type}: {missing_keys}")
            return
            
        try:
            rf_params = RFParameters.objects.create(
                timestamp=params["timestamp"],
                lte_type=lte_type,
                rsrp=params["rsrp"],
                rsrq=params["rsrq"],
                rssi=params["rssi"],
                sinr=params["sinr"]
            )
            print(f"Successfully saved RFParameters record: {rf_params.id}")
        except Exception as e:
            print(f"Error saving RFParameters for {lte_type}: {str(e)}")
            raise