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
            response = requests.post(self.api_url, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("result", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Zabbix data: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON response: {e}")
            return []

    def process_and_save_data(self, data):
        """Process and save data to Django models"""
        if not data:
            print("No data received to process")
            return

        lte1_params = {}
        lte2_params = {}

        for item in data:
            timestamp = timezone.make_aware(timezone.datetime.fromtimestamp(int(item["lastclock"])))
            #timestamp = timezone.datetime.fromtimestamp(int(item["lastclock"]))
                
 

            try:
                if "LTE_Inbuilt1" in item["name"] or "SIM1" in item["name"]:
                    if self._is_new_data("LTE1", timestamp):
                        self._process_lte_item(item, lte1_params, timestamp, "LTE1")
                elif "LTE_Inbuilt2" in item["name"] or "SIM2" in item["name"]:
                    if self._is_new_data("LTE2", timestamp):
                        self._process_lte_item(item, lte2_params, timestamp, "LTE2")
            except Exception as e:
                logger.error(f"Error processing item {item['name']}: {e}")

        # Save the collected data
        self._save_parameters(lte1_params, "LTE1")
        self._save_parameters(lte2_params, "LTE2")

    def _is_new_data(self, lte_type, timestamp):
        """Check if the data is new for the given LTE type and timestamp."""
        return not RFParameters.objects.filter(lte_type=lte_type, timestamp=timestamp).exists()

    def _process_lte_item(self, item, params_dict, timestamp, lte_type):
        """Helper method to process individual LTE items"""
        if "RSRP" in item["name"]:
            params_dict["rsrp"] = float(item["lastvalue"])
        elif "RSRQ" in item["name"]:
            params_dict["rsrq"] = float(item["lastvalue"])
        elif "RSSI" in item["name"]:
            params_dict["rssi"] = float(item["lastvalue"])
        elif "SINR" in item["name"]:
            params_dict["sinr"] = float(item["lastvalue"])
        elif "PacketLoss" in item["name"]:
            PacketLoss.objects.create(
                timestamp=timestamp,
                lte_type=lte_type,
                packet_loss=float(item["lastvalue"])
            )
        params_dict["timestamp"] = timestamp

    def _save_parameters(self, params, lte_type):
        """Helper method to save RF parameters"""
        required_keys = ["timestamp", "rsrp", "rsrq", "rssi", "sinr"]
        if all(key in params for key in required_keys):
            RFParameters.objects.get_or_create(
                timestamp=params["timestamp"],
                lte_type=lte_type,
                defaults={
                    "rsrp": params["rsrp"],
                    "rsrq": params["rsrq"],
                    "rssi": params["rssi"],
                    "sinr": params["sinr"],
                },
            )
