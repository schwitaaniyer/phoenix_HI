import requests
import logging
import json
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from ..models import RFParameters, PacketLoss
from datetime import timedelta
from celery import shared_task

logger = logging.getLogger(__name__)

class ZabbixDataFetcher:
    def __init__(self):
        self.api_url = settings.ZABBIX_API_URL
        self.auth_token = settings.ZABBIX_AUTH_TOKEN
        self.interval = settings.ZABBIX_FETCH_INTERVAL

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
            return response.json().get("result", [])
        except Exception as e:
            logger.error(f"Zabbix data fetch error: {e}")
            return None

    @transaction.atomic
    def process_and_save_data(self, data):
        """Process and save data with transaction and deduplication"""
        if not data:
            return

        lte1_params = {}
        lte2_params = {}
        
        for item in data:
            timestamp = timezone.datetime.fromtimestamp(
                int(item["lastclock"])
            ) + timedelta(hours=5, minutes=30)
            
            try:
                if "LTE_Inbuilt1" in item["name"] or "SIM1" in item["name"]:
                    self._process_lte_item(item, lte1_params, timestamp, "LTE1")
                elif "LTE_Inbuilt2" in item["name"] or "SIM2" in item["name"]:
                    self._process_lte_item(item, lte2_params, timestamp, "LTE2")
            except Exception as e:
                logger.error(f"Item processing error: {e}")
                continue

        self._save_parameters(lte1_params, "LTE1")
        self._save_parameters(lte2_params, "LTE2")

    def _process_lte_item(self, item, params_dict, timestamp, lte_type):
        """Process individual LTE items"""
        if "RSRP" in item["name"]:
            params_dict["rsrp"] = float(item["lastvalue"])
        elif "RSRQ" in item["name"]:
            params_dict["rsrq"] = float(item["lastvalue"])
        elif "RSSI" in item["name"]:
            params_dict["rssi"] = float(item["lastvalue"])
        elif "SINR" in item["name"]:
            params_dict["sinr"] = float(item["lastvalue"])
        elif "PacketLoss" in item["name"]:
            PacketLoss.objects.get_or_create(
                timestamp=timestamp,
                lte_type=lte_type,
                defaults={'packet_loss': float(item["lastvalue"])}
            )
        params_dict["timestamp"] = timestamp

    def _save_parameters(self, params, lte_type):
        """Save RF parameters with deduplication"""
        required_keys = ["timestamp", "rsrp", "rsrq", "rssi", "sinr"]
        if not all(key in params for key in required_keys):
            return

        RFParameters.objects.get_or_create(
            timestamp=params["timestamp"],
            lte_type=lte_type,
            defaults={
                'rsrp': params["rsrp"],
                'rsrq': params["rsrq"],
                'rssi': params["rssi"],
                'sinr': params["sinr"]
            }
        )

@shared_task
def fetch_zabbix_data_task():
    """Celery task to fetch and process Zabbix data"""
    fetcher = ZabbixDataFetcher()
    data = fetcher.fetch_zabbix_data()
    if data:
        fetcher.process_and_save_data(data)