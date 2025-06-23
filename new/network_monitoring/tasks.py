# tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .services.data_fetcher import ZabbixDataFetcher
from .services.predicton import NetworkPredictor
from .models import RFParameters, PacketLoss, PredictedParameters
import logging
from django.db import transaction

logger = logging.getLogger(__name__)

from .models import PredictedParameters

@shared_task
def fetch_and_predict_data():
    """Fetch new data, generate predictions, and clean up old data"""
    try:
        current_time = timezone.now()
        #delete_old_data()

        # Fetch new data
        fetcher = ZabbixDataFetcher()
        data = fetcher.fetch_zabbix_data()
        fetcher.process_and_save_data(data)

        delete_old_data()

        # Generate predictions
        predictor = NetworkPredictor()
        lte1_prediction = predictor.predict_next_values('LTE1')
        lte2_prediction = predictor.predict_next_values('LTE2')

        # Ensure predictions have aware timestamps
        for prediction in [lte1_prediction, lte2_prediction]:
            if prediction and 'timestamp' in prediction:
                if timezone.is_naive(prediction['timestamp']):
                    prediction['timestamp'] = timezone.make_aware(prediction['timestamp'])

                # **Save to the database**
                PredictedParameters.objects.create(
                    timestamp=prediction['timestamp'],
                    lte_type='LTE1' if prediction == lte1_prediction else 'LTE2',
                    predicted_rsrp=prediction['rsrp'],
                    predicted_rsrq=prediction['rsrq'],
                    predicted_sinr=prediction['sinr']
                )

        logger.info(f"Predictions saved to DB: LTE1={lte1_prediction}, LTE2={lte2_prediction}")

        return {
            'status': 'success',
            'timestamp': current_time,
            'predictions': {
                'LTE1': lte1_prediction,
                'LTE2': lte2_prediction
            }
        }
    except Exception as e:
        logger.error(f"Error in fetch_and_predict_data: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': timezone.now()
        }


def delete_old_data():
    """Delete records older than 60 minutes"""
    try:
        # Get current time and calculate threshold
        current_time = timezone.now()
        time_threshold = current_time - timedelta(minutes=60)

        logger.info(f"Current time: {current_time}")
        logger.info(f"Deleting data older than: {time_threshold}")

        # Get counts before deletion
        rf_count = RFParameters.objects.filter(timestamp__lt=time_threshold).count()
        packet_loss_count = PacketLoss.objects.filter(timestamp__lt=time_threshold).count()
        predicted_count = PredictedParameters.objects.filter(timestamp__lt=time_threshold).count()

        logger.info(f"Found records to delete -> RFParameters: {rf_count}, "
                   f"PacketLoss: {packet_loss_count}, "
                   f"PredictedParameters: {predicted_count}")

        # Delete old records within a transaction
        with transaction.atomic():
            rf_deleted, _ = RFParameters.objects.filter(timestamp__lt=time_threshold).delete()
            packet_loss_deleted, _ = PacketLoss.objects.filter(timestamp__lt=time_threshold).delete()
            predicted_deleted, _ = PredictedParameters.objects.filter(timestamp__lt=time_threshold).delete()

        logger.info(f"Successfully deleted:"
                   f"\n- RFParameters: {rf_deleted} records"
                   f"\n- PacketLoss: {packet_loss_deleted} records"
                   f"\n- PredictedParameters: {predicted_deleted} records")

    except Exception as e:
        logger.error(f"Error during data cleanup: {e}")
        raise




################################# Packet loss ping ##################################



from celery import shared_task
import subprocess
from .models import PacketLossRecord
from django.utils.timezone import now
import json
import os

CONFIG_PATH = "config.json"

@shared_task
def monitor_packet_loss():
    if not os.path.exists(CONFIG_PATH):
        return "Config file missing"

    with open(CONFIG_PATH, "r") as file:
        config = json.load(file)

    packets_per_test = config.get("packets_per_test", 100)

    result = subprocess.run(
        ["fping", "-C", str(packets_per_test), "-q", "8.8.8.8"],
        capture_output=True,
        text=True,
    )

    output = result.stdout.strip().split()
    loss_count = output.count("-")
    total_packets = len(output) - 1
    packet_loss = (loss_count / total_packets) * 100 if total_packets else 100

    PacketLossRecord.objects.create(packet_loss=packet_loss, timestamp=now())

    return f"Packet Loss: {packet_loss}%"
