from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .services.data_fetcher import ZabbixDataFetcher
from .services.predicton import NetworkPredictor
from .models import RFParameters, PacketLoss, PredictedParameters
import logging
import csv
import os

logger = logging.getLogger(__name__)

ARCHIVE_DIR = "/path/to/archives/"  # Change this to your desired archive directory

@shared_task
def fetch_and_predict_data():
    """Fetch new data, generate predictions, and clean up old data"""
    try:
        # Fetch new data
        fetcher = ZabbixDataFetcher()
        data = fetcher.fetch_zabbix_data()
        fetcher.process_and_save_data(data)

        # Generate predictions
        predictor = NetworkPredictor()

        # Predict for both LTE types
        lte1_prediction = predictor.predict_next_values('LTE1')
        lte2_prediction = predictor.predict_next_values('LTE2')

        logger.info(f"LTE1 Prediction: {lte1_prediction}")
        logger.info(f"LTE2 Prediction: {lte2_prediction}")

        # Archive and delete old data
        cleanup_old_data()

        return {
            'status': 'success',
            'timestamp': timezone.now(),
            'predictions': {
                'LTE1': lte1_prediction,
                'LTE2': lte2_prediction
            }
        }
    except Exception as e:
        logger.error(f"Error in fetch_and_predict_data: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }



def archive_and_delete(model, model_name, time_threshold):
    """Helper function to archive and delete old records"""
    old_records = model.objects.filter(timestamp__lt=time_threshold)
    if old_records.exists():
        file_path = os.path.join(ARCHIVE_DIR, f"{model_name}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv")

        # Save to CSV
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([field.name for field in model._meta.fields])  # Write headers
            for record in old_records:
                writer.writerow([getattr(record, field.name) for field in model._meta.fields])  # Write data

        logger.info(f"Archived {old_records.count()} {model_name} records to {file_path}")

        # Delete old records
        deleted_count, _ = old_records.delete()
        logger.info(f"Deleted {deleted_count} old {model_name} records.")


def cleanup_old_data():
    """Archive and delete records older than 60 minutes"""
    time_threshold = timezone.now() - timedelta(minutes=60)

    # Ensure archive directory exists
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    # Archive and delete RFParameters
    archive_and_delete(RFParameters, "RFParameters", time_threshold)

    # Archive and delete PacketLoss
    archive_and_delete(PacketLoss, "PacketLoss", time_threshold)

    # Archive and delete PredictedParameters
    archive_and_delete(PredictedParameters, "PredictedParameters", time_threshold)