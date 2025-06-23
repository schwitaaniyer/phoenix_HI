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

@shared_task
def fetch_and_predict_data():
    """Fetch new data, generate predictions, and clean up old data"""
    try:
        # Get current time once
        current_time = timezone.now()
        
        # First clean up old data
        delete_old_data()

        # Fetch new data
        fetcher = ZabbixDataFetcher()
        data = fetcher.fetch_zabbix_data()
        fetcher.process_and_save_data(data)

        # Generate predictions
        predictor = NetworkPredictor()
        
        # Predict for both LTE types
        lte1_prediction = predictor.predict_next_values('LTE1')
        lte2_prediction = predictor.predict_next_values('LTE2')

        # Ensure predictions have aware timestamps
        for prediction in [lte1_prediction, lte2_prediction]:
            if prediction and 'timestamp' in prediction:
                if timezone.is_naive(prediction['timestamp']):
                    prediction['timestamp'] = timezone.make_aware(
                        prediction['timestamp']
                    )

        logger.info(f"Current time: {current_time}")
        logger.info(f"LTE1 Prediction: {lte1_prediction}")
        logger.info(f"LTE2 Prediction: {lte2_prediction}")

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