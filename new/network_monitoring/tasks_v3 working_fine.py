

# network_monitoring/tasks.py
from celery import shared_task
from django.utils import timezone
from .services.data_fetcher import ZabbixDataFetcher
from .services.predicton import NetworkPredictor
import logging

logger = logging.getLogger(__name__)

@shared_task
def fetch_and_predict_data():
    """Fetch new data and generate predictions"""
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