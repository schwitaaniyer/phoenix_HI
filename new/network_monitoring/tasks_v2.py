# network_monitoring/tasks.py

from celery import shared_task
from celery.utils.log import get_task_logger
from .services.predictor import predict_and_save
from .services.data_fetcher import ZabbixDataFetcher
from django.db import transaction
import traceback

logger = get_task_logger(__name__)

@shared_task(bind=True, max_retries=3)
def fetch_and_predict_data(self):
    """Fetch new data and generate predictions"""
    try:
        logger.info("Starting data fetch and prediction task...")
        
        # Fetch new data
        fetcher = ZabbixDataFetcher()
        data = fetcher.fetch_zabbix_data()
        
        if not data:
            logger.warning("No data received from Zabbix API")
            return False
            
        # Use transaction to ensure data consistency
        with transaction.atomic():
            fetcher.process_and_save_data(data)
            logger.info("Data fetch and save completed")
            
            # Generate predictions
            logger.info("Starting prediction...")
            predict_and_save("LTE1")
            predict_and_save("LTE2")
            logger.info("Prediction completed")
            
        return True

    except Exception as e:
        logger.error(f"Error in fetch_and_predict_data: {traceback.format_exc()}")
        # Retry the task
        self.retry(exc=e, countdown=60)  # Retry after 60 seconds