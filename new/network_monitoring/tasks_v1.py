# network_monitoring/tasks.py
from celery import shared_task
from .services.data_fetcher import ZabbixDataFetcher

@shared_task
def fetch_network_data():
    """Celery task to fetch and save network data"""
    fetcher = ZabbixDataFetcher()
    data = fetcher.fetch_zabbix_data()
    fetcher.process_and_save_data(data)




# # network_monitoring/tasks.py
# from celery import shared_task
# from django.utils import timezone
# from .services.data_fetcher import ZabbixDataFetcher
# from .services.predicton import NetworkPredictor
# import logging

# logger = logging.getLogger(__name__)

# @shared_task
# def fetch_and_predict_data():
#     """Fetch new data and generate predictions"""
#     try:
#         # Fetch new data
#         fetcher = ZabbixDataFetcher()
#         data = fetcher.fetch_zabbix_data()
#         fetcher.process_and_save_data(data)
        
#         # Generate predictions
#         predictor = NetworkPredictor()
        
#         # Predict for both LTE types
#         lte1_prediction = predictor.predict_next_values('LTE1')
#         lte2_prediction = predictor.predict_next_values('LTE2')
        
#         logger.info(f"LTE1 Prediction: {lte1_prediction}")
#         logger.info(f"LTE2 Prediction: {lte2_prediction}")
        
#         return {
#             'status': 'success',
#             'timestamp': timezone.now(),
#             'predictions': {
#                 'LTE1': lte1_prediction,
#                 'LTE2': lte2_prediction
#             }
#         }
#     except Exception as e:
#         logger.error(f"Error in fetch_and_predict_data: {e}")
#         return {
#             'status': 'error',
#             'error': str(e)
#         }
    


# # network_monitoring/tasks.py
# from celery import shared_task
# from .services.data_fetcher import ZabbixDataFetcher
# from .services.predictor import predict_and_save

# @shared_task
# def fetch_network_data():
#     fetcher = ZabbixDataFetcher()
#     data = fetcher.fetch_zabbix_data()
#     fetcher.process_and_save_data(data)


# logger = logging.getLogger(__name__)

# @shared_task
# def run_prediction():
#     """Run predictions for LTE1 and LTE2."""
#     logger.info("Starting prediction task.")
#     predict_and_save("LTE1")
#     predict_and_save("LTE2")
#     logger.info("Prediction task completed.")




# network_monitoring/tasks.py
from celery import shared_task
from .services.data_fetcher import ZabbixDataFetcher
from .services.predictor import predict_and_save
from django.utils.timezone import now, timedelta
from .models import RFParameters

# @shared_task  ==================== WORKING (27.01.25/ 12:47)
# def fetch_and_predict_data():
#     """Fetch data, save it to the database, and generate predictions."""
#     try:
#         # Step 1: Fetch and save network data
#         fetcher = ZabbixDataFetcher()
#         data = fetcher.fetch_zabbix_data()
#         fetcher.process_and_save_data(data)

#         # Step 2: Run predictions
#         predict_and_save("LTE1")
#         predict_and_save("LTE2")

#         # Step 3: Prune old data (keep only the last 1 hour)
#         cutoff_time = now() - timedelta(hours=1)
#         RFParameters.objects.filter(timestamp__lt=cutoff_time).delete()

#         print("Fetch, predict, and pruning completed.")
#     except Exception as e:
#         print(f"Error in fetch_and_predict_data: {e}")















@shared_task
def fetch_and_predict_data():
    """Fetch new data and generate predictions"""
    try:
        print("Starting data fetch and prediction task...")
        
        # Fetch new data
        fetcher = ZabbixDataFetcher()
        data = fetcher.fetch_zabbix_data()
        fetcher.process_and_save_data(data)
        
        print("Data fetch completed.")
        
        # Generate predictions
        print("Starting prediction...")
        predict_and_save("LTE1")
        predict_and_save("LTE2")
        print("Prediction completed.")
    except Exception as e:
        print(f"Error in fetch_and_predict_data: {e}")
