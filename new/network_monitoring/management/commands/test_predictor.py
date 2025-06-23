from django.core.management.base import BaseCommand
from network_monitoring.services.predictor import predict_and_save

class Command(BaseCommand):
    help = "Test predictor logic"

    def handle(self, *args, **kwargs):
        print("Testing predictor...")
        predict_and_save("LTE1")
        predict_and_save("LTE2")
        print("Prediction completed.")
