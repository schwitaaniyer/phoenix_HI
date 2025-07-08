# celery.py - nk

from __future__ import absolute_import, unicode_literals
import os
import json
from celery import Celery
from celery.schedules import schedule  # ✅ Corrected import
from django.conf import settings

# Set the default Django settings module for Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Hello.settings')

app = Celery('Hello',
             broker='redis://localhost:6379/0',  # Redis as broker
             backend='redis://localhost:6379/0')  # Redis as result backend

# Configure Celery from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Path to config file
CONFIG_PATH = os.path.join(settings.BASE_DIR, "config.json")

def get_celery_interval():
    """Reads the interval (in minutes) from the config file."""
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
            interval_minutes = int(config.get("celery_interval", 2))  # Default: 2 min
            return interval_minutes * 60  # Convert minutes to seconds
    except Exception as e:
        print(f"Error reading config: {e}")
        return 120  # Default 2 minutes

# Define Celery Beat schedule dynamically
app.conf.beat_schedule = {
    'fetch-network-data-every-minute': {
        'task': 'network_monitoring.tasks.fetch_and_predict_data',
        'schedule': schedule(get_celery_interval()),  # ✅ Corrected usage
    },
}

# Automatically discover tasks from installed apps.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')