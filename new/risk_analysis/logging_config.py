import logging
from logging.handlers import TimedRotatingFileHandler
from .models import Settings
import os

def get_retention_seconds():
    settings = Settings.objects.first()
    if not settings:
        settings = Settings.objects.create(log_retention_minutes=60)
    return settings.log_retention_minutes * 60

class DynamicTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.when = 'S'
        self.interval = get_retention_seconds()
        self.backupCount = 1

    def doRollover(self):
        self.interval = get_retention_seconds()
        super().doRollover()

def setup_logger():
    log_dir = '/root/Project2/logs'
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'risk_analysis.log')

    logger = logging.getLogger('risk_analysis')
    logger.setLevel(logging.INFO)

    handler = DynamicTimedRotatingFileHandler(
        filename=log_file,
        when='S',
        interval=1,
        backupCount=1
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    if not logger.handlers:
        logger.addHandler(handler)

    return logger