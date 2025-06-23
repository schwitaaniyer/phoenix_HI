#24/04/25

# from celery import shared_task
# from django.utils import timezone
# from .models import AnalysisLog, Settings
# from datetime import timedelta

# @shared_task
# def cleanup_old_logs():
#     try:
#         settings = Settings.objects.first()
#         if not settings:
#             settings = Settings.objects.create(log_retention_minutes=60)
#         retention_minutes = settings.log_retention_minutes
#         cutoff = timezone.now() - timedelta(minutes=retention_minutes)
#         deleted_count, _ = AnalysisLog.objects.filter(created_at__lt=cutoff).delete()
#         return f"Deleted {deleted_count} old logs"
#     except Exception as e:
#         return f"Error cleaning logs: {str(e)}"





#25/04/25


from celery import shared_task
from .logging_config import setup_logger

@shared_task
def rotate_logs():
    try:
        logger = setup_logger()
        for handler in logger.handlers:
            if hasattr(handler, 'doRollover'):
                handler.doRollover()
        return "Log rotation triggered"
    except Exception as e:
        return f"Error rotating logs: {str(e)}"
