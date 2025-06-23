from django.core.management.base import BaseCommand
from django_celery_beat.models import PeriodicTask, IntervalSchedule

class Command(BaseCommand):
    help = "Schedule periodic tasks for predictions"

    def handle(self, *args, **kwargs):
        # Create or retrieve an interval schedule
        schedule, created = IntervalSchedule.objects.get_or_create(
            every=2,
            period=IntervalSchedule.MINUTES,
        )

        # Add a periodic task for running predictions
        task, created = PeriodicTask.objects.get_or_create(
            interval=schedule,
            name="Run Predictions",
            task="network_monitoring.tasks.run_prediction",
        )

        if created:
            self.stdout.write(self.style.SUCCESS("Prediction task scheduled to run every 2 minutes."))
        else:
            self.stdout.write(self.style.WARNING("Prediction task already exists."))
