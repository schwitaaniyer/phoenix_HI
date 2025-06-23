import os
import json
import subprocess
import time
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from network_monitoring.models import PacketLossRecord
from django.utils.timezone import now

CONFIG_PATH = "config.json"

class Command(BaseCommand):
    help = "Monitor network packet loss and store in database"

    def handle(self, *args, **kwargs):
        if not os.path.exists(CONFIG_PATH):
            self.stdout.write(self.style.ERROR("Config file not found!"))
            return

        # Load config values
        with open(CONFIG_PATH, "r") as file:
            config = json.load(file)

        packets_per_test = config.get("packets_per_test", 100)
        time_between_instances = config.get("time_between_instances", 2)  # Default 2 min

        while True:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                # Execute fping command
                result = subprocess.run(
                    ["fping", "-C", str(packets_per_test), "-q", "8.8.8.8"],
                    capture_output=True,
                    text=True,
                )

                output = result.stdout.strip().split()
                loss_count = output.count("-")
                total_packets = len(output) - 1
                packet_loss = (loss_count / total_packets) * 100 if total_packets else 100

                # Calculate Latency & Jitter
                valid_rtt = [float(x) for x in output[1:] if x != "-"]
                avg_latency = sum(valid_rtt) / len(valid_rtt) if valid_rtt else None
                jitter = sum(abs(valid_rtt[i] - valid_rtt[i - 1]) for i in range(1, len(valid_rtt))) / (len(valid_rtt) - 1) if len(valid_rtt) > 1 else None

                # Save to database
                PacketLossRecord.objects.create(packet_loss=packet_loss, latency=avg_latency, jitter=jitter)

                # Delete records older than 1 hour
                one_hour_ago = now() - timedelta(hours=1)
                PacketLossRecord.objects.filter(timestamp__lt=one_hour_ago).delete()

                self.stdout.write(f"[{timestamp}] Loss: {packet_loss}% Latency: {avg_latency}ms Jitter: {jitter}ms")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error: {e}"))

            # Wait before next execution
            time.sleep(time_between_instances * 60)
