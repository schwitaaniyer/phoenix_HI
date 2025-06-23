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
                valid_rtt = [x for x in output[1:]]  # Collecting raw RTT values (including '-')

                # Loss count
                loss_count = valid_rtt.count("-")
                total_packets = len(valid_rtt)
                packet_loss = (loss_count / total_packets) * 100 if total_packets else 100

                # Store latency as raw values (or None if all lost)
                latency_values = [float(x) if x != "-" else None for x in valid_rtt]
                jitter_values = []
                
                # Compute jitter as raw difference between consecutive valid RTTs
                for i in range(1, len(latency_values)):
                    if latency_values[i] is not None and latency_values[i - 1] is not None:
                        jitter_values.append(abs(latency_values[i] - latency_values[i - 1]))

                # Format latency and jitter correctly as strings with "ms"
                avg_latency = sum(filter(None, latency_values)) / len(filter(None, latency_values)) if latency_values else 0
                raw_latency = f"{avg_latency:.5f}ms" if avg_latency else "0ms"

                avg_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0
                raw_jitter = f"{avg_jitter:.5f}ms" if avg_jitter else "0ms"

                # Save to database
                PacketLossRecord.objects.create(
                    packet_loss=packet_loss,
                    latency=raw_latency,  # Store as string
                    jitter=raw_jitter,  # Store as string
                )

                # Delete records older than 1 hour
                one_hour_ago = now() - timedelta(hours=1)
                PacketLossRecord.objects.filter(timestamp__lt=one_hour_ago).delete()

                # Print exact values to the terminal
                self.stdout.write(f"[{timestamp}] Loss: {packet_loss}% Latency: {raw_latency} Jitter: {raw_jitter}")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error: {e}"))

            # Wait before next execution
            time.sleep(time_between_instances * 60)
