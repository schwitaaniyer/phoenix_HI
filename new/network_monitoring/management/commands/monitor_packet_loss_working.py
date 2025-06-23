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
        interface = config.get("interface", "ens224")  # Get interface from config or use default

        while True:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                # Execute fping command with interface flag, matching the shell script
                # Fix: Use stdout and stderr parameters instead of capture_output
                result = subprocess.run(
                    ["fping", "-I", interface, "-C", str(packets_per_test), "-q", "8.8.8.8"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # Redirect stderr to stdout
                    text=True
                )

                # Process the output in the same way as the shell script
                output = result.stdout.strip()
                
                # Parse the fping output similar to the awk script
                loss = 0
                sum_latency = 0
                count = 0
                prev = -1
                jitter_sum = 0
                jitter_count = 0
                
                # Split the output and process each value
                # fping output has values after the first line which contains target info
                values = []
                for line in output.split('\n'):
                    if ":" in line and "icmp_seq" not in line:  # Get the line with RTT values
                        parts = line.split(':')
                        if len(parts) > 1:
                            values = parts[1].strip().split()
                            break
                
                for val in values:
                    if val == "-":
                        loss += 1
                    else:
                        try:
                            float_val = float(val)
                            sum_latency += float_val
                            count += 1
                            
                            if prev != -1:
                                jitter = abs(float_val - prev)
                                jitter_sum += jitter
                                jitter_count += 1
                            
                            prev = float_val
                        except ValueError:
                            continue
                
                # Calculate metrics exactly as in the shell script
                packet_loss = (loss / packets_per_test) * 100
                avg_latency = sum_latency / count if count > 0 else 0
                avg_jitter = jitter_sum / jitter_count if jitter_count > 0 else 0
                
                # Format as strings with "ms" to match expected output
                formatted_loss = f"{packet_loss}%"
                formatted_latency = f"{avg_latency:.5f}ms" if avg_latency else "0ms"
                formatted_jitter = f"{avg_jitter:.5f}ms" if avg_jitter else "0ms"

                # Save to database
                PacketLossRecord.objects.create(
                    packet_loss=packet_loss,
                    latency=formatted_latency,
                    jitter=formatted_jitter,
                )

                # Delete records older than 1 hour
                one_hour_ago = now() - timedelta(hours=1)
                PacketLossRecord.objects.filter(timestamp__lt=one_hour_ago).delete()

                # Print exact values to the terminal in the expected format
                self.stdout.write(f"{timestamp} Loss: {formatted_loss} Latency: {formatted_latency} Jitter: {formatted_jitter}")

                # Also log to file like the shell script if needed
                with open("network_log.txt", "a") as log_file:
                    log_file.write(f"{timestamp} Loss: {formatted_loss} Latency: {formatted_latency} Jitter: {formatted_jitter}\n")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error: {e}"))
                # Log error to file as well
                with open("network_log.txt", "a") as log_file:
                    log_file.write(f"{timestamp} Error: {str(e)}\n")

            # Wait before next execution
            time.sleep(time_between_instances * 60)