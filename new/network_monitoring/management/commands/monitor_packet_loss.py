# monitor_packet_loss.py

import os
import json
import subprocess
import time
import concurrent.futures
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from network_monitoring.models import PacketLossRecord
from django.utils.timezone import now

CONFIG_PATH = "config.json"

class Command(BaseCommand):
    help = "Monitor network packet loss and store in database"

    def ping_and_process(self, lte_type, test_ip, interface, packets_per_test, timestamp):
        """Run ping test for a specific LTE connection and return results"""
        try:
            # Execute fping command with config values
            result = subprocess.run(
                ["fping", "-I", interface, "-C", str(packets_per_test), "-q", test_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            # Process the output
            output = result.stdout.strip()
            
            # Parse the fping output
            loss = 0
            sum_latency = 0
            count = 0
            prev = -1
            jitter_sum = 0
            jitter_count = 0
            
            # Split the output and process each value
            values = []
            for line in output.split('\n'):
                if ":" in line and "icmp_seq" not in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        values = parts[1].strip().split()
                        break
            
            # If no values found, try an alternative parsing method
            if not values and output:
                # Sometimes fping output might be in a different format
                all_words = output.split()
                # Find where the ping values start (after the target IP)
                try:
                    ip_index = all_words.index(test_ip)
                    if ip_index + 1 < len(all_words):
                        values = all_words[ip_index+1:]
                except ValueError:
                    pass
            
            # Process values to calculate metrics
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
            
            # Calculate metrics
            total_packets = packets_per_test
            packet_loss = (loss / total_packets) * 100 if total_packets > 0 else 100
            avg_latency = sum_latency / count if count > 0 else 0
            avg_jitter = jitter_sum / jitter_count if jitter_count > 0 else 0
            
            # Format as strings with "ms"
            formatted_latency = f"{avg_latency:.5f}ms" if avg_latency else "0ms"
            formatted_jitter = f"{avg_jitter:.5f}ms" if avg_jitter else "0ms"

            # Log message
            log_message = f"{timestamp} {lte_type} Loss: {packet_loss}% Latency: {formatted_latency} Jitter: {formatted_jitter}"
            self.stdout.write(log_message)

            # Also log to file
            with open("network_log.txt", "a") as log_file:
                log_file.write(f"{log_message}\n")

            return {
                "lte_type": lte_type,
                "packet_loss": packet_loss,
                "latency": formatted_latency,
                "jitter": formatted_jitter,
                "success": True
            }

        except Exception as e:
            error_message = f"Error testing {lte_type} ({test_ip}): {str(e)}"
            self.stdout.write(self.style.ERROR(error_message))
            # Log error to file
            with open("network_log.txt", "a") as log_file:
                log_file.write(f"{timestamp} {error_message}\n")
            
            return {
                "lte_type": lte_type,
                "success": False,
                "error": str(e)
            }

    def handle(self, *args, **kwargs):
        if not os.path.exists(CONFIG_PATH):
            self.stdout.write(self.style.ERROR("Config file not found!"))
            return

        while True:
            # Read config values fresh each time to pick up any changes
            try:
                with open(CONFIG_PATH, "r") as file:
                    config = json.load(file)
                
                # Log loaded config for debugging
                self.stdout.write(f"Loaded config: {config}")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error reading config: {e}"))
                time.sleep(60)  # Wait a minute before retrying
                continue

            # Get all values from config with defaults
            packets_per_test = int(config.get("packets_per_test", 100))
            time_between_instances = int(config.get("time_between_instances", 2))
            interface = config.get("interface", "ens224")
            
            # Get test IPs from config
            test_ips = config.get("test_ips", [{"type": "LTE1", "ip": "8.8.8.8"}, {"type": "LTE2", "ip": "8.8.4.4"}])
            
            # Log the actual values being used
            self.stdout.write(f"Using: packets={packets_per_test}, interval={time_between_instances}min")
            self.stdout.write(f"Testing {len(test_ips)} LTE connections simultaneously")
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Use ThreadPoolExecutor to run all ping tests concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(test_ips)) as executor:
                # Start all ping tests at the same time
                future_to_lte = {
                    executor.submit(
                        self.ping_and_process, 
                        ip_config["type"], 
                        ip_config["ip"], 
                        interface, 
                        packets_per_test,
                        timestamp
                    ): ip_config["type"] for ip_config in test_ips
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_lte):
                    result = future.result()
                    if result["success"]:
                        # Save to database with LTE type
                        PacketLossRecord.objects.create(
                            lte_type=result["lte_type"],
                            packet_loss=result["packet_loss"],
                            latency=result["latency"],
                            jitter=result["jitter"],
                        )
            
            # Delete records older than 1 hour
            one_hour_ago = now() - timedelta(hours=1)
            PacketLossRecord.objects.filter(timestamp__lt=one_hour_ago).delete()

            # Wait before next execution
            wait_time = time_between_instances * 60
            self.stdout.write(f"Waiting {time_between_instances} minutes before next test...")
            time.sleep(wait_time)