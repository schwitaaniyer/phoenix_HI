from django.db import models

# Create your models here.

class BondInterface(models.Model):
    BOND_MODES = [
        ('balance-rr', 'Round Robin'),
        ('active-backup', 'Active Backup'),
        ('balance-xor', 'XOR'),
        ('broadcast', 'Broadcast'),
        ('802.3ad', 'LACP'),
        ('balance-tlb', 'Adaptive Transmit Load Balancing'),
        ('balance-alb', 'Adaptive Load Balancing'),
    ]
    
    name = models.CharField(max_length=20, unique=True)
    mode = models.CharField(max_length=20, choices=BOND_MODES, default='balance-rr')
    slaves = models.CharField(max_length=255)  # Comma-separated list of slave interfaces
    status = models.CharField(max_length=10, default='down')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.mode})"

class BondStatistics(models.Model):
    interface = models.ForeignKey(BondInterface, on_delete=models.CASCADE)
    transmit = models.BigIntegerField(default=0)
    receive = models.BigIntegerField(default=0)
    failures = models.IntegerField(default=0)
    active_slave = models.CharField(max_length=20, blank=True)
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Stats for {self.interface.name}"

# --- Network Monitor Models ---
class RFParameters(models.Model):
    timestamp = models.DateTimeField()
    lte_type = models.CharField(max_length=10)  # 'LTE1' or 'LTE2'
    rsrp = models.FloatField()
    rsrq = models.FloatField()
    rssi = models.FloatField()
    sinr = models.FloatField()
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'lte_type'])
        ]

class PacketLoss(models.Model):
    timestamp = models.DateTimeField()
    lte_type = models.CharField(max_length=10)
    packet_loss = models.FloatField()
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'lte_type'])
        ]

class PredictedParameters(models.Model):
    timestamp = models.DateTimeField()
    lte_type = models.CharField(max_length=10)  # 'LTE1' or 'LTE2'
    predicted_rsrp = models.FloatField()
    predicted_rsrq = models.FloatField()
    predicted_sinr = models.FloatField()
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'lte_type'])
        ]

class PacketLossRecord(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    lte_type = models.CharField(max_length=10, null=True, blank=True)  # 'LTE1', 'LTE2', etc.
    packet_loss = models.FloatField()
    latency = models.CharField(max_length=255)  # Store latency as a string
    jitter = models.CharField(max_length=255)   # Store jitter as a string
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'lte_type'])
        ]
    
    def __str__(self):
        return f"{self.timestamp} - {self.lte_type} - Loss: {self.packet_loss}%"
