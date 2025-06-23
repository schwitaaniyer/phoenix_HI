from django.db import models
from django.utils import timezone


# Create your models here.

from django.db import models
from django.utils.timezone import now

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









from django.db import models



# class RFParameters(models.Model):
#     timestamp = models.DateTimeField()
#     lte_type = models.CharField(max_length=10)
#     rsrp = models.FloatField()
#     rsrq = models.FloatField()
#     rssi = models.FloatField()
#     sinr = models.FloatField()

#     class Meta:
#         unique_together = ('timestamp', 'lte_type')
#         indexes = [
#             models.Index(fields=['timestamp', 'lte_type'])
#         ]

# class PacketLoss(models.Model):
#     timestamp = models.DateTimeField()
#     lte_type = models.CharField(max_length=10)
#     packet_loss = models.FloatField()

#     class Meta:
#         unique_together = ('timestamp', 'lte_type')
#         indexes = [
#             models.Index(fields=['timestamp', 'lte_type'])
#         ]

# class PredictedParameters(models.Model):
#     timestamp = models.DateTimeField()
#     lte_type = models.CharField(max_length=10)
#     predicted_rsrp = models.FloatField()
#     predicted_rsrq = models.FloatField()
#     predicted_sinr = models.FloatField()

#     class Meta:
#         unique_together = ('timestamp', 'lte_type')
#         indexes = [
#             models.Index(fields=['timestamp', 'lte_type'])
#         ]
