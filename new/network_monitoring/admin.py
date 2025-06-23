# Register your models here.
from django.contrib import admin
from .models import RFParameters, PacketLoss

@admin.register(RFParameters)
class RFParametersAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'lte_type', 'rsrp', 'rsrq', 'rssi', 'sinr')
    list_filter = ('lte_type', 'timestamp')
    search_fields = ('lte_type',)

@admin.register(PacketLoss)
class PacketLossAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'lte_type', 'packet_loss')
    list_filter = ('lte_type', 'timestamp')
    search_fields = ('lte_type',)

from django.contrib import admin
from .models import PredictedParameters

@admin.register(PredictedParameters)
class PredictedParametersAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'lte_type', 'predicted_rsrp', 'predicted_rsrq', 'predicted_sinr')
    list_filter = ('lte_type', 'timestamp')
    search_fields = ('lte_type',)



from .models import PacketLossRecord


@admin.register(PacketLossRecord)
class PacketLossRecordAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'lte_type', 'packet_loss', 'latency', 'jitter')
    list_filter = ('lte_type', 'timestamp')
    search_fields = ('lte_type', 'packet_loss')