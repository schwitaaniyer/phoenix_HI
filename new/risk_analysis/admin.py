from django.contrib import admin

# Register your models here.



#24/04/25


# from django.contrib import admin
# from .models import PacketAnalysis, Settings, AnalysisLog, SevereFlowLog

# @admin.register(Settings)
# class SettingsAdmin(admin.ModelAdmin):
#     list_display = ['log_retention_minutes']

# @admin.register(AnalysisLog)
# class AnalysisLogAdmin(admin.ModelAdmin):
#     list_display = ['created_at', 'message']
#     list_filter = ['created_at']
#     search_fields = ['message']

# @admin.register(SevereFlowLog)
# class SevereFlowLogAdmin(admin.ModelAdmin):
#     list_display = ['created_at', 'first_seen', 'source_ip', 'destination_ip', 'protocol', 'ndpi_protocol']
#     list_filter = ['created_at', 'protocol']
#     search_fields = ['source_ip', 'destination_ip']

# @admin.register(PacketAnalysis)
# class PacketAnalysisAdmin(admin.ModelAdmin):
#     list_display = ['first_seen', 'source_ip', 'destination_ip', 'protocol', 'ndpi_protocol']
#     list_filter = ['protocol', 'ndpi_protocol']
#     search_fields = ['source_ip', 'destination_ip']






#25/04/25


from django.contrib import admin
from .models import PacketAnalysis, Settings, SevereFlowLog

@admin.register(Settings)
class SettingsAdmin(admin.ModelAdmin):
    list_display = ['log_retention_minutes']

@admin.register(SevereFlowLog)
class SevereFlowLogAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'first_seen', 'source_ip', 'destination_ip', 'protocol', 'ndpi_protocol']
    list_filter = ['created_at', 'protocol']
    search_fields = ['source_ip', 'destination_ip']

@admin.register(PacketAnalysis)
class PacketAnalysisAdmin(admin.ModelAdmin):
    list_display = ['first_seen', 'source_ip', 'destination_ip', 'protocol', 'ndpi_protocol']
    list_filter = ['protocol', 'ndpi_protocol']
    search_fields = ['source_ip', 'destination_ip']