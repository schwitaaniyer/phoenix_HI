# network_monitoring/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('test-fetch/', views.test_fetch, name='test_fetch'),
    path('dashboard/', views.monitor_dashboard, name='monitor_dashboard'),
    path('trigger-fetch/', views.trigger_fetch_predict, name='trigger_fetch_predict'),
    path("", views.network_monitoring, name="network_monitoring"),
    path("configuration/", views.configuration_view, name="configuration"),
    path("lte/", views.lte_view, name="lte"),
    path("save_config/", views.save_config, name="save_config"),
    path("apply-switching/", views.apply_switching_logic, name="apply_switching"),
    path("get_config/", views.get_config, name="get_config"),
    path("current_status/", views.current_status, name="current_status"),


    
    
]