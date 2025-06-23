# risk_analysis/urls.py

from django.urls import path
from . import views

app_name = 'risk_analysis'  # Add namespace

urlpatterns = [
    path('', views.risk_analysis_view, name='risk_analysis'),
    path('start_capture/', views.start_capture, name='start_capture'),
    path('stop_capture/', views.stop_capture, name='stop_capture'),
    path('start_session_capture/', views.start_session_capture, name='start_session_capture'),
    path('stop_session_capture/', views.stop_session_capture, name='stop_session_capture'),
    path('get_latest_flows/', views.get_latest_flows, name='get_latest_flows'),
    path('add_protocol/', views.add_protocol_page, name='add_protocol_page'),
    path('add_protocol/submit/', views.add_protocol, name='add_protocol'),
    path('delete_protocol/', views.delete_protocol, name='delete_protocol'),
]