from django.urls import path
from . import views

app_name = 'system'

urlpatterns = [
    # Logs and processes
    path('logs/', views.LogsView.as_view(), name='logs'),
    
    # System information
    path('info/', views.SystemInfoView.as_view(), name='info'),
    
    # LEDs and ports
    path('leds-ports/', views.leds_ports_view, name='leds_ports'),
    
    # Configuration
    path('configuration/', views.ConfigurationView.as_view(), name='configuration'),
    
    # Port management
    path('ports/<str:port_name>/toggle/', views.toggle_port, name='toggle_port'),
    path('ports/<str:port_name>/edit/', views.edit_port, name='edit_port'),
]