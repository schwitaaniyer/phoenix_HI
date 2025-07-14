from django.urls import path
from . import views

app_name = 'system'

urlpatterns = [
    # Logs and processes
    path('logs/', views.LogsView.as_view(), name='logs'),
    
    # System information
    path('info/', views.SystemInfoView.as_view(), name='info'),
    
    # LEDs and ports
    path('interfaces/', views.interfaces_view, name='interfaces'),
    
    # Configuration
    path('configuration/', views.ConfigurationView.as_view(), name='configuration'),
    
    # Port management
    path('ports/<str:port_name>/toggle/', views.toggle_port, name='toggle_port'),
    path('ports/<str:port_name>/edit/', views.edit_port, name='edit_port'),
    # VLAN, Bridge, Team, and IP management
    path('vlans/create/', views.create_vlan, name='create_vlan'),
    path('bridges/create/', views.create_bridge, name='create_bridge'),
    path('teams/create/', views.create_team, name='create_team'),
    path('ports/<str:port_name>/edit_ip/', views.edit_ip, name='edit_ip'),
]