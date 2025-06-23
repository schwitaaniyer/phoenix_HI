from django.urls import path
from . import views

app_name = 'services'

urlpatterns = [
    # IPSec Services
    path('ipsec/', views.IPsecView.as_view(), name='ipsec'),
    
    # VPN Services
    path('vpn/', views.VPNView.as_view(), name='vpn'),
    
    # SNMP Services
    path('snmp/', views.SNMPView.as_view(), name='snmp'),
    
    # IPS/IDS Services
    path('ips-ids/', views.IPSIDSView.as_view(), name='ips_ids'),
    
    # Risk Analysis
    path('risk-analysis/', views.risk_analysis_view, name='risk_analysis'),
    path('risk-analysis/start_capture/', views.start_capture, name='start_capture'),
    path('risk-analysis/stop_capture/', views.stop_capture, name='stop_capture'),
    path('risk-analysis/start_session_capture/', views.start_session_capture, name='start_session_capture'),
    path('risk-analysis/stop_session_capture/', views.stop_session_capture, name='stop_session_capture'),
    path('risk-analysis/get_latest_flows/', views.get_latest_flows, name='get_latest_flows'),
    path('risk-analysis/add_protocol/', views.add_protocol_page, name='add_protocol_page'),
    path('risk-analysis/add_protocol/submit/', views.add_protocol, name='add_protocol'),
    path('risk-analysis/delete_protocol/', views.delete_protocol, name='delete_protocol'),
    
    # Authentication Services
    path('authentication/', views.AuthenticationView.as_view(), name='authentication'),
]