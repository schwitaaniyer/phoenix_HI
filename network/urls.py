from django.urls import path
from .views import (
    FirewallView, OptimisationView, BondingView, 
    MonitorView, DPIView, RoutingView, MPTCPView,
    mptcp_endpoint_show, mptcp_endpoint_add, mptcp_endpoint_delete,
    mptcp_endpoint_change, mptcp_limits_show, mptcp_limits_set,
    mptcp_monitor
)
from . import views
from .monitor_views import (
    monitor_config_view, monitor_analysis_view, get_monitor_config, get_monitor_status
)

app_name = 'network'

urlpatterns = [
    path('routing/', RoutingView.as_view(), name='routing'),
    path('firewall/', FirewallView.as_view(), name='firewall'),
    path('optimisation/', OptimisationView.as_view(), name='optimisation'),
    path('bonding/', BondingView.as_view(), name='bonding'),
    path('monitor/', MonitorView.as_view(), name='monitor'),
    path('dpi/', DPIView.as_view(), name='dpi'),
    path('bonding/<str:bond_name>/delete/', BondingView.as_view(), name='delete_bond'),
    path('mptcp/', MPTCPView.as_view(), name='mptcp'),
    path('mptcp/endpoint/show/', mptcp_endpoint_show, name='mptcp_endpoint_show'),
    path('mptcp/endpoint/add/', mptcp_endpoint_add, name='mptcp_endpoint_add'),
    path('mptcp/endpoint/<int:endpoint_id>/delete/', mptcp_endpoint_delete, name='mptcp_endpoint_delete'),
    path('mptcp/endpoint/<int:endpoint_id>/change/', mptcp_endpoint_change, name='mptcp_endpoint_change'),
    path('mptcp/limits/show/', mptcp_limits_show, name='mptcp_limits_show'),
    path('mptcp/limits/set/', mptcp_limits_set, name='mptcp_limits_set'),
    path('mptcp/monitor/', mptcp_monitor, name='mptcp_monitor'),
    path('monitor/config/', monitor_config_view, name='monitor_config'),
    path('monitor/analysis/', monitor_analysis_view, name='monitor_analysis'),
    path('monitor/get_config/', get_monitor_config, name='monitor_get_config'),
    path('monitor/get_status/', get_monitor_status, name='monitor_get_status'),
]