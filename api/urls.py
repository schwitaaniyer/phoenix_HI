from django.urls import path
from .views import (
    SystemInfoAPIView,
    NetworkInterfacesAPIView,
    ServicesListAPIView,
    FirewallStatusAPIView,
    SystemLogsAPIView,
    ProcessListAPIView,
)
from . import views

urlpatterns = [
    path('system/info/', SystemInfoAPIView.as_view(), name='system-info'),
    path('network/interfaces/', NetworkInterfacesAPIView.as_view(), name='network-interfaces'),
    path('services/list/', ServicesListAPIView.as_view(), name='services-list'),
    path('firewall/status/', FirewallStatusAPIView.as_view(), name='firewall-status'),
    path('logs/', SystemLogsAPIView.as_view(), name='system-logs'),
    path('processes/', ProcessListAPIView.as_view(), name='process-list'),
    path('auth/config/', views.authentication_config, name='auth-config'),
    path('auth/set_method/', views.set_auth_method, name='set-auth-method'),
    path('auth/set_ldap/', views.set_ldap_config, name='set-ldap-config'),
    path('auth/set_tacacs/', views.set_tacacs_config, name='set-tacacs-config'),
    path('auth/set_radius/', views.set_radius_config, name='set-radius-config'),
    path('auth/privilege_levels/', views.get_privilege_levels, name='get-privilege-levels'),
    path('auth/users/', views.get_users, name='get-users'),
    path('auth/set_user_privilege/', views.set_user_privilege, name='set-user-privilege'),
]

urlpatterns += [
    path('services/snmp/status/', views.snmp_status, name='snmp-status'),
    path('services/snmp/control/', views.snmp_control, name='snmp-control'),
    path('services/ips/status/', views.ips_status, name='ips-status'),
    path('services/ips/control/', views.ips_control, name='ips-control'),
    path('services/ipsec/status/', views.ipsec_status, name='ipsec-status'),
    path('services/ipsec/control/', views.ipsec_control, name='ipsec-control'),
] 