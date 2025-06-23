from django.contrib import admin
from django.urls import path
from home import views
from . import views
from django.urls import path
from .views import configure_ldap




urlpatterns = [
    path("", views.user_login, name='login'),
    # path('configure-local/', views.configure_local, name='configure_local'),
    path('configure-ldap/', views.configure_ldap, name='configure_ldap'),
    path('configure-radius/', views.configure_radius, name='configure_radius'),
    path('configure-tacas/', views.configure_tacas, name='configure_tacas'),
    path("home", views.home, name='home'),
    path("firewall", views.firewall, name='firewall'),
    path("rules", views.rules, name='rules'),
    path("blocklist", views.blocklist, name='blocklist'),
    path("services", views.services, name='services'),
    path("zones", views.zones, name='zones'), 
    path("interfaces", views.interfaces, name='interfaces'),
    path("rulesfig", views.rulesfig, name='rulesfig'),
    path("viewLog", views.log, name='log'),
    path("apply", views.apply, name='apply'),
    path("config", views.config, name='config'),
    path("capabalities", views.capabilities, name='capabilities'),
    path("plugins", views.plugins, name='plugins'),
    path("modules", views.modules, name='modules'),
    path("logging", views.logging, name='logging'),
    path("conntrack", views.conntrack, name='conntrack'),
    path("system_protection", views.system_protection, name='system_protection'),
    path("interface2", views.interface2, name='interface2'),
    path("connections/", views.connections, name='connections'),
    path('snmp/', views.snmp_config, name='snmp_config'),
    path('pie/', views.pie, name='pie'),
    path('routing', views.routing, name='routing'),
    path('networkmanagment', views.networkmanagment, name='networkmanagment'),
    path('terminal', views.terminal, name='terminal'),
    path('snmp/', views.snmp_config, name='snmp_config'), 
    path('ipsec/', views.ipsec, name='ipsec'),
    # path('ipsec/generate_psk/', views.generate_psk, name='generate_psk'),  
    path('ipsec/get_ipsec_options/', views.get_ipsec_options, name='get_ipsec_options'),
    path('ipsec/save-certificate/', views.save_ike2_certificate, name='save_ike2_certificate'),
    path('ipsec/generate-psk/', views.generate_psk, name='generate_psk'),
    path('snort/', views.snort, name='snort'),
    path('authentication', views.authentication, name='authentication'),
    path('link_conditions/', views.link_conditions, name='link_conditions'),  # For rendering the interface
    path('link_conditions/get_link_data/', views.get_link_data, name='get_link_data'),  # For fetching data
     path('logout/', views.user_logout, name='logout'),
]

    

