from django.urls import re_path
from .consumers import VtyshConsoleConsumer

websocket_urlpatterns = [
    re_path(r'ws/vtysh/$', VtyshConsoleConsumer.as_asgi()),
] 