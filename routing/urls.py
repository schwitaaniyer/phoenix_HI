from django.urls import path
from .views import RoutingView

app_name = 'routing'

urlpatterns = [
    path('', RoutingView.as_view(), name='index'),
]