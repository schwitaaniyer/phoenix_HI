from django.urls import path
from . import views

app_name = 'terminal'

urlpatterns = [
    path('', views.TerminalView.as_view(), name='index'),
]