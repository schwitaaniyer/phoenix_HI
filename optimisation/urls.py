from django.urls import path
from .views import OptimisationView

app_name = 'optimisation'

urlpatterns = [
    path('', OptimisationView.as_view(), name='index'),
]