from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from login.views import LoginView, logout_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', include('login.urls')),
    path('system/', include('system.urls')),
    path('services/', include('services.urls')),
    path('network/', include('network.urls')),
    path('routing/', include('routing.urls')),
    path('optimisation/', include('optimisation.urls')),
    path('terminal/', include('terminal.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('', include('dashboard.urls')),
    path('api/', include('api.urls')),
]