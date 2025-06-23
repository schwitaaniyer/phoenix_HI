from django.urls import path
from .views import LoginView, logout_view, profile_view, change_password_view

app_name = 'login'

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),
    path('profile/change-password/', change_password_view, name='change_password'),
]