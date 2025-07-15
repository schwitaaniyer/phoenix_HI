from django.contrib import admin
from .models import PrivilegeLevel, AuthenticationMethod, UserProfile

admin.site.register(PrivilegeLevel)
admin.site.register(AuthenticationMethod)
admin.site.register(UserProfile)
