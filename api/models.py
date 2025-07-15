from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

# Create your models here.

class PrivilegeLevel(models.Model):
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)
    level = models.PositiveIntegerField(unique=True)
    editable = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.level}: {self.name}"

class AuthenticationMethod(models.Model):
    METHOD_CHOICES = [
        ('local', 'Local'),
        ('ldap', 'LDAP'),
        ('tacacs', 'TACACS+'),
        ('radius', 'RADIUS'),
    ]
    method = models.CharField(max_length=16, choices=METHOD_CHOICES, default='local')
    config = models.JSONField(default=dict, blank=True)  # Store config for LDAP/TACACS+/RADIUS
    is_global = models.BooleanField(default=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.method} ({'global' if self.is_global else self.user.username})"

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    privilege_level = models.ForeignKey(PrivilegeLevel, on_delete=models.SET_NULL, null=True)
    auth_method = models.ForeignKey(AuthenticationMethod, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Profile for {self.user.username}"
