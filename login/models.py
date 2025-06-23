from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    # Add unique related_names to avoid clashes
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name="login_user_groups",  # Unique related_name
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="login_user_permissions",  # Unique related_name
        related_query_name="user",
    )

##################

# from django.db import models
# from django.contrib.auth.models import AbstractUser
# from django.core.validators import MinLengthValidator

# class User(AbstractUser):
#     AUTH_METHODS = [
#         ('local', 'Local'),
#         ('ldap', 'LDAP'),
#         ('tacacs', 'TACACS+'),
#         ('radius', 'RADIUS'),
#     ]
    
#     ROLES = [
#         ('admin', 'Administrator'),
#         ('operator', 'Operator'),
#         ('viewer', 'Viewer'),
#     ]
    
#     bio = models.TextField(blank=True, null=True)
#     auth_method = models.CharField(max_length=10, choices=AUTH_METHODS, default='local')
#     role = models.CharField(max_length=10, choices=ROLES, default='viewer')
#     profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    
#     def __str__(self):
#         return self.email