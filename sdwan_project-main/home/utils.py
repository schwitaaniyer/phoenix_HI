from django.contrib.auth.models import Group
from .models import PagePermission

def check_permission(user, page_name, permission_type):
    """
    Checks if the user has the specified permission (read or write) for the page.
    """
    try:
        page_permission = PagePermission.objects.get(
            group__in=user.groups.all(),
            page_name=page_name
        )
        
        # Check read or write permission
        if permission_type == 'read' and page_permission.can_read:
            return True
        if permission_type == 'write' and page_permission.can_write:
            return True
        return False
    except PagePermission.DoesNotExist:
        return False

   