from functools import wraps
from django.shortcuts import render, get_object_or_404
from django.shortcuts import render, get_object_or_404
from home.models import Page, PagePermission


def check_page_permissions(page_name):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Fetch the page and user's group
            page = get_object_or_404(Page, name=page_name)
            user_group = request.user.groups.first()
            permission = PagePermission.objects.filter(group=user_group, page=page).first()

            # No permission
            if not permission:
                return render(request, 'no_permission.html', {'message': "You do not have permissions for this page."})

            # Read-only permission
            if permission.can_read and not permission.can_write:
                return render(request, 'less_priv.html', {
                    'message': "You do not have permission to perform this action. Please contact the administrator."
                })

            # Allow access if write permission exists
            if permission.can_write:
                return view_func(request, *args, **kwargs)

            # Fallback
            return render(request, 'no_permission.html', {'message': "You do not have permissions for this page."})
        return wrapper
    return decorator
