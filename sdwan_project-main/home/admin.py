from django.contrib import admin
from home.models import Contact
from django.contrib import admin
from .models import Page, PagePermission

@admin.register(Page)
class PageAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(PagePermission)
class PagePermissionAdmin(admin.ModelAdmin):
    list_display = ('group', 'page', 'can_read', 'can_write')
    list_filter = ('group', 'page')
    search_fields = ('group__name', 'page__name')

admin.site.register(Contact)
from django.contrib import admin
from .models import LDAPConfig

@admin.register(LDAPConfig)
class LDAPConfigAdmin(admin.ModelAdmin):
    list_display = ("server_uri", "user_search_base")
    fieldsets = (
        ("LDAP Server Settings", {
            "fields": ("server_uri", "bind_dn", "bind_password")
        }),
        ("Search Settings", {
            "fields": ("user_search_base",)
        }),
    )
