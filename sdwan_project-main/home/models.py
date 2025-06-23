from django.db import models
from django.contrib.auth.models import Group

class Contact(models.Model):
    name = models.CharField(max_length=122)
    email = models.CharField(max_length=122)
    phone = models.CharField(max_length=12)
    desc = models.TextField()
    date = models.DateField()

    def __str__(self):
        return self.name


class Page(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name  # Display the Page name in the admin and elsewhere


class PagePermission(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    page = models.ForeignKey(Page, on_delete=models.CASCADE)
    can_read = models.BooleanField(default=False)
    can_write = models.BooleanField(default=False)

    def __str__(self):
        # Use meaningful representation for PagePermission
        return f"{self.group.name} - {self.page.name} (Read: {self.can_read}, Write: {self.can_write})"


class LDAPConfig(models.Model):
    server_uri = models.URLField("LDAP Server URI")
    bind_dn = models.CharField("Bind DN", max_length=255)
    bind_password = models.CharField("Bind Password", max_length=255)
    user_search_base = models.CharField("User Search Base", max_length=255)

    def __str__(self):
        return f"LDAP Config ({self.server_uri})"
    class Meta:
        verbose_name = "LDAP Configuration"  # Singular
        verbose_name_plural = "LDAP Configurations"