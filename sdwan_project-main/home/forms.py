from django import forms
from django import forms
from .models import LDAPConfig

class LDAPConfigForm(forms.ModelForm):
    class Meta:
        model = LDAPConfig
        fields = ["server_uri", "bind_dn", "bind_password", "user_search_base"]
        widgets = {
            "bind_password": forms.PasswordInput(),
        }
