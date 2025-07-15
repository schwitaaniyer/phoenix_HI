from django import forms
from .models import AuthenticationMethod, PrivilegeLevel, UserProfile
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthMethodForm(forms.ModelForm):
    class Meta:
        model = AuthenticationMethod
        fields = ['method']

class LDAPConfigForm(forms.Form):
    server_uri = forms.CharField(label='LDAP Server URI', max_length=255)
    base_dn = forms.CharField(label='Base DN', max_length=255)
    user_dn_template = forms.CharField(label='User DN Template', max_length=255)

class TACACSConfigForm(forms.Form):
    server = forms.CharField(label='TACACS+ Server', max_length=255)
    port = forms.IntegerField(label='Port', initial=49)
    secret = forms.CharField(label='Secret', max_length=255, widget=forms.PasswordInput)

class RADIUSConfigForm(forms.Form):
    server = forms.CharField(label='RADIUS Server', max_length=255)
    secret = forms.CharField(label='Secret', max_length=255, widget=forms.PasswordInput)

class PrivilegeLevelForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['privilege_level']

class UserCreateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
    password = forms.CharField(widget=forms.PasswordInput)

class UserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email'] 