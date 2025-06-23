from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from .models import User  # Make sure to import your custom User model

class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter your password'})
    )

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email']

# Keep your PasswordChangeForm as is

#################


# from django import forms
# from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordChangeForm
# from .models import User

# class LoginForm(AuthenticationForm):
#     username = forms.EmailField(
#         label="Email",
#         widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
#     )
#     password = forms.CharField(
#         label="Password",
#         widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter your password'})
#     )

# class UserProfileForm(forms.ModelForm):
#     class Meta:
#         model = User
#         fields = ['first_name', 'last_name', 'email', 'bio', 'profile_picture']
#         widgets = {
#             'first_name': forms.TextInput(attrs={'class': 'form-control'}),
#             'last_name': forms.TextInput(attrs={'class': 'form-control'}),
#             'email': forms.EmailInput(attrs={'class': 'form-control'}),
#             'bio': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
#         }