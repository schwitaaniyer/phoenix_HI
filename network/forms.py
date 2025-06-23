from django import forms
from .models import BondInterface
import subprocess

class BondInterfaceForm(forms.ModelForm):
    name = forms.CharField(
        max_length=20,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g., bond0'
        }),
        help_text='Enter a name for the bond interface (e.g., bond0)'
    )
    
    mode = forms.ChoiceField(
        choices=BondInterface.BOND_MODES,
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text='Select the bonding mode'
    )
    
    slaves = forms.MultipleChoiceField(
        widget=forms.SelectMultiple(attrs={
            'class': 'form-control',
            'size': '5'
        }),
        help_text='Select slave interfaces (hold Ctrl/Cmd to select multiple)'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Get available network interfaces
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and '@' not in line:
                    iface = line.split(':')[1].strip()
                    if iface != 'lo':  # Exclude loopback
                        interfaces.append((iface, iface))
            self.fields['slaves'].choices = interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            self.fields['slaves'].choices = []

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name:
            raise forms.ValidationError('Bond interface name is required')
        if not name.startswith('bond'):
            raise forms.ValidationError('Bond interface name must start with "bond"')
        return name

    def clean_slaves(self):
        slaves = self.cleaned_data.get('slaves')
        if not slaves:
            raise forms.ValidationError('At least one slave interface is required')
        return ','.join(slaves)

    class Meta:
        model = BondInterface
        fields = ['name', 'mode', 'slaves']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'mode': forms.Select(attrs={'class': 'form-control'}),
            'slaves': forms.SelectMultiple(attrs={'class': 'form-control', 'size': '5'}),
        }
        labels = {
            'name': 'Bond Interface Name',
            'mode': 'Bonding Mode',
            'slaves': 'Slave Interfaces',
        }
        help_texts = {
            'name': 'Enter a name for the bond interface (e.g., bond0)',
            'mode': 'Select the bonding mode',
            'slaves': 'Select slave interfaces (hold Ctrl/Cmd to select multiple)',
        } 