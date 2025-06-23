from django import forms

class RetentionForm(forms.Form):
    log_retention_minutes = forms.IntegerField(
        min_value=1,
        label="Log Retention (minutes)",
        help_text="Enter the duration to retain logs (minimum 1 minute).",
        widget=forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 200px;'})
    ) 