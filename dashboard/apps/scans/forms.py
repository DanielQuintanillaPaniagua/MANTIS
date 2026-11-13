""""Forms for the scans app."""

from django import forms
from apps.targets.models import TargetRecord
from .models import Scan


class ScanForm(forms.ModelForm):
    """Form to launch a new scan against an authorized target."""

    target = forms.ModelChoiceField(
        queryset=TargetRecord.objects.filter(authorized=True),
        label="Authorized Target",
        empty_label="-- Select an authorized target --",
    )
    
    identity_a_key = forms.CharField(widget=forms.PasswordInput, label="Identity A API key")
    identity_b_key = forms.CharField(widget=forms.PasswordInput, label="Identity B API key")
    sequences = forms.BooleanField(required=False, label="Run sequences (BFLA + state skip)")
    
    # Configuración avanzada (oculta por defecto o simple)
    reset_endpoint = forms.CharField(required=False, initial="/lab/reset", label="Reset Endpoint")

    class Meta:
        model = Scan
        fields = ["identity_a", "identity_b"]
        widgets = {
            "identity_a": forms.TextInput(attrs={"placeholder": "admin"}),
            "identity_b": forms.TextInput(attrs={"placeholder": "employee"}),
        }

    def clean_target(self):
        target = self.cleaned_data["target"]
        if not target.authorized:
            raise forms.ValidationError("This target is not authorized for testing.")
        return target

    def save(self, commit=True):
        instance = super().save(commit=False)
        target = self.cleaned_data["target"]
        
        # Mapear datos del Target al Scan
        instance.spec_path = target.spec_path
        instance.spec_title = target.name
        instance.base_url = target.base_url
        
        # Opciones
        instance.options_json = {
            "sequences": self.cleaned_data.get("sequences", False),
            "reset_endpoint": self.cleaned_data.get("reset_endpoint") or None,
            "privileged_operations": ["approve"], # Podríamos añadirlo al form
            "allowed_transitions": ["status:draft->submitted", "status:submitted->approved"],
            "max_requests": 200
        }
        
        if commit:
            instance.save()
        return instance