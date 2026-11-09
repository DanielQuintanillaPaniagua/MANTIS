"""Forms for targets."""

from django import forms

from .models import TargetRecord


class TargetForm(forms.ModelForm):
    class Meta:
        model = TargetRecord
        fields = ["name", "base_url", "spec_path", "authorized", "notes"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Local Lab"}),
            "base_url": forms.TextInput(attrs={"placeholder": "http://127.0.0.1:8000"}),
            "spec_path": forms.TextInput(attrs={"placeholder": "examples/openapi/mantis-lab.json"}),
            "notes": forms.Textarea(attrs={"rows": 3, "placeholder": "Authorized for testing on 2026-11-01"}),
        }