"""Forms for the scans app."""

from django import forms

from .models import Scan


class ScanForm(forms.ModelForm):
    """Form to launch a new scan."""

    identity_a_key = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="Identity A API key",
        help_text="Privileged identity (e.g. lab-admin-key)",
    )
    identity_b_key = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="Identity B API key",
        help_text="Limited identity (e.g. lab-employee-key)",
    )

    sequences = forms.BooleanField(
        required=False,
        initial=False,
        label="Run sequences (BFLA + state skip)",
    )
    privileged_operations = forms.CharField(
        required=False,
        initial="approve",
        label="Privileged operations",
        help_text="Comma-separated substrings (e.g. approve)",
    )
    allowed_transitions = forms.CharField(
        required=False,
        initial="status:draft->submitted, status:submitted->approved",
        label="Allowed transitions",
        help_text="Comma-separated FIELD:FROM->TO",
    )
    max_requests = forms.IntegerField(
        required=False,
        initial=200,
        label="Max requests per session",
    )

    class Meta:
        model = Scan
        fields = ["spec_path", "spec_title", "base_url", "identity_a", "identity_b"]
        widgets = {
            "spec_path": forms.TextInput(attrs={"placeholder": "examples/openapi/mantis-lab.json"}),
            "spec_title": forms.TextInput(attrs={"placeholder": "MANTIS Lab"}),
            "base_url": forms.TextInput(attrs={"placeholder": "http://127.0.0.1:8000"}),
            "identity_a": forms.TextInput(attrs={"placeholder": "admin"}),
            "identity_b": forms.TextInput(attrs={"placeholder": "employee"}),
        }

    def clean_privileged_operations(self):
        raw = self.cleaned_data.get("privileged_operations", "")
        return [x.strip() for x in raw.split(",") if x.strip()]

    def clean_allowed_transitions(self):
        raw = self.cleaned_data.get("allowed_transitions", "")
        return [x.strip() for x in raw.split(",") if x.strip()]

    def build_options_json(self) -> dict:
        return {
            "sequences": self.cleaned_data.get("sequences", False),
            "privileged_operations": self.cleaned_data.get("privileged_operations", []),
            "allowed_transitions": self.cleaned_data.get("allowed_transitions", []),
            "max_requests": self.cleaned_data.get("max_requests") or 200,
        }