"""Model for authorized targets."""

from django.db import models


class TargetRecord(models.Model):
    """An API target authorized for testing."""

    name = models.CharField(max_length=200)
    base_url = models.CharField(max_length=500)
    spec_path = models.CharField(max_length=500, blank=True)
    authorized = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.base_url})"