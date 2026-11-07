"""Models for scans and findings.

These are Django models, separate from the mantis analysis dataclasses.
Conversion happens explicitly in services.py.
"""

from django.db import models


class Scan(models.Model):
    """A single scan run."""

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    spec_path = models.CharField(max_length=500)
    spec_title = models.CharField(max_length=200, blank=True)
    base_url = models.CharField(max_length=500, default="http://127.0.0.1:8000")
    identity_a = models.CharField(max_length=100)
    identity_b = models.CharField(max_length=100)
    options_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    findings_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Scan #{self.pk} ({self.spec_title or self.spec_path}) [{self.status}]"


class FindingRecord(models.Model):
    """A finding stored in the dashboard DB."""

    TYPE_CHOICES = [
        ("BOLA", "BOLA"),
        ("BFLA", "BFLA"),
        ("STATE_SKIP", "State Skip"),
    ]
    SEVERITY_CHOICES = [
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
    ]
    CONFIDENCE_CHOICES = [
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    finding_id = models.CharField(max_length=300)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    confidence = models.CharField(max_length=20, choices=CONFIDENCE_CHOICES)
    operation_method = models.CharField(max_length=10)
    operation_path = models.CharField(max_length=500)
    identity = models.CharField(max_length=100)
    summary = models.TextField()
    details = models.TextField()
    evidence_json = models.JSONField(default=list, blank=True)
    reproduction_json = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-severity", "finding_id"]

    def __str__(self) -> str:
        return f"{self.finding_id} ({self.type})"