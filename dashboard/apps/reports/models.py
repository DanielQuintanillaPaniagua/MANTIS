"""Model for exported reports."""

from django.db import models


class ReportRecord(models.Model):
    """A report file associated with a scan."""

    FORMAT_CHOICES = [
        ("json", "JSON"),
        ("markdown", "Markdown"),
    ]

    scan = models.ForeignKey(
        "scans.Scan", on_delete=models.CASCADE, related_name="reports"
    )
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES)
    file_path = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Report #{self.pk} ({self.format}) for scan #{self.scan_id}"