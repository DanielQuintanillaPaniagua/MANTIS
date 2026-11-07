from django.contrib import admin

from .models import FindingRecord, Scan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "spec_title", "status", "findings_count", "created_at")
    list_filter = ("status",)
    search_fields = ("spec_title", "spec_path")


@admin.register(FindingRecord)
class FindingRecordAdmin(admin.ModelAdmin):
    list_display = ("finding_id", "type", "severity", "scan")
    list_filter = ("type", "severity", "confidence")
    search_fields = ("finding_id", "summary")