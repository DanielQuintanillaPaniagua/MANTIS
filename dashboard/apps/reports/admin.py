from django.contrib import admin

from .models import ReportRecord


@admin.register(ReportRecord)
class ReportRecordAdmin(admin.ModelAdmin):
    list_display = ("id", "scan", "format", "created_at")
    list_filter = ("format",)