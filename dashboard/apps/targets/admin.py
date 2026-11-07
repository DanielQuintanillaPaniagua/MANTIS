from django.contrib import admin

from .models import TargetRecord


@admin.register(TargetRecord)
class TargetRecordAdmin(admin.ModelAdmin):
    list_display = ("name", "base_url", "authorized", "created_at")
    list_filter = ("authorized",)