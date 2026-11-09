"""URL configuration for mantis_dashboard."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("scans/", include("apps.scans.urls")),
    path("targets/", include("apps.targets.urls")),
    path("reports/", include("apps.reports.urls")),
    path("", include("apps.core.urls")),
]