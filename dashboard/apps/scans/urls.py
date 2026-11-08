"""URLs for scans."""

from django.urls import path

from . import views

app_name = "scans"

urlpatterns = [
    path("", views.scan_list, name="list"),
    path("new/", views.scan_new, name="new"),
    path("<int:pk>/", views.scan_detail, name="detail"),
    path("findings/<int:pk>/", views.finding_detail, name="finding_detail"),
]