"""URLs for reports."""

from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("", views.report_list, name="list"),
    path("<int:pk>/download/", views.report_download, name="download"),
]