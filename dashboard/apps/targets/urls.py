"""URLs for targets."""

from django.urls import path

from . import views

app_name = "targets"

urlpatterns = [
    path("", views.target_list, name="list"),
    path("new/", views.target_new, name="new"),
    path("<int:pk>/edit/", views.target_edit, name="edit"),
    path("<int:pk>/delete/", views.target_delete, name="delete"),
]