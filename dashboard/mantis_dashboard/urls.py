from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(template_name="login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("scans/", include("apps.scans.urls")),
    path("targets/", include("apps.targets.urls")),
    path("reports/", include("apps.reports.urls")),
    path("", include("apps.core.urls")),
]