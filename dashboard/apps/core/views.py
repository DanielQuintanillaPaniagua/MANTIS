"""Views for the core app (home page)."""

from django.shortcuts import render


def home(request):
    """Dashboard home page."""
    context = {
        "title": "Mission Control",
    }
    return render(request, "core/home.html", context)