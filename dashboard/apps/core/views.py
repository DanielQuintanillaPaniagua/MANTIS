"""Views for the core app (home page)."""

from django.db.models import Count
from django.shortcuts import render

from apps.scans.models import FindingRecord, Scan
from django.contrib.auth.decorators import login_required
@login_required


def home(request):
    """Dashboard home with stats."""
    total_scans = Scan.objects.count()
    completed = Scan.objects.filter(status="completed").count()
    failed = Scan.objects.filter(status="failed").count()
    total_findings = FindingRecord.objects.count()

    by_type = (
        FindingRecord.objects.values("type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    by_severity = (
        FindingRecord.objects.values("severity")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    recent_scans = Scan.objects.all()[:5]

    context = {
        "total_scans": total_scans,
        "completed": completed,
        "failed": failed,
        "total_findings": total_findings,
        "by_type": list(by_type),
        "by_severity": list(by_severity),
        "recent_scans": recent_scans,
    }
    return render(request, "core/home.html", context)