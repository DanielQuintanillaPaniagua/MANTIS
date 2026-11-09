"""Views for reports."""

from pathlib import Path

from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, render

from .models import ReportRecord


def report_list(request):
    reports = ReportRecord.objects.select_related("scan").all()
    return render(request, "reports/report_list.html", {"reports": reports})


def report_download(request, pk):
    report = get_object_or_404(ReportRecord, pk=pk)
    path = Path(report.file_path)
    if not path.exists():
        raise Http404("Report file not found on disk")
    return FileResponse(
        path.open("rb"),
        as_attachment=True,
        filename=path.name,
    )