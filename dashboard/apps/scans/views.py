"""Views for scans: list, detail, new."""

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from .forms import ScanForm
from .models import FindingRecord, Scan
from .services import run_scan


def scan_list(request):
    scans = Scan.objects.all()
    return render(request, "scans/scan_list.html", {"scans": scans})


def scan_detail(request, pk):
    scan = get_object_or_404(Scan, pk=pk)
    findings = scan.findings.all()
    return render(
        request,
        "scans/scan_detail.html",
        {"scan": scan, "findings": findings},
    )


def scan_new(request):
    if request.method == "POST":
        form = ScanForm(request.POST)
        if form.is_valid():
            scan = form.save(commit=False)
            scan.options_json = form.build_options_json()
            scan.status = "pending"
            scan.save()

            identity_a_key = form.cleaned_data["identity_a_key"]
            identity_b_key = form.cleaned_data["identity_b_key"]
            run_scan(scan=scan, identity_a_key=identity_a_key, identity_b_key=identity_b_key)

            if scan.status == "completed":
                messages.success(
                    request,
                    f"Scan completed. Findings: {scan.findings_count}",
                )
            else:
                messages.error(
                    request,
                    f"Scan failed: {scan.error_message}",
                )
            return redirect("scans:detail", pk=scan.pk)
    else:
        form = ScanForm()

    return render(request, "scans/scan_new.html", {"form": form})


def finding_detail(request, pk):
    finding = get_object_or_404(FindingRecord, pk=pk)
    return render(request, "scans/finding_detail.html", {"finding": finding})
def finding_list(request):
    """Global list of findings, filterable by type and severity."""
    findings = FindingRecord.objects.select_related("scan").all()

    type_filter = request.GET.get("type", "")
    severity_filter = request.GET.get("severity", "")

    if type_filter:
        findings = findings.filter(type=type_filter)
    if severity_filter:
        findings = findings.filter(severity=severity_filter)

    return render(
        request,
        "scans/finding_list.html",
        {
            "findings": findings,
            "type_filter": type_filter,
            "severity_filter": severity_filter,
            "all_types": [t[0] for t in FindingRecord.TYPE_CHOICES],
            "all_severities": [s[0] for s in FindingRecord.SEVERITY_CHOICES],
        },
    )