"""Views for scans: list, detail, new."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from .forms import ScanForm
from .models import FindingRecord, Scan
from .services import run_scan


@login_required
def scan_list(request):
    scans = Scan.objects.all()
    return render(request, "scans/scan_list.html", {"scans": scans})


@login_required
def scan_detail(request, pk):
    scan = get_object_or_404(Scan, pk=pk)
    findings = scan.findings.all()
    return render(
        request,
        "scans/scan_detail.html",
        {"scan": scan, "findings": findings},
    )


@login_required
def scan_new(request):
    if request.method == "POST":
        form = ScanForm(request.POST)
        if form.is_valid():
            # 1. Guardamos el Scan (el nuevo formulario ya rellena options_json, spec_path y base_url)
            scan = form.save()

            # 2. Recuperamos las API keys del formulario
            identity_a_key = form.cleaned_data["identity_a_key"]
            identity_b_key = form.cleaned_data["identity_b_key"]
            
            # 3. Ejecutamos el motor
            run_scan(scan=scan, identity_a_key=identity_a_key, identity_b_key=identity_b_key)

            # 4. Feedback
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


@login_required
def finding_detail(request, pk):
    finding = get_object_or_404(FindingRecord, pk=pk)
    return render(request, "scans/finding_detail.html", {"finding": finding})


@login_required
def finding_list(request):
    """Global list of findings, filterable by type, severity and text search."""
    findings = FindingRecord.objects.select_related("scan").all()

    type_filter = request.GET.get("type", "")
    severity_filter = request.GET.get("severity", "")
    query = request.GET.get("q", "")

    if type_filter:
        findings = findings.filter(type=type_filter)
    if severity_filter:
        findings = findings.filter(severity=severity_filter)
    if query:
        findings = findings.filter(
            Q(summary__icontains=query) | 
            Q(operation_path__icontains=query) |
            Q(finding_id__icontains=query)
        )

    return render(
        request,
        "scans/finding_list.html",
        {
            "findings": findings,
            "type_filter": type_filter,
            "severity_filter": severity_filter,
            "query": query,
            "all_types": [t[0] for t in FindingRecord.TYPE_CHOICES],
            "all_severities": [s[0] for s in FindingRecord.SEVERITY_CHOICES],
        },
    )