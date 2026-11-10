"""Context processors for global dashboard data."""

from apps.scans.models import Scan


def notifications(request):
    """Provide recent system events for the notification bell."""
    # Get the last 3 failed scans and last 3 completed scans with findings
    failed_scans = Scan.objects.filter(status="failed").order_by("-created_at")[:3]
    finding_scans = Scan.objects.filter(status="completed", findings_count__gt=0).order_by("-created_at")[:3]

    events = []

    for scan in failed_scans:
        events.append({
            "type": "danger",
            "icon": "bi-x-circle-fill",
            "text": f"Scan #{scan.pk} failed",
            "time": scan.created_at,
        })

    for scan in finding_scans:
        events.append({
            "type": "warning",
            "icon": "bi-exclamation-triangle-fill",
            "text": f"Scan #{scan.pk} found {scan.findings_count} issues",
            "time": scan.created_at,
        })

    # Sort by time (newest first) and take top 5
    events.sort(key=lambda x: x["time"], reverse=True)
    events = events[:5]

    return {
        "notifications_list": events,
        "notifications_count": len(events),
    }