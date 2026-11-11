"""Integration tests for the dashboard views."""

from django.test import TestCase
from django.urls import reverse

from apps.scans.models import FindingRecord, Scan
from apps.targets.models import TargetRecord


class DashboardViewsTest(TestCase):
    def setUp(self):
        self.scan = Scan.objects.create(
            spec_path="dummy.json", identity_a="a", identity_b="b", status="completed"
        )
        self.finding = FindingRecord.objects.create(
            scan=self.scan, finding_id="BOLA-1", type="BOLA", severity="high",
            confidence="high", operation_method="GET", operation_path="/test",
            identity="employee", summary="Test BOLA", details="Details"
        )

    def test_dashboard_home_renders(self):
        response = self.client.get(reverse("core:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "MANTIS")
        self.assertContains(response, "Overview")

    def test_scan_list_renders(self):
        response = self.client.get(reverse("scans:list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Scans")

    def test_finding_list_renders_with_search(self):
        # Normal render
        response = self.client.get(reverse("scans:finding_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test BOLA")

        # Search render
        response = self.client.get(reverse("scans:finding_list") + "?q=BOLA")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test BOLA")
        
        # Search with no match
        response = self.client.get(reverse("scans:finding_list") + "?q=NONEXISTENT")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Test BOLA")

    def test_targets_crud_views(self):
        response = self.client.post(reverse("targets:new"), {
            "name": "Test Target",
            "base_url": "http://test.local",
            "authorized": True
        })
        self.assertEqual(response.status_code, 302)  # Redirect after success
        
        target = TargetRecord.objects.first()
        self.assertEqual(target.name, "Test Target")
