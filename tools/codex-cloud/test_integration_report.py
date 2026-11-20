"""Offline regression checks for the integration summary using the retained report."""

from copy import deepcopy
import unittest

import test as cloud


class IntegrationReportTests(unittest.TestCase):
    def setUp(self):
        self.report = cloud.load(cloud.ROOT / "review/codex-cloud/scan-runner-20261117/integration.json")
        # These tests cover result aggregation, independent of later runner changes.
        self.report["scan_runner_sha256"] = cloud.digest(cloud.ROOT / "tools/codex-cloud/scan.py")

    def summarize(self, report):
        return cloud.summarize_integration(report, self.report["source_sha256"])

    def ipv4_only(self):
        report = deepcopy(self.report)
        report["cases"] = [case for case in report["cases"] if case["case"].endswith("-ipv4")]
        report["scans"] = len(report["cases"])
        return report

    def test_accepts_complete_inventory_in_any_order(self):
        self.report["cases"].reverse()
        self.assertEqual(self.summarize(self.report)["scans"], 9)

    def test_accepts_ipv4_with_documented_skip(self):
        report = self.ipv4_only()
        report["ipv6_skipped"] = "Loopback unavailable"
        summary = self.summarize(report)
        self.assertEqual(summary["scans"], 7)
        self.assertEqual(summary["ipv6_skipped"], report["ipv6_skipped"])

    def test_rejects_inconsistent_case_evidence(self):
        cases = self.report["cases"]
        for label, replacement in (
            ("empty", []),
            ("missing", cases[:-1]),
            ("duplicate", cases[:-1] + [cases[0]]),
            ("unknown", cases[:-1] + [dict(cases[-1], case="unknown")]),
            ("failed", cases[:-1] + [dict(cases[-1], status="fail")]),
        ):
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                self.summarize(dict(self.report, cases=replacement))
        with self.assertRaises(RuntimeError):
            self.summarize(dict(self.report, scans=7))

    def test_rejects_missing_empty_or_contradictory_skip(self):
        ipv4 = self.ipv4_only()
        for report in (ipv4, dict(ipv4, ipv6_skipped="  "), dict(ipv4, ipv6_skipped=None),
                       dict(self.report, ipv6_skipped="Loopback unavailable")):
            with self.subTest(reason=report.get("ipv6_skipped"), scans=report["scans"]), self.assertRaises(RuntimeError):
                self.summarize(report)

    def test_requires_every_control_to_succeed(self):
        for name in self.report["controls"]:
            controls = self.report["controls"].copy()
            del controls[name]
            with self.subTest(missing=name), self.assertRaisesRegex(RuntimeError, name):
                self.summarize(dict(self.report, controls=controls))
            controls[name] = False
            with self.subTest(failed=name), self.assertRaisesRegex(RuntimeError, name):
                self.summarize(dict(self.report, controls=controls))


if __name__ == "__main__":
    unittest.main()
