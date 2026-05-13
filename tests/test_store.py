from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from aibom.scanner import scan_path
from aibom.store import diff_scans, get_scan, list_scans, save_scan
from aibom.tuning import load_tuning_file


FIXTURES = Path(__file__).parent / "fixtures"


class StoreTestCase(unittest.TestCase):
    def test_save_and_load_scan(self) -> None:
        with TemporaryDirectory(prefix="aibom-store-") as temp_dir:
            db_path = str(Path(temp_dir) / "history.db")
            result = scan_path(FIXTURES / "python_app")
            scan_id = save_scan(result, command="scan tests/fixtures/python_app", output_format="json", db_path=db_path)
            stored = get_scan(scan_id, db_path=db_path)

            self.assertEqual(stored.scan_id, scan_id)
            self.assertEqual(stored.result.root, result.root)
            self.assertEqual(len(stored.result.findings), len(result.findings))

    def test_list_and_diff_scans(self) -> None:
        with TemporaryDirectory(prefix="aibom-store-") as temp_dir:
            db_path = str(Path(temp_dir) / "history.db")
            first = scan_path(FIXTURES / "python_app")
            second = scan_path(FIXTURES / "policy_app")
            first_id = save_scan(first, command="scan python_app", output_format="json", db_path=db_path)
            second_id = save_scan(second, command="scan policy_app", output_format="json", db_path=db_path)

            history = list_scans(db_path=db_path, limit=10)
            self.assertEqual(len(history), 2)

            diff = diff_scans(first_id, second_id, db_path=db_path)
            self.assertEqual(diff["left_scan_id"], first_id)
            self.assertEqual(diff["right_scan_id"], second_id)
            self.assertGreaterEqual(len(diff["added"]) + len(diff["removed"]), 1)

    def test_diff_reports_severity_changes_and_ignores_baseline_findings(self) -> None:
        with TemporaryDirectory(prefix="aibom-store-") as temp_dir:
            db_path = str(Path(temp_dir) / "history.db")
            baseline_tuning = load_tuning_file(str(FIXTURES / "tuning.toml"))
            first = scan_path(FIXTURES / "python_app")
            second = scan_path(FIXTURES / "python_app", tuning=baseline_tuning)
            first_id = save_scan(first, command="scan python_app", output_format="json", db_path=db_path)
            second_id = save_scan(second, command="scan python_app --tuning tuning.toml", output_format="json", db_path=db_path)

            diff = diff_scans(first_id, second_id, db_path=db_path)
            self.assertTrue(any(item["rule_id"] == "endpoint.public_ai.same_file" for item in diff["severity_changes"]))
            self.assertFalse(any(item["rule_id"] == "prompt.pattern" for item in diff["removed"]))


if __name__ == "__main__":
    unittest.main()
