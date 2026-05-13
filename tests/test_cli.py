from __future__ import annotations

from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from aibom.cli import main
from aibom.models import ScanResult, ScanStats


class CliTestCase(unittest.TestCase):
    def test_scan_huggingface_command_routes_without_scan_prefix_injection(self) -> None:
        fake_result = ScanResult(root="huggingface://org/demo-model", findings=[], stats=ScanStats())
        with patch("aibom.cli.scan_huggingface_model", return_value=fake_result) as mock_scan:
            exit_code = main(["scan-huggingface", "org/demo-model", "--format", "json"])
        self.assertEqual(exit_code, 0)
        mock_scan.assert_called_once()

    def test_scan_aws_command_routes_without_scan_prefix_injection(self) -> None:
        fake_result = ScanResult(root="aws://dev/us-east-1", findings=[], stats=ScanStats())
        with patch("aibom.cli.scan_aws_account", return_value=fake_result) as mock_scan:
            exit_code = main(["scan-aws", "dev", "--region", "us-east-1", "--format", "json"])
        self.assertEqual(exit_code, 0)
        mock_scan.assert_called_once()

    def test_scan_azure_command_routes_without_scan_prefix_injection(self) -> None:
        fake_result = ScanResult(root="azure://dev/sub-123", findings=[], stats=ScanStats())
        with patch("aibom.cli.scan_azure_subscription", return_value=fake_result) as mock_scan:
            exit_code = main(["scan-azure", "dev", "--subscription-id", "sub-123", "--format", "json"])
        self.assertEqual(exit_code, 0)
        mock_scan.assert_called_once()

    def test_scan_gcp_command_routes_without_scan_prefix_injection(self) -> None:
        fake_result = ScanResult(root="gcp://dev/proj-123", findings=[], stats=ScanStats())
        with patch("aibom.cli.scan_gcp_project", return_value=fake_result) as mock_scan:
            exit_code = main(["scan-gcp", "dev", "--project-id", "proj-123", "--format", "json"])
        self.assertEqual(exit_code, 0)
        mock_scan.assert_called_once()

    def test_history_commands_work_with_temp_db(self) -> None:
        with TemporaryDirectory(prefix="aibom-cli-") as temp_dir:
            db_path = str(Path(temp_dir) / "history.db")
            fixture = Path(__file__).parent / "fixtures" / "python_app"

            with patch("sys.stdout", new_callable=StringIO), patch("sys.stderr", new_callable=StringIO):
                exit_code = main(["scan", str(fixture), "--format", "json", "--save", "--db", db_path])
            self.assertEqual(exit_code, 0)

            with patch("sys.stdout", new_callable=StringIO) as stdout:
                exit_code = main(["history", "--db", db_path, "--limit", "5"])
            self.assertEqual(exit_code, 0)
            self.assertIn("scan_id", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
