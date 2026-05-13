"""Structural validation of the CycloneDX 1.6 ML-BOM emitter.

These tests don't pull jsonschema (kept the project dep-free); they assert
the structural invariants required by CDX 1.6 + ML-BOM:

  - bomFormat == "CycloneDX"
  - specVersion == "1.6"
  - serialNumber matches urn:uuid:<uuid>
  - metadata.timestamp is ISO 8601 UTC
  - metadata.tools.components[*] is the 1.6 form (no deprecated tools[])
  - components[*].type is in the allowed set
  - machine-learning-model components carry a modelCard
  - services[*] use the service shape (provider, endpoints, data flows)
  - dependencies graph references the root component

A future PR adds full jsonschema validation behind an optional [test]
extra; the structural checks here cover what we can test without a dep.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from aibom.cyclonedx import (
    CDX_SPEC_VERSION,
    build_bom,
    render_cyclonedx,
)
from aibom.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


_VALID_COMPONENT_TYPES = {
    "application", "framework", "library", "container", "platform",
    "operating-system", "device", "device-driver", "firmware", "file",
    "machine-learning-model", "data", "cryptographic-asset",
}


_UUID_SERIAL_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CycloneDxStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = scan_path(FIXTURES / "python_app")
        cls.bom = build_bom(cls.result)
        cls.rendered = render_cyclonedx(cls.result)

    def test_top_level_envelope(self) -> None:
        self.assertEqual(self.bom["bomFormat"], "CycloneDX")
        self.assertEqual(self.bom["specVersion"], CDX_SPEC_VERSION)
        self.assertEqual(self.bom["specVersion"], "1.6")
        self.assertEqual(self.bom["version"], 1)

    def test_serial_number_is_urn_uuid(self) -> None:
        self.assertRegex(self.bom["serialNumber"], _UUID_SERIAL_RE)

    def test_timestamp_is_iso8601_utc(self) -> None:
        self.assertRegex(self.bom["metadata"]["timestamp"], _ISO8601_RE)

    def test_tool_uses_1_6_components_form(self) -> None:
        # CDX 1.5+ deprecates `tools` array in favor of `tools.components[]`
        tools = self.bom["metadata"]["tools"]
        self.assertIsInstance(tools, dict)
        self.assertIn("components", tools)
        self.assertNotIn("tools", self.bom["metadata"].get("tools", {}))
        names = [c["name"] for c in tools["components"]]
        self.assertIn("aibom", names)

    def test_root_component_application(self) -> None:
        root = self.bom["metadata"]["component"]
        self.assertEqual(root["type"], "application")
        self.assertTrue(root["bom-ref"].startswith("aibom:application:"))

    def test_component_types_are_valid(self) -> None:
        for component in self.bom["components"]:
            self.assertIn(component["type"], _VALID_COMPONENT_TYPES)
            self.assertIn("name", component)
            self.assertIn("bom-ref", component)

    def test_provider_routed_to_services(self) -> None:
        # OpenAI provider detection should land in services, not components
        service_names = [s["name"] for s in self.bom["services"]]
        self.assertTrue(any("OpenAI" in name for name in service_names))
        for service in self.bom["services"]:
            self.assertIn("provider", service)
            self.assertIn("data", service)
            for data_flow in service["data"]:
                self.assertIn("flow", data_flow)
                self.assertIn("classification", data_flow)

    def test_ml_model_has_modelcard(self) -> None:
        ml_models = [c for c in self.bom["components"] if c["type"] == "machine-learning-model"]
        for model in ml_models:
            self.assertIn("modelCard", model)
            self.assertIn("modelParameters", model["modelCard"])
            self.assertIn("task", model["modelCard"]["modelParameters"])

    def test_evidence_occurrences_have_path_and_line(self) -> None:
        for component in self.bom["components"]:
            for occ in component.get("evidence", {}).get("occurrences", []):
                self.assertIn("location", occ)
                self.assertIn("line", occ)
                self.assertIsInstance(occ["line"], int)

    def test_dependencies_reference_root(self) -> None:
        root_ref = self.bom["metadata"]["component"]["bom-ref"]
        deps = self.bom["dependencies"]
        self.assertEqual(deps[0]["ref"], root_ref)
        depended = set(deps[0]["dependsOn"])
        for component in self.bom["components"]:
            self.assertIn(component["bom-ref"], depended)
        for service in self.bom["services"]:
            self.assertIn(service["bom-ref"], depended)

    def test_findings_grouped_no_duplicate_components(self) -> None:
        # Same (category, name) finding repeated across files should produce
        # exactly one component with multiple evidence occurrences, not multiple
        # components.
        refs = [c["bom-ref"] for c in self.bom["components"]] + [
            s["bom-ref"] for s in self.bom["services"]
        ]
        self.assertEqual(len(refs), len(set(refs)))

    def test_rendered_is_parseable_json(self) -> None:
        parsed = json.loads(self.rendered)
        self.assertEqual(parsed["specVersion"], "1.6")

    def test_no_v1_7_anywhere(self) -> None:
        # Regression: previous emitter incorrectly reported 1.7.
        self.assertNotIn('"specVersion": "1.7"', self.rendered)


class SuppressedCategoriesAttachToRoot(unittest.TestCase):
    def test_secret_finding_becomes_root_property(self) -> None:
        # secrets_app fixture emits a `secret` category finding; under CDX
        # mapping it must NOT appear as a component, but should be visible
        # as a metadata property so ASPM consumers can link it back.
        result = scan_path(FIXTURES / "secrets_app")
        bom = build_bom(result)
        component_names = [c["name"] for c in bom["components"]]
        for name in component_names:
            self.assertNotIn("secret", name.lower())
        prop_names = [p["name"] for p in bom["metadata"]["properties"]]
        self.assertTrue(
            any(name.startswith("aibom:observation:secret:") for name in prop_names),
            f"expected suppressed secret observation in root properties, got {prop_names}",
        )


if __name__ == "__main__":
    unittest.main()
