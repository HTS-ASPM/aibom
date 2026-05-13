"""BOM signing helpers — Sigstore-friendly, dep-free.

We deliberately do not call Sigstore directly (cosign requires
OIDC + ambient identity that the scanner cannot synthesize). Instead:

  hash_bom(bom_json_bytes)            -> sha256 hex (canonical)
  build_signature_manifest(bom_path)  -> dict the user can hand to
                                          cosign sign-blob, sigstore-py,
                                          or any other signer
  invoke_cosign(bom_path, key_ref)    -> opt-in subprocess wrapper that
                                          shells out to `cosign` if
                                          present. Never required.

The manifest shape mirrors Sigstore's bundle layout enough to be
round-tripped: artifact + sha256 + intended signer + (optional)
witness URL. This keeps the AiBOM CLI dep-free while making the
signing handoff trivial.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SignatureManifest:
    artifact_path: str
    sha256: str
    intended_signer: str
    rekor_log_url: str | None = None
    cosign_command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_path": self.artifact_path,
            "sha256": self.sha256,
            "intended_signer": self.intended_signer,
            "rekor_log_url": self.rekor_log_url,
            "cosign_command": self.cosign_command,
        }


def hash_bom(bom_bytes: bytes) -> str:
    return hashlib.sha256(bom_bytes).hexdigest()


def hash_bom_file(bom_path: Path) -> str:
    h = hashlib.sha256()
    with bom_path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonicalize_bom(bom: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding — same input always hashes the same.

    Required for reproducible signatures. We intentionally normalize:
      - sort keys at every level
      - strict ASCII output (escape non-ASCII)
      - no insignificant whitespace
    """
    return json.dumps(bom, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def build_signature_manifest(
    bom_path: Path,
    *,
    intended_signer: str,
    rekor_log_url: str | None = "https://rekor.sigstore.dev",
    key_ref: str | None = None,
) -> SignatureManifest:
    """Compute the manifest the user would feed into a signer."""
    digest = hash_bom_file(bom_path)
    cmd = _suggested_cosign_command(bom_path, key_ref)
    return SignatureManifest(
        artifact_path=str(bom_path),
        sha256=digest,
        intended_signer=intended_signer,
        rekor_log_url=rekor_log_url,
        cosign_command=cmd,
    )


def invoke_cosign(
    bom_path: Path,
    *,
    key_ref: str,
    output_signature: Path,
    output_certificate: Path | None = None,
    runner=None,
) -> dict[str, Any]:
    """Optional subprocess wrapper. Returns {"status": <int>, "stderr": ..., "stdout": ...}.

    When a ``runner`` is provided (tests / wrappers) we hand it the full
    argv with literal "cosign" as the binary name — no PATH lookup
    happens. Without a runner we resolve cosign on PATH and shell out;
    if cosign is absent we raise FileNotFoundError so the caller can
    fall back to ``build_signature_manifest`` for an external signer.
    """
    if runner is not None:
        cmd = _build_cosign_cmd("cosign", bom_path, key_ref, output_signature, output_certificate)
        return runner(cmd)
    cosign_path = shutil.which("cosign")
    if cosign_path is None:
        raise FileNotFoundError(
            "cosign not found on PATH — install Sigstore cosign or use build_signature_manifest only"
        )
    cmd = _build_cosign_cmd(cosign_path, bom_path, key_ref, output_signature, output_certificate)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    return {"status": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def _build_cosign_cmd(
    binary: str,
    bom_path: Path,
    key_ref: str,
    output_signature: Path,
    output_certificate: Path | None,
) -> list[str]:
    cmd = [
        binary, "sign-blob",
        "--yes",
        "--key", key_ref,
        "--output-signature", str(output_signature),
    ]
    if output_certificate is not None:
        cmd.extend(["--output-certificate", str(output_certificate)])
    cmd.append(str(bom_path))
    return cmd


# --------------------------------------------------------------------------- #

def _suggested_cosign_command(bom_path: Path, key_ref: str | None) -> str:
    key_arg = f" --key {key_ref}" if key_ref else ""
    return (
        f"cosign sign-blob --yes{key_arg} "
        f"--output-signature {bom_path}.sig "
        f"--output-certificate {bom_path}.cert "
        f"{bom_path}"
    )
