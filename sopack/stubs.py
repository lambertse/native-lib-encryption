"""Load the prebuilt, injectable stub blobs shipped in sopack/stubs/.

Each ABI has `stub_<abi>.bin` (flat, relocation-free machine code) and
`stub_<abi>.json` (offsets of sopk_entry and g_decinfo within the blob), produced by
stub/build_stubs.sh with the NDK.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_STUB_DIR = Path(__file__).resolve().parent / "stubs"

# Map APK lib/<abi> directory names to our stub ABI keys (identical here, but explicit).
SUPPORTED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")


@dataclass(frozen=True)
class Stub:
    abi: str
    blob: bytes
    entry_off: int      # byte offset of sopk_entry within blob
    decinfo_off: int    # byte offset of g_decinfo within blob


class StubMissingError(FileNotFoundError):
    pass


def load_stub(abi: str) -> Stub:
    if abi not in SUPPORTED_ABIS:
        raise ValueError(f"unsupported ABI {abi!r}; supported: {SUPPORTED_ABIS}")
    blob_path = _STUB_DIR / f"stub_{abi}.bin"
    meta_path = _STUB_DIR / f"stub_{abi}.json"
    if not blob_path.exists() or not meta_path.exists():
        raise StubMissingError(
            f"stub for {abi} not built. Run stub/build_stubs.sh with the NDK first "
            f"(expected {blob_path.name} + {meta_path.name} in {_STUB_DIR})."
        )
    meta = json.loads(meta_path.read_text())
    blob = blob_path.read_bytes()
    if meta.get("size") != len(blob):
        raise ValueError(f"{blob_path.name}: size mismatch with metadata")
    return Stub(abi=abi, blob=blob,
                entry_off=int(meta["entry_off"]),
                decinfo_off=int(meta["decinfo_off"]))
