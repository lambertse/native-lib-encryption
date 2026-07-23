"""Per-pack polymorphic stub build for the ``--obfuscate`` path.

When packing with ``--obfuscate``, sopack recompiles the injection stub through O-MVLL with
a fresh random seed into a temp directory, so every packed app ships a structurally unique,
heavily-obfuscated stub (no universal offline unpacker across apps). This module owns
locating the toolchain and driving ``stub/build_stubs.sh``; the resulting temp stub dir is
handed to ``inject_so(..., stub_dir=...)``.

The obfuscation toolchain (O-MVLL plugin + a matching Android NDK) is x86_64-only and NOT
bundled — it is provided by the environment (see ``assets/Dockerfile``). Requirements:

  ANDROID_NDK_HOME / ANDROID_NDK_ROOT   an NDK matching the O-MVLL plugin's LLVM
  OMVLL_PLUGIN                          path to the O-MVLL pass-plugin .so
  OMVLL_PYTHONPATH                      O-MVLL's bundled Python stdlib (Lib/)

If any is missing, ``--obfuscate`` fails fast with an actionable message rather than
silently packing an un-obfuscated stub.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BUILD_SCRIPT = _REPO_ROOT / "stub" / "build_stubs.sh"


class ObfuscationUnavailableError(RuntimeError):
    """The O-MVLL / NDK toolchain needed for --obfuscate is not present."""


def _require_toolchain() -> None:
    missing = []
    if not (os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")):
        missing.append("ANDROID_NDK_HOME (or ANDROID_NDK_ROOT)")
    plugin = os.environ.get("OMVLL_PLUGIN")
    if not plugin:
        missing.append("OMVLL_PLUGIN")
    elif not Path(plugin).is_file():
        raise ObfuscationUnavailableError(f"OMVLL_PLUGIN={plugin} does not exist")
    if not os.environ.get("OMVLL_PYTHONPATH"):
        missing.append("OMVLL_PYTHONPATH")
    if not _BUILD_SCRIPT.is_file():
        raise ObfuscationUnavailableError(f"missing build script {_BUILD_SCRIPT}")
    if missing:
        raise ObfuscationUnavailableError(
            "--obfuscate needs the O-MVLL/NDK toolchain, but these are not set: "
            + ", ".join(missing)
            + ". Run inside the sopack Docker image (assets/Dockerfile) or set them by hand."
        )


# O-MVLL's probability_seed is a signed int32, so seeds must fit in 31 bits (a larger value
# raised "TypeError: incompatible function arguments"). The retry loop below is a thin safety
# net for any other transient O-MVLL failure; with the 31-bit range it should not fire.
_SEED_BITS = 2**31
_AUTO_SEED_RETRIES = 3


def _run_build(seed: int, out_dir, api_level: int, logger) -> None:
    env = dict(os.environ)
    env["SOPK_SEED"] = str(seed)
    env["SOPK_STUB_OUT"] = str(out_dir)
    logger(f"  building polymorphic stub (seed={seed}) via O-MVLL …")
    # Run with cwd = out_dir so O-MVLL's "omvll-logs/" (created at plugin init, before its
    # Python config loads) lands in the temp build dir and is cleaned up, not the caller's
    # cwd. build_stubs.sh uses absolute paths ($HERE / SOPK_STUB_OUT), so cwd is free.
    subprocess.run(["bash", str(_BUILD_SCRIPT), str(api_level)],
                   env=env, check=True, cwd=str(out_dir),
                   capture_output=True, text=True)


def build_obfuscated_stubs(out_dir: str | Path, api_level: int = 24,
                           seed: int | None = None, logger=print) -> int:
    """Build a fresh, seeded, O-MVLL-obfuscated stub set into ``out_dir``.

    Returns the seed used (so it can be logged/recorded). Raises
    ObfuscationUnavailableError if the toolchain is missing, or CalledProcessError if a
    build/guard step fails (after retrying with fresh seeds when the seed was auto-chosen).
    """
    _require_toolchain()
    if seed is not None:
        # Explicit seed (reproducibility): a single attempt, surface any failure.
        try:
            _run_build(seed, out_dir, api_level, logger)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"obfuscated stub build failed (seed={seed}):\n{e.stderr}") from e
        return seed

    last = None
    for attempt in range(_AUTO_SEED_RETRIES):
        seed = secrets.randbelow(_SEED_BITS)
        try:
            _run_build(seed, out_dir, api_level, logger)
            return seed
        except subprocess.CalledProcessError as e:
            last = e
            logger(f"  (O-MVLL build failed for seed {seed}; retrying with a new seed)")
    raise RuntimeError(
        f"obfuscated stub build failed after {_AUTO_SEED_RETRIES} seeds; last error:\n"
        f"{last.stderr if last else '?'}")


def obfuscated_stub_dir(api_level: int = 24, seed: int | None = None, logger=print):
    """Context-manager helper: yields a temp dir holding a freshly obfuscated stub set."""
    from contextlib import contextmanager

    @contextmanager
    def _cm():
        with tempfile.TemporaryDirectory(prefix="sopack-obf-") as tmp:
            build_obfuscated_stubs(tmp, api_level=api_level, seed=seed, logger=logger)
            yield Path(tmp)

    return _cm()
