"""Host-side provisioning for `--cipher wbaes` (wbcrypto 3.0.0 key wrapping).

The white-box never touches bulk data — it runs at well under 1 MB/s, and 2.0.0 deleted
the bulk entry points (`wbc_crypt_ctr`, `wbc_encrypt_ecb`) to make that unexpressible. It
protects a *key* instead. Per target `.text` we:

  1. generate a long-term AES-128 key `kek` and seal it into a passphrase-protected
     white-box blob with the host `wb_keygen` tool;
  2. generate a 32-byte session key `sk` and wrap it under `kek` —
     `wrapped = wrap_iv || aes128_ctr(sk, kek, wrap_iv)`, which is byte-for-byte what
     the device's `wbc_wrap_key` would emit (see cipher.aes128_ctr for why);
  3. encrypt `.text` with ChaCha20(sk, nonce16) — length-preserving, so the ciphertext
     occupies the same bytes in the ELF and the device decrypts it in place;
  4. whiten the passphrase off the blob, and DISCARD both `kek` and `sk`.

Only the sealed blob + wrapped key + nonce + whitened passphrase ship. `kek` is not
reconstructable from the blob, and `sk` only exists on device between the white-box
unwrap and the wipe.

`wb_keygen` is host-only and un-obfuscated (see the whitebox-cryptography repo
scripts/gen_blob.sh). It must be a *host* build — an Android one does NOT run on the pack
host; provide it via `--wb-keygen`, `SOPACK_WBKEYGEN` or on `PATH`.

THE KDF TIER (wbcrypto 3.0.0). 3.0.0 moved the seal's key-derivation cost out of a
compile-time constant and into the blob header, selectable at seal time with
`--kdf light|medium|heavy` (= `WBC_KDF_NONE`/`_LOW`/`_HIGH`). It is the ONLY dial on
`wbc_open`'s latency: at `heavy` (the upstream DEFAULT, and the pre-3.0.0 behaviour) ~99% of
an open is Argon2id — measured at 266 ms per library on device, plus a transient 64 MiB
allocation, inside an ELF constructor at app startup. sopack pins `light` (HKDF-SHA256).

That is **security-neutral here**, not a weakening. Argon2id exists to make each passphrase
GUESS expensive. Our passphrase is 128 bits of machine entropy that SHIPS in the helper
beside the blob, and its whitening key is derived from that blob's own first WHITEN_SPAN
bytes — so an attacker holding the APK holds the passphrase and guesses nothing. `light` is
the correct construction for a high-entropy machine secret; upstream documents the >= 128-bit
precondition, which `secrets.token_hex(16)` below meets exactly. The tier also lives inside
the seal's AEAD associated data, so a shipped blob cannot be tier-downgraded: rewriting the
field changes both the derived key and the authenticated data, and the tag then fails for
every passphrase.
"""
from __future__ import annotations

import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from .cipher import (CIPHER_CHACHA20, aes128_ctr, apply_cipher, gen_wbaes_params,
                     whiten_pass)


class ProvisionError(RuntimeError):
    pass


_MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                 b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")

# ---- sealed blob header (wbcrypto >= 3.0.0) ---------------------------------------------
# Mirrors src/storage/trusted_storage.cpp. v4 layout:
#     magic[4] | version(u32) | kdf_tier(u32) | salt[16] | nonce[24] | ...
# v4 *inserted* kdf_tier after version, shifting every later field — which is exactly why a
# pre-3.0.0 blob is not merely "older", it is unreadable to a 3.0.0 runtime. Both u32s are
# little-endian (`PutU32` emits `x & 0xFF` first). Verified against a real sealed blob.
BLOB_MAGIC = b"WBTS"          # kMagic
BLOB_MIN_VERSION = 4          # kVersion
BLOB_TIER_OFF = 8             # kTierOff
BLOB_HDR_MIN = 12             # kTierEnd — bytes needed before the tier is readable
KDF_TIER_NONE = 0             # KdfTier::kNone  ("light", HKDF-SHA256)
KDF_TIER_LOW = 1              # KdfTier::kLow   ("medium", Argon2id 16 MiB)
KDF_TIER_HIGH = 2             # KdfTier::kHigh  ("heavy", Argon2id 64 MiB) — wb_keygen's DEFAULT
_TIER_NAMES = {KDF_TIER_NONE: "light", KDF_TIER_LOW: "medium", KDF_TIER_HIGH: "heavy"}


def blob_header(blob: bytes) -> tuple[bytes, int, int]:
    """`(magic, version, tier)` from a sealed blob's header. Raises ProvisionError if the blob
    is too short to hold one."""
    if len(blob) < BLOB_HDR_MIN:
        raise ProvisionError(
            f"sealed blob is {len(blob)} bytes, too short to hold a v{BLOB_MIN_VERSION} "
            f"header ({BLOB_HDR_MIN} bytes)")
    magic = blob[:4]
    version, tier = struct.unpack_from("<II", blob, 4)
    return magic, version, tier


def assert_light_blob(blob: bytes, *, tool: str) -> None:
    """Refuse to ship anything but a v>=4 blob sealed at the `light` KDF tier.

    This is a hard gate, not a sanity check. Two distinct failures with two distinct fixes:

      * version 3  -> a STALE PRE-3.0.0 host wb_keygen. The common route is a cached
        $WBC/build-host/wb_keygen left over from before the SDK upgrade; `build_wbaes.sh`
        reuses it unless you pass --force.
      * version >=4 but tier != 0 -> the tool is 3.0.0 but `--kdf light` did not take effect.
        That is a bug in `_seal` below, not a user error: wb_keygen DEFAULTS to `heavy`, so
        dropping the flag is silently slow rather than an error.

    `version >= BLOB_MIN_VERSION` is deliberate, not sloppiness: a future v5 that keeps the
    tier where it is should not brick the packer. (Upstream's own `PeekTier` is exact-match, so
    a v5 blob would be rejected on device — but that is upstream's call to relax, not ours to
    pre-empt by refusing to pack.)"""
    magic, version, tier = blob_header(blob)
    if magic != BLOB_MAGIC:
        raise ProvisionError(
            f"{tool} did not produce a white-box trusted-storage blob: magic is {magic!r}, "
            f"expected {BLOB_MAGIC!r}. Is it really wb_keygen?")
    if version < BLOB_MIN_VERSION:
        raise ProvisionError(
            f"sealed blob is format v{version}, but sopack requires v{BLOB_MIN_VERSION} "
            f"(whitebox-cryptography >= 3.0.0). Almost certainly a STALE HOST wb_keygen: "
            f"{tool} was built from a pre-3.0.0 checkout. A v{version} blob cannot be opened "
            f"by a 3.0.0 helper at all, so this would fail on device with no useful signal. "
            f"Rebuild it (cd $WBC && bash scripts/gen_blob.sh …, or "
            f"./scripts/build_wbaes.sh --force) and re-point --wb-keygen / $SOPACK_WBKEYGEN.")
    if tier != KDF_TIER_NONE:
        raise ProvisionError(
            f"sealed blob was sealed at KDF tier {tier} "
            f"({_TIER_NAMES.get(tier, 'unknown')}), expected {KDF_TIER_NONE} (light). "
            f"wb_keygen DEFAULTS to heavy, so this means `--kdf light` did not reach it — a "
            f"sopack bug in provision._seal, not a problem with {tool}. Shipping it would "
            f"cost ~266 ms of Argon2id and a transient 64 MiB per library at app startup.")


def _host_incompatible_reason(path: str) -> str | None:
    """Return a human reason if `path` is an executable the PACK HOST cannot run (the classic
    mistake: pointing --wb-keygen at an out-of-band *Android* wb_keygen build), else None."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    if len(head) < 4:
        return None
    is_elf = head[:4] == b"\x7fELF"
    is_macho = head[:4] in _MACHO_MAGICS
    if sys.platform == "darwin":
        if is_elf:
            return ("it is an ELF (Linux/Android) binary; a macOS host needs a Mach-O "
                    "wb_keygen built here (whitebox-cryptography scripts/gen_blob.sh)")
    else:  # linux (and other unixes)
        if is_macho:
            return ("it is a Mach-O (macOS) binary; this host needs an ELF wb_keygen built "
                    "here (whitebox-cryptography scripts/gen_blob.sh)")
        if is_elf and b"/system/bin/linker" in head:
            return ("it is an ANDROID ELF (PT_INTERP=/system/bin/linker*) and cannot run on "
                    "the pack host; build a host wb_keygen (scripts/gen_blob.sh)")
    return None


@dataclass
class PackKey:
    """One long-term key per (pack, ABI), shared by every target in that ABI.

    Why per-ABI rather than per-pack: the blob is architecture-neutral, but one blob across ABIs
    would let the x86_64 provider — which is unobfuscated and ships cleartext `.text` by scope
    choice — carry the same long-term key that protects arm64. One extra `wb_keygen` run removes
    that cross-ABI leak.

    `kek` lives in the pack process for the whole run (it must, to wrap each target's session
    key) and is never written to any output — `_self_verify_wbaes` byte-scans for it. Only
    `blob` and `wpass` ship, both in that ABI's single `libsopk_wb.so`."""
    kek: bytes             # 16-byte AES-128 long-term key. HOST-ONLY — never shipped.
    blob: bytes            # sealed white-box blob (ships in the shared provider)
    wpass: bytes           # whitened passphrase (ships in the shared provider, beside the blob)


@dataclass
class Provisioned:
    """Per-target results. Carries no blob/passphrase since v3 — see PackKey."""
    ciphertext: bytes      # ChaCha20(sk, nonce16) of the .text plaintext (ships in the lib)
    wrapped: bytes         # 48 bytes: wrap IV || session key wrapped under the pack's kek
    nonce16: bytes         # 16-byte ChaCha20 nonce block (12-byte nonce + LE counter)


def find_wb_keygen(explicit: str | None = None) -> str:
    """Locate a RUNNABLE host wb_keygen: explicit path, else SOPACK_WBKEYGEN, else PATH.
    Skips a binary the host can't execute (e.g. the shipped Android wb_keygen) and reports
    why, so the failure is clear instead of a mid-pack 'Exec format error'."""
    bad = None
    for cand in (explicit, os.environ.get("SOPACK_WBKEYGEN"), shutil.which("wb_keygen")):
        if not cand or not os.path.exists(cand):
            continue
        reason = _host_incompatible_reason(cand)
        if reason:
            bad = f"{cand}: {reason}"
            continue
        return cand
    msg = ("could not find a host wb_keygen. Build one from the whitebox-cryptography repo "
           "(scripts/gen_blob.sh -> build-host/wb_keygen) and pass --wb-keygen / set "
           "SOPACK_WBKEYGEN, or put it on PATH.")
    if bad:
        msg += f" (the one found is not runnable here — {bad})"
    raise FileNotFoundError(msg)


def _seal(key: bytes, passphrase: str, seed: int, wb_keygen: str) -> bytes:
    """Seal a 16-byte key into a white-box blob via `wb_keygen`. Returns the blob bytes.

    `--kdf light` is hardcoded, with no sopack CLI flag to override it: it is the only sound
    tier for a 128-bit machine secret that ships beside the blob, and this repo's idiom is hard
    gates rather than knobs. See the module docstring for why that is security-neutral."""
    with tempfile.TemporaryDirectory(prefix="sopack-seal-") as td:
        out = os.path.join(td, "sealed.blob")
        try:
            subprocess.run(
                [wb_keygen, "--key", key.hex(), "--pass", passphrase,
                 "--seed", str(seed), "--kdf", "light", "--out", out],
                check=True, capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode("utf-8", "replace").strip()
            msg = f"wb_keygen failed (exit {e.returncode}): {err}"
            # The realistic upgrade failure, and the one that actually fires: a pre-3.0.0
            # wb_keygen has no --kdf, and its argv loop ends in `unknown arg` + exit 2. Name
            # the cause, or the user reads a bare "unknown arg: --kdf" and blames sopack.
            if "--kdf" in err or "unknown arg" in err:
                msg += (f"\n  This is a STALE PRE-3.0.0 host wb_keygen: it does not know "
                        f"--kdf. sopack requires whitebox-cryptography >= 3.0.0. Rebuild it "
                        f"(cd $WBC && bash scripts/gen_blob.sh …, or "
                        f"./scripts/build_wbaes.sh --force) and re-point --wb-keygen / "
                        f"$SOPACK_WBKEYGEN at $WBC/build-host/wb_keygen.")
            raise ProvisionError(msg) from e
        except OSError as e:
            raise ProvisionError(
                f"could not execute wb_keygen at {wb_keygen}: {e} "
                "(is it a host build, not the Android one?)") from e
        with open(out, "rb") as f:
            blob = f.read()
    # Order matters: this is the WHITEN_SPAN precondition and a superset of the bytes the
    # header parse needs, so it must come first to give the clearer error on a stub file.
    if len(blob) < 1024:
        raise ProvisionError(f"sealed blob suspiciously small ({len(blob)} bytes)")
    assert_light_blob(blob, tool=wb_keygen)
    return blob


def provision_pack(wb_keygen: str | None = None) -> PackKey:
    """Seal ONE long-term key for a whole (pack, ABI). Call once per ABI, before the per-target
    loop — `apk.py:repackage` is the only place that knows the full target set.

    Provision every ABI *before* writing any output. `_seal` runs the host `wb_keygen` and gates
    its blob (`assert_light_blob`), so a stale pre-3.0.0 tool fails here; doing that up front
    means it fails before the packer has produced a partial APK."""
    tool = find_wb_keygen(wb_keygen)
    kek = gen_wbaes_params()[0]
    # 32 hex chars — argv-safe, < SOPK_MAX_PASS. The 16 bytes are load-bearing: exactly 128
    # bits of uniform machine entropy, which is the precondition WBC_KDF_NONE ("light")
    # documents. Do NOT shorten it — at this tier there is no KDF stretching to compensate.
    passphrase = secrets.token_hex(16)
    blob = _seal(kek, passphrase, secrets.randbits(64), tool)
    return PackKey(kek=kek, blob=blob, wpass=whiten_pass(passphrase.encode("ascii"), blob))


def provision_text(plain: bytes, pack: PackKey) -> Provisioned:
    """Provision one library's `.text` under an existing pack key: fresh session key, wrapped
    under `pack.kek`, then ChaCha20 over `.text`.

    Each target gets its OWN session key and nonce. That costs 48 bytes in its region and buys
    two things: the documented ceiling ("a process dump yields the *session* key") stays scoped
    to one library instead of all of them, and keystream reuse across libraries is impossible by
    construction rather than by relying on nonce uniqueness."""
    _kek, sk, wrap_iv, nonce16 = gen_wbaes_params()
    # Byte-identical to wbc_wrap_key(ctx, sk, wrapped) on device: the white-box IS AES-128
    # under kek, and the wrap is plain CTR with the IV prepended.
    wrapped = wrap_iv + aes128_ctr(sk, pack.kek, wrap_iv)
    ciphertext = apply_cipher(CIPHER_CHACHA20, plain, sk, nonce16)
    # `sk` is deliberately NOT "wiped" here. Rebinding it would drop our reference without
    # overwriting the `bytes` object, so it would only look diligent — CPython gives no way to
    # scrub an immutable value. It dies with the frame; what actually matters is that neither it
    # nor `pack.kek` is ever written to the output (asserted by _self_verify_wbaes).
    return Provisioned(ciphertext=ciphertext, wrapped=wrapped, nonce16=nonce16)
