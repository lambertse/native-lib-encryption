"""Host-side provisioning for `--cipher wbaes` (wbcrypto 2.0.0 key wrapping).

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
scripts/gen_blob.sh). Its CLI is unchanged at 2.0.0. The delivered `assets/wbc/wb_keygen`
is an *Android* build and does NOT run on the pack host; provide a host build via
`SOPACK_WBKEYGEN` or on `PATH`.
"""
from __future__ import annotations

import os
import secrets
import shutil
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


def _host_incompatible_reason(path: str) -> str | None:
    """Return a human reason if `path` is an executable the PACK HOST cannot run (the classic
    mistake: pointing --wb-keygen at the shipped *Android* assets/wbc/wb_keygen), else None."""
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
class Provisioned:
    ciphertext: bytes      # ChaCha20(sk, nonce16) of the .text plaintext (ships in the lib)
    wrapped: bytes         # 48 bytes: wrap IV || session key wrapped under the sealed kek
    nonce16: bytes         # 16-byte ChaCha20 nonce block (12-byte nonce + LE counter)
    blob: bytes            # sealed white-box blob (ships in the helper)
    wpass: bytes           # whitened passphrase (ships in the helper)


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
    """Seal a 16-byte key into a white-box blob via `wb_keygen`. Returns the blob bytes."""
    with tempfile.TemporaryDirectory(prefix="sopack-seal-") as td:
        out = os.path.join(td, "sealed.blob")
        try:
            subprocess.run(
                [wb_keygen, "--key", key.hex(), "--pass", passphrase,
                 "--seed", str(seed), "--out", out],
                check=True, capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            raise ProvisionError(
                f"wb_keygen failed (exit {e.returncode}): "
                f"{e.stderr.decode('utf-8', 'replace').strip()}") from e
        except OSError as e:
            raise ProvisionError(
                f"could not execute wb_keygen at {wb_keygen}: {e} "
                "(is it a host build, not the Android one?)") from e
        with open(out, "rb") as f:
            blob = f.read()
    if len(blob) < 1024:
        raise ProvisionError(f"sealed blob suspiciously small ({len(blob)} bytes)")
    return blob


def provision_text(plain: bytes, wb_keygen: str | None = None) -> Provisioned:
    """Provision one library's `.text`: seal a long-term key, wrap a session key under it,
    ChaCha20-encrypt with the session key, whiten the passphrase, discard both keys."""
    tool = find_wb_keygen(wb_keygen)
    kek, sk, wrap_iv, nonce16 = gen_wbaes_params()
    passphrase = secrets.token_hex(16)    # 32 hex chars — argv-safe, < SOPK_MAX_PASS
    seed = secrets.randbits(64)
    try:
        blob = _seal(kek, passphrase, seed, tool)
        # Byte-identical to wbc_wrap_key(ctx, sk, wrapped) on device: the white-box IS
        # AES-128 under kek, and the wrap is plain CTR with the IV prepended.
        wrapped = wrap_iv + aes128_ctr(sk, kek, wrap_iv)
        ciphertext = apply_cipher(CIPHER_CHACHA20, plain, sk, nonce16)
        wpass = whiten_pass(passphrase.encode("ascii"), blob)
    finally:
        # best-effort wipe of both secrets (neither may ship)
        kek = b"\x00" * len(kek)          # noqa: F841 — drop the reference to the secret
        sk = b"\x00" * len(sk)            # noqa: F841
    return Provisioned(ciphertext=ciphertext, wrapped=wrapped, nonce16=nonce16,
                       blob=blob, wpass=wpass)
