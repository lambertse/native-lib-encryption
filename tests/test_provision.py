"""The sealed-blob header gate (`--cipher wbaes`, wbcrypto >= 3.0.0).

Pure functions over synthetic blobs, so this runs everywhere - no host `wb_keygen` needed,
unlike the two skipping tests in test_wbaes.py.

What is being pinned: sopack seals at the `light` KDF tier (`WBC_KDF_NONE`) because the
passphrase is a 128-bit machine secret that ships beside the blob, so Argon2id buys nothing
here. wb_keygen DEFAULTS to `heavy`, which means a dropped `--kdf` flag is *silently slow*
rather than an error - 266 ms and a transient 64 MiB per library at app startup. These tests
are what make that unshippable.
"""
import os
import struct
import sys

import pytest

from sopack import provision
from sopack.provision import (BLOB_HDR_MIN, BLOB_MAGIC, BLOB_MIN_VERSION, BLOB_TIER_OFF,
                              KDF_TIER_HIGH, KDF_TIER_LOW, KDF_TIER_NONE, ProvisionError,
                              assert_light_blob, blob_header)


def _blob(version: int = 4, tier: int = KDF_TIER_NONE, magic: bytes = BLOB_MAGIC,
          size: int = 2048) -> bytes:
    """A synthetic sealed blob: real v4 header, filler body. Padded past 1024 so that
    `_seal`'s size check would not pre-empt the header check under test."""
    head = magic + struct.pack("<II", version, tier)
    return head + bytes(range(256)) * ((size - len(head)) // 256 + 1)


def test_header_offsets_match_trusted_storage():
    """Mirrors src/storage/trusted_storage.cpp: magic[4] | version(u32) | kdf_tier(u32),
    both little-endian. Captured from a real blob sealed by the 3.0.0 host wb_keygen."""
    real = bytes.fromhex("574254530400000000000000")
    assert real[:4] == BLOB_MAGIC == b"WBTS"
    assert BLOB_TIER_OFF == 8 and BLOB_HDR_MIN == 12
    assert blob_header(_blob(version=4, tier=0)) == (b"WBTS", 4, 0)
    # The literal offsets, so a struct-format edit cannot silently move them.
    assert struct.unpack_from("<I", real, 4)[0] == BLOB_MIN_VERSION == 4
    assert struct.unpack_from("<I", real, BLOB_TIER_OFF)[0] == KDF_TIER_NONE == 0


def test_light_v4_blob_is_accepted():
    assert_light_blob(_blob(version=4, tier=KDF_TIER_NONE), tool="wb_keygen")


def test_future_version_is_accepted():
    """THE test that pins `version >= 4` rather than `== 4`: a future v5 that keeps the tier
    field where it is must not brick the packer. Without this, `>=` reads as sloppiness and
    the next reader tightens it."""
    assert_light_blob(_blob(version=5, tier=KDF_TIER_NONE), tool="wb_keygen")


def test_v3_blob_is_refused_and_blames_a_stale_keygen():
    """A 2.0.0 blob. v4 inserted kdf_tier and shifted every later field, so a 3.0.0 helper
    cannot open this at all - on device it aborts with nothing pointing at the host tool."""
    with pytest.raises(ProvisionError, match="STALE HOST wb_keygen") as e:
        assert_light_blob(_blob(version=3, tier=0), tool="/path/to/old/wb_keygen")
    assert "v3" in str(e.value) and "3.0.0" in str(e.value)
    assert "--force" in str(e.value)          # names the fix, not just the problem


@pytest.mark.parametrize("tier,name", [(KDF_TIER_HIGH, "heavy"), (KDF_TIER_LOW, "medium")])
def test_non_light_tier_is_refused_and_blames_sopack(tier, name):
    """A 3.0.0 tool whose `--kdf light` did not take effect. This is the silent one: no
    error anywhere, just a slow app. The message must blame provision._seal, not the user."""
    with pytest.raises(ProvisionError, match="provision._seal") as e:
        assert_light_blob(_blob(version=4, tier=tier), tool="wb_keygen")
    assert name in str(e.value)


def test_foreign_magic_is_refused():
    with pytest.raises(ProvisionError, match="magic"):
        assert_light_blob(_blob(magic=b"WBTX"), tool="wb_keygen")


def test_truncated_blob_is_refused():
    with pytest.raises(ProvisionError, match="too short"):
        assert_light_blob(BLOB_MAGIC + b"\x04\x00\x00", tool="wb_keygen")


# ---- the v3 pack key: one KEK per (pack, ABI), one session key per target ---------------

def _have_wb_keygen() -> bool:
    """Ask find_wb_keygen itself rather than re-deriving its rules. This used to duplicate the
    old "PATH or $SOPACK_WBKEYGEN" logic, which silently stopped matching the moment the probe
    list grew a vendor/ and a bundle entry - these tests would then skip on a machine that has
    a perfectly good keygen."""
    from sopack.provision import find_wb_keygen
    try:
        find_wb_keygen()
        return True
    except FileNotFoundError:
        return False


_needs_wb_keygen = pytest.mark.skipif(
    not _have_wb_keygen(),
    reason="needs a host wb_keygen (run ./scripts/build_wbaes.sh)")


@_needs_wb_keygen
def test_one_pack_key_serves_many_targets_with_distinct_session_keys():
    """The whole point of the v3 split: N targets share ONE sealed blob (so the APK carries it
    once instead of N times) but each gets its OWN session key and nonce.

    Per-target session keys are what keep the documented ceiling - "a process dump yields the
    *session* key" - scoped to one library rather than all of them, and they make keystream reuse
    impossible by construction instead of by relying on nonce uniqueness."""
    from sopack.provision import provision_pack, provision_text

    pack = provision_pack()
    assert_light_blob(pack.blob, tool="wb_keygen")      # the shared blob is still gated
    assert len(pack.kek) == 16

    plain = b"\x90" * 4096
    a = provision_text(plain, pack)
    b = provision_text(plain, pack)

    # Distinct per target...
    assert a.wrapped != b.wrapped, "two targets must not share a wrapped session key"
    assert a.nonce16 != b.nonce16, "two targets must not share a ChaCha20 nonce"
    assert a.ciphertext != b.ciphertext, "same plaintext under two session keys must differ"
    # ...and the wrap IV is fresh each time (CTR under one KEK with a repeated IV would leak
    # the XOR of the two session keys).
    assert a.wrapped[:16] != b.wrapped[:16]
    # No blob or passphrase per target any more - they live once, in the pack key.
    assert not hasattr(a, "blob") and not hasattr(a, "wpass")


@_needs_wb_keygen
def test_pack_key_never_exposes_the_long_term_key():
    """`kek` is host-only. It must not be derivable from anything that ships (`blob`, `wpass`),
    and in particular must not appear verbatim in them - the white-box's entire claim is that
    the long-term key is not reconstructable from the shipped bytes."""
    from sopack.provision import provision_pack

    pack = provision_pack()
    assert pack.kek not in pack.blob
    assert pack.kek not in pack.wpass


# ---- find_wb_keygen: discovery, not configuration ---------------------------------------
#
# `sopack pack` has no --wb-keygen flag AND no config key for one, and `cipher: wbaes` is the
# default, so the probe order below IS the user interface. If it regresses, the tool stops
# working with nothing to fall back on, which is why these are pinned rather than left to
# integration.


def _exe(path, body=b"#!/bin/sh\nexit 0\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def isolated_probes(monkeypatch, tmp_path):
    """Neutralise every probe, so each test opts exactly one back in. Without this the real
    vendor/wbc/bin/wb_keygen on a built checkout would win and mask the case under test."""
    monkeypatch.setattr(provision, "_repo_wb_keygen", lambda: str(tmp_path / "absent-repo"))
    monkeypatch.setattr(provision, "_bundle_wb_keygen", lambda: None)
    monkeypatch.delenv("SOPACK_WBKEYGEN", raising=False)
    monkeypatch.setattr(provision.shutil, "which", lambda _n: None)
    # Every candidate this module produces is a host-native shell script in tmp_path, so the
    # ELF/Mach-O sniffing must not reject them; tests that WANT a rejection re-patch this.
    monkeypatch.setattr(provision, "_host_incompatible_reason", lambda _p: None)
    return tmp_path


def test_probe_order_prefers_the_local_build_over_everything(isolated_probes, monkeypatch):
    """vendor/wbc/bin/ wins. It is the copy build_wbaes.sh just built and gated, and a stale
    $SOPACK_WBKEYGEN export outliving a rebuild is this mode's classic silent failure."""
    repo = _exe(isolated_probes / "vendor" / "wbc" / "bin" / "wb_keygen")
    bundle = _exe(isolated_probes / "bundle" / "bin" / "wb_keygen")
    env = _exe(isolated_probes / "env" / "wb_keygen")
    monkeypatch.setattr(provision, "_repo_wb_keygen", lambda: repo)
    monkeypatch.setattr(provision, "_bundle_wb_keygen", lambda: bundle)
    monkeypatch.setenv("SOPACK_WBKEYGEN", env)
    assert provision.find_wb_keygen() == repo


def test_explicit_path_still_outranks_every_probe(isolated_probes, monkeypatch):
    """The kwarg survives for library callers even though the CLI flag is gone."""
    explicit = _exe(isolated_probes / "explicit" / "wb_keygen")
    monkeypatch.setattr(provision, "_repo_wb_keygen",
                        lambda: _exe(isolated_probes / "vendor" / "wb_keygen"))
    assert provision.find_wb_keygen(explicit) == explicit


def test_bundle_probe_is_used_when_there_is_no_local_build(isolated_probes, monkeypatch):
    """The wheel case: `vendor/` resolves into site-packages and is absent, so the bundle
    beside the venv is what makes an installed sopack work with no configuration."""
    bundle = _exe(isolated_probes / "bundle" / "bin" / "wb_keygen")
    monkeypatch.setattr(provision, "_bundle_wb_keygen", lambda: bundle)
    assert provision.find_wb_keygen() == bundle


def test_env_var_is_still_honoured_when_nothing_else_exists(isolated_probes, monkeypatch):
    env = _exe(isolated_probes / "env" / "wb_keygen")
    monkeypatch.setenv("SOPACK_WBKEYGEN", env)
    assert provision.find_wb_keygen() == env


def test_an_unrunnable_candidate_is_skipped_not_fatal(isolated_probes, monkeypatch):
    """The Android-wb_keygen mistake must not mask a good keygen further down the list. A
    probe that returned the first EXISTING path would hand the packer a binary that dies with
    'Exec format error' partway through a pack."""
    android = _exe(isolated_probes / "vendor" / "wbc" / "bin" / "wb_keygen")
    good = _exe(isolated_probes / "bundle" / "bin" / "wb_keygen")
    monkeypatch.setattr(provision, "_repo_wb_keygen", lambda: android)
    monkeypatch.setattr(provision, "_bundle_wb_keygen", lambda: good)
    monkeypatch.setattr(provision, "_host_incompatible_reason",
                        lambda p: "it is an ANDROID ELF" if p == android else None)
    assert provision.find_wb_keygen() == good


def test_not_found_names_the_build_script_and_never_the_removed_flag(isolated_probes):
    """The message is the whole recovery path now, so it must point at something that exists.
    `--wb-keygen` is gone; telling anyone to pass it would be a dead end."""
    with pytest.raises(FileNotFoundError) as e:
        provision.find_wb_keygen()
    msg = str(e.value)
    assert "--wb-keygen" not in msg
    assert "build_wbaes.sh" in msg
    assert "cipher: chacha20" in msg           # the no-white-box escape hatch


def test_bundle_probe_requires_a_sibling_manifest(monkeypatch, tmp_path):
    """Without the MANIFEST.txt guard, `--no-venv` installs make <sys.prefix>/../bin match
    /usr/bin and the probe would adopt any unrelated binary called wb_keygen."""
    prefix = tmp_path / "usr" / "local"
    _exe(tmp_path / "usr" / "bin" / "wb_keygen")
    monkeypatch.setattr(sys, "prefix", str(prefix))
    prefix.mkdir(parents=True, exist_ok=True)
    assert provision._bundle_wb_keygen() is None

    (tmp_path / "usr" / "MANIFEST.txt").write_text("bundle-format: 2\n")
    found = provision._bundle_wb_keygen()
    assert found is not None
    assert os.path.realpath(found) == os.path.realpath(tmp_path / "usr" / "bin" / "wb_keygen")
