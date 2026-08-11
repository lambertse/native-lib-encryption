# `--cipher wbaes` - the WBC integration, and how to verify it

Everything about the white-box AES-128 key-wrap mode: how sopack is wired to the
**whitebox-cryptography (WBC) SDK** (Part I - the boundary: what it consumes, what it
refuses, who owns what, what an upstream change breaks), and the layered procedure that
proves the whole thing works (Part II - Phases 1–6).

| read instead | when |
|---|---|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) §11 | you want *why* each decision was forced - the perf redesign, the AEAD rejection, the `dlsym` post-mortem |
| [`../BUILDING.md`](../BUILDING.md) §4 | you just want to pack an APK |
| [`../SECURITY.md`](../SECURITY.md) | you want the threat model and the honest ceiling |
| `CLAUDE.md` | you are changing the code |

*Citation rule:* references into the WBC repo name a **file and symbol, never a line
number** - it is an external repo and line numbers drift.

---

# Part I - The contract

## 1. Version contract

| piece | pinned at | consequence of a mismatch |
|---|---|---|
| WBC SDK | **>= 3.0.0** | pre-3.0.0 has no `wbc_blob_kdf_tier` and no KDF tier at all, so `stub/sopk_wb.c` will not **compile** against its header |
| sealed blob format | **v4** (`trusted_storage.cpp` `kVersion`; `Unseal` rejects others) | v4 *inserted* `kdf_tier` after `version`, shifting every later field - a v3 blob is unopenable, not merely old |
| KDF tier | **`WBC_KDF_NONE`** ("light") | pinned at seal time by `provision.py:_seal`'s `--kdf light`, and re-asserted from the blob header by `assert_light_blob`. `wb_keygen` DEFAULTS to `heavy`, so a dropped flag is *silently slow*, not an error |
| sopack region | **v3** (`rt_meta.REGION_VERSION`) | v3 split one region into two (`'SRTT'` per target, `'SRTW'` in the shared provider). The on-device gate is exact, and a mismatch **aborts** |
| build markers | **two**, deliberately different (`rt_meta.HELPER_BUILD_MARKER`, `PROVIDER_BUILD_MARKER`) | with one shared value, "fresh thin helper + stale provider" would pass both guards - and that mismatched pair is the real failure mode now that two artifacts must be rebuilt together |

1.x is not merely unsupported, it is *silently* unsupported: a `-shared` link permits
unresolved symbols, so a skeleton built against a 1.x `libwbcrypto.a` links cleanly and
leaves the missing `wbc_*` as `UND` imports. See §8.

## 2. What sopack consumes

| from WBC | used by | notes |
|---|---|---|
| `wb_keygen` CLI: `--key <hex> --pass <str> --seed <n> --kdf light --out <path>` | `provision.py:_seal` | must be a **host** build (WBC `scripts/gen_blob.sh`). `assets/wbc/` holds only `libwbcrypto.a` + `wbcrypto.h`; any `wb_keygen` delivered out of band is an *Android* binary and is not in this repo - `provision.py:_host_incompatible_reason` recognises that exact mistake by file magic |
| `libwbcrypto.a` | the **provider** skeleton link (`stub/sopk_wb.c`) only | the **Android** archive, from WBC `scripts/build_android.sh` (distinct from `gen_blob.sh` above, which builds the host keygen). **Bundles libsodium** since 2.0.0, so no separate Android libsodium |
| `wbcrypto.h` | `stub/sopk_wb.c` | |
| `wbc_blob_kdf_tier`, `wbc_open`, `wbc_unwrap_key`, `wbc_close`, `wbc_wipe` | `stub/sopk_wb.c:sopk_wb_k` | **five calls - that is the entire device-side surface.** `wbc_blob_kdf_tier` is a header read (no passphrase, no cost) and doubles as the 3.0.0 version tripwire |

Since region v3 the thin per-target helper (`stub/sopk_rt.c`) links **no** white-box and
calls **no** `wbc_*` at all - it reaches the provider through the single exported symbol
`sopk_wb_k`. The packer enforces that split in both directions (§8).

## 3. What sopack refuses

| not used | why |
|---|---|
| `wbc_crypt_ctr`, `wbc_encrypt_ecb` | deleted upstream in 2.0.0. Bulk white-box runs well under 1 MB/s; a 5.5 MB `libapp.so` took *minutes* inside a constructor (→ `ARCHITECTURE.md` §11b) |
| `wbc_bulk_seal`, `wbc_bulk_open` | `.text` encryption must be **length-preserving in place**; the AEAD's 40 bytes of framing have nowhere to live (→ `ARCHITECTURE.md` §11c) |
| `libwbvm.a`, `libwbprovision.a` | the provisioning surface - **must never ship on device** |
| `wbc_wrap_key` on the host | not needed; the host computes the wrap itself (§4) |

## 4. The discovery that removed the need for a host tool

`wbc_wrap_key` is plain **AES-128-CTR under the sealed key**
(`src/sdk/wbcrypto.cpp:CtrSessionKey`): a random 16-byte IV, the full IV as the initial
big-endian counter, the IV prepended to the output. The white-box *is* bit-exact AES-128,
and the pack host still holds the long-term key at the moment it seals it - so it can
compute the wrap in pure Python:

```python
wrapped = wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)   # == wbc_wrap_key(ctx, sk, …)
```

Consequences: **no host tool links the white-box runtime, and `wb_keygen`'s CLI never
changed.** The price is that the CTR convention is now a frozen cross-project contract -
pinned by a KAT captured from the real 2.0.0 `wbc_unwrap_key` in `tests/test_cipher.py`.

## 5. Artifact flow

The *ownership* view - who produces each artifact and whether it ships. For the
step-by-step **sequence** at pack time and at load, and the same picture for stub mode,
see [`ARCHITECTURE.md`](./ARCHITECTURE.md) §12c–d.

```
  ── host (pack time) ──────────────────────┐   ── device (load time) ────────────────
                                            │
  ONCE PER ABI:                             │   in libsopk_wb.so (shared provider):
  kek ──wb_keygen──▶ blob ──────────────────┼──▶ wbc_open(blob, pass) ──▶ ctx
   │                   └──▶ whiten(pass)  ──┼──▶ de-whiten ──────────────┘
   │                                        │
  PER TARGET:                               │   in libsopk_rt_<target>.so (thin helper):
   └─(AES-128-CTR)─▶ wrapped ───────────────┼──▶ sopk_wb_k() ──▶ wbc_unwrap_key ──▶ sk
                                            │                          wbc_close(ctx)
  sk ──ChaCha20──▶ encrypted .text ─────────┼──▶ ChaCha20(sk, nonce16) ──▶ plain .text
   │                     + nonce16          │                            wbc_wipe(sk)
   └── discarded, never written ────────────┘
```

| artifact | produced by | ships in the APK? |
|---|---|---|
| `kek` (long-term AES-128 key) | `cipher.gen_wbaes_params`, **once per ABI** via `provision_pack` | **no** - discarded after sealing, never reconstructable |
| passphrase | `provision.provision_pack` (`secrets.token_hex(16)`) | yes, **whitened** (`cipher.whiten_pass`, keyed off the blob's own first bytes), in the provider |
| sealed blob | host `wb_keygen`, **once per ABI** | yes, inside the provider |
| `sk` (32-byte session key) | `cipher.gen_wbaes_params`, **per target** | **no** - discarded on the host, re-derived on device by the unwrap |
| `wrapped` (48 B) | `provision.py`, in Python (§4) | yes, in that target's thin helper |
| `nonce16` | `cipher.gen_wbaes_params` | yes, in that target's thin helper |
| encrypted `.text` | `apply_cipher(CIPHER_CHACHA20, …)` | yes, in the target's own section bytes |
| skeleton `sopack/stubs/sopk_wb_<abi>.so` | **you**, by hand (NDK + O-MVLL, → Phase 4a) | no - a pack-time input |
| skeleton `sopack/stubs/sopk_rt_<abi>.so` | **you**, by hand (NDK + O-MVLL, → Phase 4b) | no - a pack-time input |
| `lib/<abi>/libsopk_wb.so` | `elf_inject.emit_provider`, **one per ABI** | yes |
| `lib/<abi>/libsopk_rt_<target>.so` | `elf_inject._emit_helper`, **one per target** | yes |

Each target gets its **own** session key and nonce. That costs 48 bytes in its region and
buys two things: the documented ceiling ("a process dump yields the *session* key") stays
scoped to one library instead of all of them, and keystream reuse across libraries is
impossible by construction rather than by relying on nonce uniqueness.

Adding files to `lib/<abi>/` is the tool's **only** add-file path, and since v3 it emits
two kinds. Delivery to the target is a `DT_NEEDED` added by raw ELF surgery
(`_inject_wbaes` / `_add_needed_inplace`, never LIEF `add_library`). bionic runs a
dependency's constructors before the dependent's init, so there is no `DT_INIT` or decinfo
surgery in this mode at all - which is why it handles `INIT_ARRAY`-only and no-init
libraries for free.

## 6. The interchange format: two regions since v3

Regions are the **only** structured data crossing from packer to device. `sopack/rt_meta.py`
mirrors `stub/sopk_rt.h`; `tests/test_rt_meta.py` pins both layouts, both build markers, and
that a foreign version is rejected.

```
'SRTT'  target region, 96-byte header  (in each thin helper, one per target)
   magic | version | text_rva | text_size | wrapped[48] | nonce16[16] |
   soname_len | flags | reserved            ── tail: soname ONLY

'SRTW'  provider region, 24-byte header  (in libsopk_wb.so, one per ABI)
   magic | version | blob_len | pass_len | flags | reserved0 | reserved1
                                          ── tail: wpass, then blob
```

The wpass and the blob **must stay in the same artifact**: the whitening key is derived
from the blob's own first `cipher.WHITEN_SPAN` bytes.

> **The magic is the drift gate, not the size.** v3 kept the target header at 96 bytes and
> `_FMT` textually identical - `pass_len`/`blob_len` simply became `flags`/`reserved` - so a
> size assertion passes against either version. Only the magic and the version tell them
> apart, which is why `TargetRegion.unpack` checks for a `'SRTW'` magic *before* checking
> the length, and says "the two artifacts were mixed up" rather than "truncated".

Each region is appended to its artifact as one read-only 16 KB-aligned `PT_LOAD` and found
at runtime by **magic-scanning that artifact's own program headers** - no patched symbol or
file offset, because LIEF re-bases the file when the segment is appended (→
`ARCHITECTURE.md` §11e).

## 7. What an upstream change breaks

| if this changes in WBC | sopack effect | what catches it |
|---|---|---|
| `CtrSessionKey`'s CTR convention | the host-computed wrap silently stops matching | the KAT in `tests/test_cipher.py` |
| blob format / `Unseal` | `wbc_open` fails → the ctor **aborts**, in the provider's `10..19` band | nothing automatic; re-run Phase 3 |
| `wb_keygen` CLI | `provision.py:_seal` argv fails | loud, at pack time |
| `libwbcrypto.a` stops bundling libsodium | undefined `sodium_*` in the provider | `-Wl,--no-undefined`, then `_emit_helper` |
| a consumed `wbc_*` signature | provider compile error | the compiler - the only failure mode loud by default |

Note the pattern: **the device side cannot explain itself**. Since the fail-closed change it
at least stops rather than running encrypted code, but a release build does not log, so an
abort names no cause beyond its `sopk_fail_code`. Almost every guard therefore has to sit on
the host, where it can name the remedy. The codes themselves are listed in
[`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md).

## 8. The guards that make a mismatch visible

Each of these exists because the corresponding silent failure actually shipped. `_emit_helper`
runs in two modes (`is_thin`) and **the expectations invert** between them.

- **Build markers.** The skeletons are built by hand outside this repo, so a stale one is easy
  to leave behind - and on device it is undiagnosable (the ctor's version gate finds no region
  and aborts, with nothing pointing at the packer). `sopk_rt.c` and `sopk_wb.c` each embed
  their own `..._BUILD_MARKER_BYTES`; `rt_meta.HELPER_BUILD_MARKER` / `PROVIDER_BUILD_MARKER`
  mirror them; the packer refuses a skeleton without the right one. **Bump the marker on any
  region-layout *or* ctor-flow change**, in both the C header and `rt_meta.py`; bump
  `REGION_VERSION` as well only when a layout itself moves. Retired values live in
  `SUPERSEDED_BUILD_MARKERS` so a rebuild cannot silently reuse one. Markers must stay in an
  `SHF_ALLOC` section, because the packer strips everything else and its own guard is a
  byte-scan.
- **Not a tracing build.** A `-DSOPK_RT_LOG` artifact logs the target soname, `.text` RVA and
  size, and a final "OK" to logcat. Refused unless `--allow-helper-log`, which warns on every
  pack.
- **Strip.** Every non-`SHF_ALLOC` section is removed from both emitted artifacts - on a
  default (unstripped) build that is the whole symbol table plus megabytes of DWARF (§ Phase 4).
- **Export hygiene, inverted.** The **provider** must export exactly `sopk_wb_k`; the **thin
  helper** must export nothing. An exported `wbc_*` is refused either way, since only
  `--exclude-libs,ALL` can hide what `WBC_API` marks visible.
- **No undefined `wbc_*`/`sodium_*`.** The 1.x-archive trap of §1, checked on the provider.
  `DT_NEEDED` and export checks do **not** catch it - the leftovers are undefined symbols, not
  dependencies. The thin helper must additionally reference **no** `wbc_*` at all, and must
  import `sopk_wb_k`.
- **`DT_NEEDED` ⊆ `_BIONIC_ALLOWED` ∪ {`libsopk_wb.so`}.** Catches a shared `libc++_shared.so`
  or any stray dependency, i.e. a white-box that was not statically linked. The provider's
  `DT_SONAME` must be exactly `libsopk_wb.so`, and the packer **asserts** rather than fixes it
  - it cannot fix it, because every thin helper already recorded that string at link time.
- **Pack-level closure** (`apk.py`, after the target loop). Every staged thin helper's provider
  must be present in the output. `_self_verify_wbaes` runs per target and structurally cannot
  see this. A pre-existing `libsopk_wb.so` in the input APK is a **fatal** collision, not a
  skip: reusing it would leave every thin helper resolving against a foreign blob.
- **`_self_verify_wbaes`: dynamic symbol names identical in vs out.** Repointing `DT_STRTAB` at
  an appended `.dynstr` copy desynced every `st_name` once and shipped a crashing APK (→
  `ARCHITECTURE.md` §11f). The table must be read back from the **written** file
  (`_effective_strtab`), and symbols resolved the way bionic does (`_LoaderView`), never via
  section headers.

The toolchain requirements these imply (static libc++, `-x c`, `--exclude-libs`,
`--no-undefined`, `-soname`) are stated once, with their rationale, in **Phase 4** - that is
their only home.

## 9. Cost

sopack seals at the **`light`** KDF tier, so no term dominates: a 5.5 MiB `.text` host
round-trip is ~13.7 ms total, of which only the ChaCha20 line grows with `.text`. The
breakdown and why the tier is security-neutral live in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) §11b; Phase 3 below reproduces it as a live
measurement.

What remains per-library is one `wbc_open` per protected library, because the provider is
**stateless** (open → unwrap → close per call, no cached `wbc_ctx` - which also sidesteps
`wbc_ctx` not being thread-safe). `Unseal` AEAD-decrypts the ~455 KB blob and builds the VM
image on each call, ~1 ms on a host. Caching it is the open optimisation - see
[`IMPROVEMENTS.md`](./IMPROVEMENTS.md) §1.

The APK-size argument that used to sit here is **closed**: before v3 each per-target helper
carried its own ~465 KB of white-box code plus its own ~455 KB blob, ≈920 KB duplicated N
times. Since v3 that ships **once per ABI** in `libsopk_wb.so`, and each additional protected
library costs only a few-KB thin helper.

## 10. Security ceiling

Summarised where users will find it, in [`../SECURITY.md`](../SECURITY.md); the argument is
in `ARCHITECTURE.md` §11a. The one-line version: the white-box is Chow-style AES, broken by
BGE-class attacks, so it protects against **static** analysis only - and key wrapping trades
the "portable key ships in the binary" weakness for a narrower one, where the **session** key
sits in ordinary memory between the unwrap and the `wbc_wipe`. Do not oversell either way.

## 11. Upgrading to a newer SDK

1. Diff `wbcrypto.h` for the five consumed symbols (§2), the blob version, **and the
   `wbc_kdf_tier` enum numbering** - `provision.py` hardcodes tier 0 == light, and a
   `_Static_assert` in `sopk_wb.c` turns a renumbering into a build error rather than a packer
   that refuses every blob.
2. Re-run `python -m pytest tests/test_cipher.py` - the `aes128_ctr` KAT is the wrap tripwire -
   and `tests/test_provision.py`, which pins the blob-header offsets.
3. Rebuild **both** per-ABI skeletons against the new `libwbcrypto.a`, **with
   `-Wl,--no-undefined`**.
4. If a region layout changes, bump `REGION_VERSION` **and** the affected build marker. Bump a
   build marker **whenever that artifact's WBC call sequence changes, even if `REGION_VERSION`
   does not** - that is exactly what the 3.0.0 migration needed. Three files must agree:
   `stub/sopk_rt.h`, `stub/sopk_wb.h` and `rt_meta.py`; move the old value into
   `SUPERSEDED_BUILD_MARKERS`.
5. Re-run Phase 1 **with `--force`**. A cached `build-host/wb_keygen` (and a cached
   `build-android/libwbcrypto.a`) survives an SDK upgrade otherwise; both are documented traps
   with their own gates now, but `--force` avoids the question.
6. Confirm `blob kdf tier = 0` appears in Phase 3's output.
7. Re-run Phases 1–4 (Phase 3 exercises every contract above through the real library, no
   device needed), then Phase 6 on hardware.

---

# Part II - Verifying it end to end

A layered checklist. Each phase has a **command** and a **PASS signal** you can check
yourself. Phases 1–5 run on the pack host (Linux/macOS); Phase 6 needs an Android device.

**Requires whitebox-cryptography >= 3.0.0.** 3.0.0 made the KDF cost a per-blob tier chosen at
seal time (which is what sopack pins to `light`) and bumped the sealed-blob format to **v4**;
2.0.0 before it removed the bulk entry points (`wbc_crypt_ctr`, `wbc_encrypt_ecb`) in favour of
key wrapping. Older artifacts are not usable: a v3 blob is *rejected* by `Unseal`, a pre-3.0.0
header will not compile `stub/sopk_wb.c` (no `wbc_blob_kdf_tier`), and a 1.x
`libwbcrypto.a` links *silently* against it while leaving `wbc_*` undefined (§1). If
`scripts/gen_blob.sh` fails with `'abort' is not a member of 'std'`, your checkout predates
the `#include <cstdlib>` fix in `src/vm/assembler.cpp` - update it.

**Phases 1-4 are automated** by `scripts/build_wbaes.sh`, which runs them in order and turns
every PASS signal below into a hard gate:

```bash
./scripts/build_wbaes.sh                      # prompts for WBC/NDK if unset; RELEASE skeletons
./scripts/build_wbaes.sh --host-only          # Phases 1-3 only; no NDK needed
./scripts/build_wbaes.sh --trace              # Phase-6 tracing build (NOT shippable)
```

It stops before Phase 5 (that needs your APK and lib names) and prints the pack command to run
next. The phases below are the manual equivalent, and the reference for what each check means
when the script fails one. (`scripts/build_chacha20.sh` is the equivalent for the stub ciphers,
which need only the stub blobs.)

Set these once if you prefer to run the phases by hand:

```bash
export SOPACK=/path/to/sopack             # this repo
export WBC=/path/to/whitebox-cryptography # the SDK repo (master, >= 3.0.0)
export NDK=/path/to/android-ndk           # your NDK (for Phase 4)
```

---

## Phase 1 - Prove the white-box IS standard AES-128 (host `wb_keygen`)

Any `wb_keygen` delivered out of band is an **Android** binary and will not run on the pack
host. Build the host-native, un-obfuscated provisioning tool from source (this is exactly
what the SDK's `scripts/gen_blob.sh` is for) and let it self-check the FIPS-197 vector:

```bash
cd "$WBC"
bash scripts/gen_blob.sh --key 000102030405060708090a0b0c0d0e0f \
     --pass demo --seed 42 --out /tmp/sealed.blob
```

**PASS:** the output ends with `69c4e0d86a7b0430d8cdb78070b4c55a` and
`sealed white-box -> /tmp/sealed.blob (454848 bytes, hardened bytecode, 44604 B code)`.
That hex is the FIPS-197 AES-128 vector - proof the white-box is bit-exact AES-128, which is
what lets sopack compute the key wrap in Python (Phase 3). It also leaves a runnable host
tool at `$WBC/build-host/wb_keygen`.

```bash
export SOPACK_WBKEYGEN="$WBC/build-host/wb_keygen"
```

---

## Phase 2 - sopack unit tests (crypto + layout + injection)

```bash
cd "$SOPACK"
python3 -m pytest tests/ -q
```

**PASS:** all tests pass. **Four** SKIP by design rather than fail (two in `test_provision.py`,
two in `test_wbaes.py`), and the reason says why: they need a host `wb_keygen`, because they seal
a real white-box blob and there is nothing meaningful to fake - the run reports
`needs a host wb_keygen (SOPACK_WBKEYGEN or on PATH)`. Everything else - including the guards
and the `.dynstr` re-sort
behaviour the mode depends on - runs off the committed `tests/fixtures/mini_arm64.so` with no
setup at all. What this covers:

- `test_cipher.py` - AES core vs FIPS-197; **`aes128_ctr` vs a vector captured from the real
  2.0.0 `wbc_unwrap_key`, still exact at 3.0.0** (the key-wrap contract); openssl fast paths ==
  pure Python for both AES-CTR and ChaCha20, **and that a wrong-IV-convention `openssl` is
  rejected rather than silently trusted** (macOS ships LibreSSL, Linux OpenSSL 3.x - a
  same-length wrong result would ship a corrupt `.text` that only crashes on device);
  passphrase whitening self-inverse.
- `test_rt_meta.py` - **both** region layouts match `stub/sopk_rt.h` (the 96-byte `'SRTT'`
  target header and the 24-byte `'SRTW'` provider header), both build markers in Python match
  the C headers and are not a superseded value, and a foreign region version is rejected loudly.
- `test_provision.py` - the blob-header gate: `assert_light_blob` accepts only a v≥4, tier-0
  blob.
- `test_wbaes.py` - a REAL wbaes injection on an arm64 `.so`: `.text` encrypted, the raw
  `DT_NEEDED` added, both target and helper stay 16 KB-aligned, region round-trips; **that
  every one of the target's exported symbol names survives** (the defect that produced a
  loading-then-crashing APK) and that reintroducing it fails the pack; that a skeleton without
  the build marker is refused; **that a skeleton with unresolved `wbc_*` imports is refused**
  (the 1.x-archive trap); and that the symbol count is right for `DT_GNU_HASH`-only libraries
  and for ones that export nothing.

---

## Phase 3 - Full round-trip through the REAL white-box (host, no device)

This is the strongest check available without a device, and the one that catches
Python↔C drift. It proves, in one run: the C structs in `sopk_rt.h` parse the regions the
Python packer wrote; the passphrase whitening mirror is byte-exact (otherwise `wbc_open`
rejects the passphrase); the wrap computed in Python is what the real `wbc_unwrap_key`
inverts; and the ChaCha20 mirror is byte-exact (otherwise the plaintext compare fails).

The probe lives at [`scripts/rt_roundtrip.c`](../../scripts/rt_roundtrip.c) (it is what
`build_wbaes.sh` compiles, so there is one copy, not two). Build it:

```bash
cd "$WBC"
SODIUM_INC="$(echo third_party/libsodium/libsodium-*/src/libsodium/include)"
SRCS=$(find src -name '*.cpp' -not -path 'src/tools/*' -not -path 'src/rt/*' | sort)
cc -O2 -Iinclude -I"$SOPACK/stub" -c "$SOPACK/scripts/rt_roundtrip.c" -o /tmp/rt_roundtrip.o
c++ -std=c++17 -O2 -w -Isrc -Iinclude -I"$SODIUM_INC" \
    /tmp/rt_roundtrip.o $SRCS build-host/libsodium.a -o /tmp/rt_roundtrip
```

Provision a realistically sized payload through the real packer code, then decrypt it.
**Since v3 the metadata is split across two artifacts**, so the snippet writes two region
files and the probe takes four inputs:

```bash
cd "$SOPACK"
python3 - <<'PY'
import os
from sopack.provision import provision_pack, provision_text
from sopack.rt_meta import TargetRegion, WbRegion

plain = os.urandom(5_513_872)                 # libapp.so-sized .text
pack = provision_pack()                       # ONE kek + blob per ABI; needs $SOPACK_WBKEYGEN
prov = provision_text(plain, pack)            # per-target session key, wrapped under pack.kek

wbregion = WbRegion(wpass=pack.wpass, blob=pack.blob).pack()          # 'SRTW' -> the provider
region = TargetRegion(text_rva=0x10000, text_size=len(plain),         # 'SRTT' -> a thin helper
                      wrapped=prov.wrapped, nonce16=prov.nonce16,
                      soname=b'libapp.so').pack()

open('/tmp/wbregion.bin','wb').write(wbregion)
open('/tmp/region.bin','wb').write(region)
open('/tmp/cipher.bin','wb').write(prov.ciphertext)
open('/tmp/plain.bin','wb').write(plain)
print(f'provisioned {len(plain)} bytes; wb region {len(wbregion)} (blob {len(pack.blob)}), '
      f'target region {len(region)}')
PY

/tmp/rt_roundtrip /tmp/wbregion.bin /tmp/region.bin /tmp/cipher.bin /tmp/plain.bin
```

**PASS:** `ROUND-TRIP: PASS`. The probe prints one line per region, then the timings:

```
wb region: <bytes> bytes, hdr=24
target region: <bytes> bytes, hdr=96
  magic/version OK  target='libapp.so'  text_size=5513872  blob=…  pass_len=32
  blob kdf tier = 0 (0 = light/HKDF)
  wbc_open OK (… ms)
  wbc_unwrap_key OK (… ms)
  ChaCha20 decrypt: … ms

ROUND-TRIP: PASS   (total … ms for 5513872 bytes)
```

> **The numeric reference run needs regenerating.** The figures previously quoted here
> (`wbc_open` 1.1 ms, `wbc_unwrap_key` 0.83 ms, ChaCha20 11.8 ms, 13.7 ms total, on an
> aarch64 Linux host) were captured from the **pre-v3, single-region** probe. The
> per-operation costs are not expected to move - v3 relocated the blob, it did not change
> what `wbc_open` does - but the region sizes and the two-line header are new. Re-run the
> command above and paste the real output, noting the host and the wbcrypto version.

A target region that is **not** exactly `96 + soname_len` bytes makes the probe fail with
"it still carries a blob, i.e. a pre-v3 region" - that check is the point of splitting the
inputs.

Note where the time goes: **no term dominates**, and the only one that grows with `.text` is
the ChaCha20 line. `wbc_blob_kdf_tier` asserting tier 0 is what makes that true - it proves
the blob was sealed at the `light` tier. Before wbcrypto 3.0.0 this run showed `wbc_open OK
(226.3 ms)` for a 243 ms total, because the seal's KDF was a fixed Argon2id 64 MiB / 2;
sealing at `light` (HKDF-SHA256) replaces that with ~1 ms and removes the transient 64 MiB. A
`wbc_open` line in the hundreds of ms here means the tier assertion should have caught it
first - report that, it is a bug.

The white-box itself is sub-millisecond because it only ever touches the 32-byte session key.
Both the long-term key and the session key were generated, used and discarded inside
`provision_pack`/`provision_text` - only the sealed blob, the wrapped key, the nonce and the
whitened passphrase exist afterwards.

If `wbc_open` fails here, the passphrase whitening mirror has drifted
(`sopack/cipher.py` ⇄ `stub/stub_cipher.h`). If it opens but the compare fails, the
ChaCha20 mirror or the wrap has drifted.

---

## Phase 4 - Build the per-ABI skeletons (NDK + O-MVLL)

**Since region v3 there are TWO artifacts per ABI**, and they must be built in this order,
because 4b links against 4a's output:

| # | source | output | role |
|---|---|---|---|
| 4a | `stub/sopk_wb.c` | `sopk_wb_<abi>.so` → `libsopk_wb.so` | ONE shared white-box provider per ABI. Links `libwbcrypto.a`, owns every `wbc_*` call and the sealed blob, exports exactly `sopk_wb_k`. |
| 4b | `stub/sopk_rt.c` | `sopk_rt_<abi>.so` | The THIN per-target helper. Links **no** white-box; the packer clones it once per protected library. |

Why the split, in one line: the trigger must stay 1:1 with the target (bionic runs a shared
object's constructors **once**, so one helper shared by N targets would only decrypt the
libraries already mapped when the first loads), but the ~465 KB of white-box code and the
~455 KB blob do not need duplicating N times. Full argument in `ARCHITECTURE.md` §11b; see
also `stub/sopk_wb.h`.

`./scripts/build_wbaes.sh` does both in one step. The manual recipe follows.

First the Android runtime library - `libwbcrypto.a` **bundles libsodium** since 2.0.0, so the
separate Android `libsodium.a` the old recipe built by hand is no longer needed:

```bash
cd "$WBC"
./scripts/build_android.sh --abi arm64-v8a --api 24     # -> build-android/libwbcrypto.a
cp build-android/libwbcrypto.a include/wbcrypto.h "$SOPACK/assets/wbc/"
```

**4a - the shared provider.** Add YOUR O-MVLL plugin flags to this line:

```bash
CXX="$NDK/toolchains/llvm/prebuilt/$(uname | tr A-Z a-z)-x86_64/bin/clang++"
# (on Apple Silicon the prebuilt dir is still darwin-x86_64)

"$CXX" --target=aarch64-linux-android24 -fPIC -shared -O2 -g0 \
    -ffile-prefix-map="$WBC=." -ffile-prefix-map="$SOPACK=." \
    -fvisibility=hidden -Wl,--exclude-libs,ALL -Wl,--no-undefined \
    -Wl,-soname,libsopk_wb.so \
    -static-libstdc++ \
    -I"$WBC/include" -I"$SOPACK/stub" \
    -x c "$SOPACK/stub/sopk_wb.c" -x none \
    "$SOPACK/assets/wbc/libwbcrypto.a" \
    -o "$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so"

"$(dirname "$CXX")/llvm-strip" --strip-all "$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so"
```

Six things about that link line, all load-bearing:

- **Use `clang++`, not `clang`, and link libc++ STATICALLY.** `libwbcrypto.a` is C++, so the
  C driver leaves the entire C++ runtime unresolved - `operator new`/`delete`, `__cxa_*`,
  `std::runtime_error`, `typeinfo`, vtables, `__gxx_personality_v0`, dozens of them. Static,
  because a `libc++_shared.so` dependency would be another `.so` to ship and sopack's
  dependency-closure guard rejects it (check P1 below is what catches that).

- **`-x c` on the source, `-x none` after it.** `sopk_wb.c` is C; the C++ driver would
  otherwise compile it as C++. `-x none` restores by-extension handling so the archive that
  follows is still treated as an archive. (Upstream hit this exact trap in its own examples
  build.)

- **`-Wl,--no-undefined` is not optional.** A `-shared` link permits unresolved symbols by
  default, so if `libwbcrypto.a` is a **1.x** archive - no `wbc_wrap_key`/`wbc_unwrap_key`/
  `wbc_wipe`/`wbc_random`/`wbc_bulk_*` - the link **succeeds silently** and leaves
  `wbc_unwrap_key` and `wbc_wipe` as `UND` imports. Nothing complains until the device, where
  bionic cannot resolve them, `dlopen` of the *provider* fails, and therefore `dlopen` of the
  thin helper and of the **target** fails too - surfacing as a crash inside whatever was
  loading the target, nowhere near the real cause. `--no-undefined` turns it into `undefined
  reference to 'wbc_unwrap_key'` at build time. This is why the `build_android.sh` step above
  is a prerequisite and not a suggestion: nothing under `assets/` is tracked (it holds large
  third-party binaries), so the archive is whatever you last built there - check it before
  blaming the link.

- **Do not link `libwbvm.a` / `libwbprovision.a`.** Those carry the *provisioning* surface
  (`wbc_seal_key`, the white-box generator, the reference AES) which must never ship in an
  app. Only `libwbcrypto.a` (the runtime set) belongs here.

- **`-Wl,--exclude-libs,ALL` is what hides the `wbc_*` symbols.** `WBC_API` expands to
  `visibility("default")` inside the archive's own objects, baked in when the archive was
  built, so neither `-fvisibility=hidden` nor `-DWBC_STATIC` on this compile can remove
  them. Without it the provider advertises `wbc_open`/`wbc_unwrap_key` in its dynamic symbol
  table, which hands a reverser a labelled map of the scheme.

  If check P3 below prints more than `sopk_wb_k`, `--exclude-libs` did not take effect (its
  coverage has varied across lld versions). Use a version script instead - it works regardless
  of where the visibility came from, because it filters at link time:

  ```bash
  printf '{ global: sopk_wb_k; local: *; };\n' > /tmp/only-entry.map
  # ...add to the clang++ line, alongside or instead of --exclude-libs:
  #   -Wl,--version-script=/tmp/only-entry.map
  ```

- **`-Wl,-soname,libsopk_wb.so` is load-bearing, not tidiness.** The thin helper's `DT_NEEDED`
  string is whatever the linker recorded here. Without an explicit soname, lld records the file
  **path** it was given (`.../sopack/stubs/sopk_wb_arm64-v8a.so`) and the resulting APK cannot
  load. The packer *asserts* this rather than fixing it - it cannot fix it, because every thin
  helper already recorded the string at link time, and it never renames this artifact.

If `-static-libstdc++` is not accepted, drop it and append the two archives explicitly after
`libwbcrypto.a` instead:

```bash
SYSROOT="$NDK/toolchains/llvm/prebuilt/$(uname | tr A-Z a-z)-x86_64/sysroot"
    "$SYSROOT/usr/lib/aarch64-linux-android/libc++_static.a" \
    "$SYSROOT/usr/lib/aarch64-linux-android/libc++abi.a" \
```

**4b - the thin helper.** Simpler than 4a: plain `clang`, no static libc++, no `-x c` dance, no
`libwbcrypto.a`. But it **must** take the provider as a link input, so `--no-undefined` still
holds and the `DT_NEEDED` comes from the provider's `DT_SONAME` rather than being invented:

```bash
CC="$(dirname "$CXX")/clang"

"$CC" --target=aarch64-linux-android24 -fPIC -shared -O2 -g0 \
    -ffile-prefix-map="$SOPACK=." \
    -fvisibility=hidden -Wl,--no-undefined \
    -I"$SOPACK/stub" \
    "$SOPACK/stub/sopk_rt.c" \
    "$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so" \
    -o "$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"

"$(dirname "$CXX")/llvm-strip" --strip-all "$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"
```

The thin helper exports nothing by design - its only entry point is an ELF constructor, which
the loader reaches through `DT_INIT_ARRAY`, not the symbol table. No `-llog` on either artifact
unless you also pass `-DSOPK_RT_LOG` (Phase 6).

**Keep the thin helper under the same O-MVLL flags as the provider.** Otherwise every packed app
ships an identical un-obfuscated copy of the decrypt-and-place dance - a hardening regression
versus the pre-v3 single artifact.

This is the RELEASE line, and it is the default for a reason. Built without `-g0` and the
strip, these carry megabytes of DWARF naming `sopk_rt_ctor`, the whole `wbc_*` API and the VM
handler set, plus a multi-thousand-entry `.symtab` and the absolute host source paths. A
static-analysis report on a shipped APK named exactly that as the single largest shortcut it
had. See [`HARDENING.md`](./HARDENING.md) § Method 5 for what the pack-time strip removes on
top of this.

`--strip-all` keeps `.dynsym`/`.dynstr` and the section header table, which is what bionic
needs. It is **not** the section-header stripping that `HARDENING.md` § Method 3 rejected;
that zeroed `e_shoff`, and Android 14+ refuses to load the result.

For the **Phase 6** tracing build, add `-DSOPK_RT_LOG -llog` (the `-D` may sit anywhere on the
line - the driver collects defines globally - but `-llog` must come after the source). Such an
artifact must then be packed with `sopack pack --allow-helper-log`, because it logs the target
soname and the `.text` address and size to logcat; the packer refuses it otherwise, and the
result is not shippable.

**PASS checks - and they DIFFER per artifact.** The expectations invert: the provider must
export exactly one symbol and define every `wbc_*`; the thin helper must export nothing and
reference no `wbc_*` at all. `sopack pack` re-runs all of these (and refuses on failure), so
this is the early-warning copy, not the only line of defence:

```bash
P="$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so"      # provider
S="$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"      # thin helper
NM="$NDK"/toolchains/llvm/prebuilt/*/bin/llvm-readelf

# ---- the provider ----
# P1. only bionic dependencies. libc++_shared.so means the static libc++ did not take effect.
$NM -dW "$P" | grep NEEDED
# P2. DT_SONAME must be exactly libsopk_wb.so - see the -Wl,-soname note above.
$NM -dW "$P" | grep SONAME
# P3. exports EXACTLY sopk_wb_k. Nothing means --exclude-libs/a version script swallowed the
#     entry; extra names mean --exclude-libs did not take effect.
$NM --dyn-syms "$P" | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" {print $8}'
# expect exactly: sopk_wb_k
# P4. IMPORTS no wbc_* - anything here means a PRE-3.0.0 archive. wbc_blob_kdf_tier in
#     particular is the 3.0.0-only symbol.
$NM --dyn-syms "$P" | awk '$7=="UND" && $8 ~ /^(wbc_|sodium_)/ {print $8}'
# expect NO output

# ---- the thin helper ----
# S1. bionic + libsopk_wb.so, and libsopk_wb.so must be PRESENT (a helper that lost it fails on
#     device as "cannot locate symbol sopk_wb_k", taking the target's dlopen with it).
$NM -dW "$S" | grep NEEDED
# expect libc.so / libm.so / libdl.so / libsopk_wb.so (+ liblog.so if built with tracing)
# S2. exports nothing
$NM --dyn-syms "$S" | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" {print $8}'
# expect NO output
# S3. imports sopk_wb_k and NO wbc_*/sodium_* - since v3 only the provider touches the white-box
$NM --dyn-syms "$S" | awk '$7=="UND" {print $8}' | grep -E '^(sopk_wb_k|wbc_|sodium_)'
# expect exactly: sopk_wb_k

# ---- both ----
# B1. each carries ITS OWN build marker. The two values differ on purpose: with one shared
#     marker, a fresh thin helper + a stale provider would pass both checks.
python3 -c "
from sopack.rt_meta import HELPER_BUILD_MARKER as h, PROVIDER_BUILD_MARKER as p
print('helper  marker:', h in open('$S','rb').read())
print('provider marker:', p in open('$P','rb').read())"
# expect True, True

# B2. stripped: no symbol table, no DWARF, no host build paths - and still a section table
for f in "$P" "$S"; do
  $NM -SW "$f" | grep -cE '\.symtab|\.debug_'    # expect 0
  strings "$f" | grep -cE '^/(Users|home)/'       # expect 0
done

# B3. THE SIZE SPLIT - this is the point of the v3 design, so check it.
ls -l "$P" "$S"
# provider ~470 KB (ships ONCE per ABI); thin helper a few KB. A thin helper anywhere near
# 470 KB means it still statically links libwbcrypto.a, and nothing was saved.
```

Check B1 is what stops a **stale** skeleton shipping. The on-device ctor requires an exact
region-version match and otherwise aborts with no explanation, so a skeleton built from an
older `sopk_rt.c`/`sopk_wb.c` would produce an APK that crashes with encrypted `.text` and no
diagnostic. sopack refuses such a skeleton at pack time instead.

---

## Phase 5 - Pack a real APK and inspect the output

```bash
cd "$SOPACK"
mkdir -p output                 # sopack does not create it, and apksigner will fail without it

APK=path/to/your.apk
OUT=output/vsa-encrypted.apk
TGT=libso1.so                   # the lib you check below

python3 -m sopack.cli pack "$APK" \
  --lib "libso1.so,libso2.so" \
  --cipher wbaes \
  --abi arm64-v8a \
  --wb-keygen "$SOPACK_WBKEYGEN" \
  -o "$OUT" \
  --verify
```

**Quote the `--lib` list.** It is comma-separated but must be ONE argv word: unquoted
`--lib libso1.so, libso2.so` shell-splits, and argparse rejects the second name with
`error: unrecognized arguments: libso2.so`.

Verify the output APK:

```bash
OUT="$OUT" TGT="$TGT" python3 - <<'PY'
import zipfile, subprocess, tempfile, os, math, collections
Z = zipfile.ZipFile(os.environ["OUT"]); TGT = os.environ["TGT"]
libs = [n for n in Z.namelist() if n.startswith("lib/arm64-v8a/")]
helper = f"lib/arm64-v8a/libsopk_rt_{TGT[:-3]}.so"
provider = "lib/arm64-v8a/libsopk_wb.so"
print("1) helper added         :", helper in libs)
print("1) provider added       :", provider in libs)
print("1) exactly ONE provider :", sum(n.endswith("/libsopk_wb.so") for n in libs) == 1)
print("2) helper is STORED     :", Z.getinfo(helper).compress_type == zipfile.ZIP_STORED)
print("2) provider is STORED   :", Z.getinfo(provider).compress_type == zipfile.ZIP_STORED)
print("2) target is STORED     :", Z.getinfo(f"lib/arm64-v8a/{TGT}").compress_type == zipfile.ZIP_STORED)
def extract(n):
    p = os.path.join(tempfile.gettempdir(), os.path.basename(n))
    open(p,"wb").write(Z.read(n)); return p
tp, hp, pp = extract(f"lib/arm64-v8a/{TGT}"), extract(helper), extract(provider)
for label,p in (("target",tp),("helper",hp),("provider",pp)):
    al = subprocess.run(f"readelf -lW {p} | awk '/LOAD/{{print $NF}}' | sort -u",
                        shell=True, capture_output=True, text=True).stdout.split()
    print(f"3) {label} 16K-aligned  :", all(int(a,16)%16384==0 for a in al), al)
need = subprocess.run(f"readelf -dW {tp} | grep NEEDED", shell=True, capture_output=True, text=True).stdout
print("4) target NEEDs helper  :", f"libsopk_rt_{TGT[:-3]}.so" in need)
# 4b) CLOSURE: the thin helper must NEED the provider, and its DT_SONAME must match.
hneed = subprocess.run(f"readelf -dW {hp} | grep NEEDED", shell=True, capture_output=True, text=True).stdout
psn = subprocess.run(f"readelf -dW {pp} | grep SONAME", shell=True, capture_output=True, text=True).stdout
print("4) helper NEEDs provider:", "libsopk_wb.so" in hneed)
print("4) provider SONAME OK   :", "libsopk_wb.so" in psn, "|", psn.strip())
# 5) .text is encrypted (high Shannon entropy)
o = subprocess.run(f"readelf -SW {tp}", shell=True, capture_output=True, text=True).stdout
for ln in o.splitlines():
    if " .text " in ln:
        parts = ln.replace("]"," ").split(); i = parts.index("PROGBITS")
        off, size = int(parts[i+2],16), int(parts[i+3],16)
data = open(tp,"rb").read()[off:off+size]
c = collections.Counter(data); H = -sum(v/len(data)*math.log2(v/len(data)) for v in c.values())
print(f"5) .text entropy        : {H:.2f} bits/byte (encrypted ≈ 8.0)")
# 6) the added files must not stand out from the libraries they ship beside
stamps = {n: Z.getinfo(n).date_time for n in libs}
print("6) helper timestamp OK  :", stamps[helper][0] != 1980,
      "| provider:", stamps[provider][0] != 1980,
      "| distinct stamps:", len(set(stamps.values())))
# 7) neither added file carries a symbol table, DWARF or host build paths
for label, f in (("helper", hp), ("provider", pp)):
    sec = subprocess.run(f"readelf -SW {f}", shell=True, capture_output=True, text=True).stdout
    bad = [n for n in (".symtab", ".strtab", ".debug_") if n in sec]
    paths = [l for l in subprocess.run(f"strings {f}", shell=True, capture_output=True,
                                       text=True).stdout.splitlines()
             if l.startswith(("/Users/", "/home/"))]
    print(f"7) {label} stripped      :", not bad, "| leftover:", bad,
          "| no host paths:", not paths)
    print(f"7) {label} shstrtab      :", ".shstrtab" in sec)
# 8) THE SIZE SPLIT survives into the APK
print("8) sizes                :", "helper", len(Z.read(helper)), "provider", len(Z.read(provider)))
PY
```

**PASS:** all of (1)–(4) `True` - including **exactly one** provider per ABI, the helper
depending on it, and the provider's `DT_SONAME` being literally `libsopk_wb.so`; (5) entropy
≈ 8.0 (encrypted); (6) the added entries' ZIP timestamps match the Gradle-built libraries
around them rather than 1980-01-01 - an outlier there was the *first* thing a static-analysis
report noticed about a shipped APK, before any disassembly; (7) no `.symtab`/`.debug_*`/host
paths on either, `.shstrtab` still present; (8) the thin helper is a few KB and the provider
~470 KB. `--verify` prints a signer cert. No AES key appears anywhere: the long-term key is
diffused into the white-box blob (inside the provider), and each session key ships only in
its wrapped form.

**(9) The target's exported symbol names must be unchanged.** `inject_so` already refuses to
pack otherwise, but check it here too - it is the failure that produced a loading-then-crashing
APK, and it is invisible to every other check in this list:

```bash
APK="$APK" OUT="$OUT" TGT="$TGT" python3 - <<'PY'
import zipfile, os, sys
sys.path.insert(0, ".")
from sopack.elf_inject import _dynsym_names
TGT = os.environ["TGT"]
for tag, apk in (("orig", os.environ["APK"]), ("packed", os.environ["OUT"])):
    z = zipfile.ZipFile(apk)
    open(f"/tmp/{tag}_{TGT}", "wb").write(z.read(f"lib/arm64-v8a/{TGT}"))
a, b = _dynsym_names(f"/tmp/orig_{TGT}"), _dynsym_names(f"/tmp/packed_{TGT}")
print(f"{len(a)} symbols; PRESERVED: {a == b}")
if a != b:
    print("  first diff:", next((x, y) for x, y in zip(a, b) if x != y))
PY
```

Expect `PRESERVED: True`. Note this must be resolved via `DT_STRTAB` (as `_dynsym_names` does),
not `readelf`'s section-header view - in this mode the two legitimately point at different
tables, so `readelf --dyn-syms` alone can mislead in either direction.

---

## Phase 6 - On-device (the last mile; needs a device/emulator, arm64)

**Strongly recommended for the FIRST device test: build both skeletons with tracing** so each
helper's decrypt is visible in logcat (a release build does not log, so an abort names no
cause). Add `-DSOPK_RT_LOG -llog` to the Phase-4 lines, rebuild, re-pack with
`--allow-helper-log`, then:

```bash
adb install -r out.apk
adb logcat -c && adb shell am start -n <pkg>/<launcher-activity>
# TWO tags since the v3 split: sopk_rt = each thin helper, sopk_wb = the shared provider
# (which is where the KDF-tier line comes from). DEBUG = native crash tombstones.
adb logcat -s sopk_rt sopk_wb DEBUG
```

With tracing you should see one line PER packed library, e.g.:
`decrypted 'libapp.so' .text (5513872 bytes) at 0x… - OK`, plus `blob kdf tier = 0` from the
`sopk_wb` tag. A `SIGABRT` names the exact step that failed; `sopk_fail_code` in the tombstone
gives the code, and provider failures arrive in the **10..19** band (see `stub/sopk_wb.h`, and
[`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) for the full list).

**PASS:**
- One `… - OK` line per packed library, and the app launches and behaves normally - meaning
  each helper's constructor ran **before** its target's init and decrypted `.text` in place.
- **No** `SIGILL`/`SIGSEGV` from a target (a crash there = its `.text` ran still-encrypted).
- **COUNT THE LINES.** `sopack pack` reports how many libraries it injected; you need that many
  `- OK` lines. A missing one does **not** necessarily mean failure - a library the app never
  loads never runs its helper - but you must establish which it is rather than assume. Check
  whether it was loaded at all:

  ```bash
  PID=$(adb shell pidof <pkg>)
  adb shell run-as <pkg> cat /proc/$PID/maps | grep -E 'libvtap|libsopk'
  ```

  If the library IS mapped and there is no `- OK` line for it, that is a real failure: its
  `.text` is running encrypted and it will `SIGILL` when reached.
- If your app loads more than one packed library at **different** times (separate
  `System.loadLibrary` / `dlopen` calls), exercise each and confirm all work / all log OK -
  this validates the one-thin-helper-per-target design. Note the log will show different TIDs
  for libraries loaded on different threads; that is the design working, not a problem. A single
  helper shared by N targets would only ever decrypt the first group.

**Confirm the `light` KDF tier is actually in effect.** This is a *confirmation* step, not a
decision: since wbcrypto 3.0.0 the blob is sealed with `--kdf light`, so each `wbc_open` should
be single-digit-to-low-teens ms and there should be **no ~64 MiB spike per library**. With a
tracing build the provider logs `blob kdf tier = 0` before opening. Things to read off logcat:

- `blob kdf tier = 0` - anything else means a pre-3.0.0 host `wb_keygen` sealed the blob, which
  the pack-time gate (`provision.assert_light_blob`) should have refused. If it packed anyway,
  that is a bug worth reporting.
- an `open=` in the hundreds of ms - same conclusion: an Argon2id-sized open means a `heavy` blob.
- `SIGABRT` with `sopk_fail_code == 16` (provider reason 6, `SOPK_WB_ERR_TIER`) -
  `wbc_blob_kdf_tier` rejected the header, i.e. the runtime and the blob format disagree (a
  pre-3.0.0 `libwbcrypto.a` linked into the provider against a v4 blob). The full code table is
  in [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md).

**Then measure startup cost and memory.** The provider is stateless, so each protected library
still pays its own `wbc_open` - `Unseal` AEAD-decrypts the ~455 KB blob and builds the VM image,
~1 ms on a host - and with N packed libraries you pay that N times, at a far smaller constant
than the pre-3.0.0 ~230 ms:

```bash
adb shell am start -W -n <pkg>/<launcher-activity>   # TotalTime = startup wall clock
adb shell dumpsys meminfo <pkg> | head -20           # peak RSS around startup
```

Record both, and compare peak RSS against the pre-3.0.0 baseline (which carried N × 64 MiB of
transient Argon2id arena). What these numbers decide is whether caching the provider's
`wbc_ctx` is worth doing - see [`IMPROVEMENTS.md`](./IMPROVEMENTS.md) §1. The APK-size question
that used to live here is already answered: since v3 the ~465 KB of white-box code and the
~455 KB blob ship **once per ABI**, not once per library.

For a **release** build, drop `-DSOPK_RT_LOG -llog` - nothing then logs, and neither artifact
depends on liblog.

Optional runtime confirmation on a 16 KB device: `adb shell getconf PAGE_SIZE` → `16384`, and
the app still runs.

---

## Appendix - one request to send upstream: scrub build paths from `libwbcrypto.a`

Not a sopack change, and - since the strip landed - **not urgent**. Recording it so it is asked
for once rather than rediscovered.

A static-analysis report on a shipped APK reported a host path in the artifact's `.rodata`:

```
/Users/<user>/src/opensource/<org>/whitebox-cryptography/third_party/libsodium/libsodium-1.0.20/src/libsodium/crypto_verify/verify.c
```

which leaks a developer username, the internal project name, and the exact libsodium version
for CVE matching. **Measurement corrected the location:** in the reference skeleton every such
string lives in `.debug_str`, `.debug_line` and `.strtab` - 40, 98 and a handful of hits - and
**none** in `.rodata` or `.data.rel.ro`. All three are non-`SHF_ALLOC`, so the pack-time strip
(`HARDENING.md` § Method 5) already removes every one. `_emit_helper` warns if any survives,
which would mean a mapped section and therefore an archive-side fix.

Still worth doing upstream as defence in depth, because it stops the strings existing at all:

```cmake
# top-level CMakeLists.txt, covering first-party sources and vendored libsodium alike
add_compile_options(
    -ffile-prefix-map=${CMAKE_SOURCE_DIR}=.
    -ffile-prefix-map=${CMAKE_BINARY_DIR}=.
)
```

Two things to pass on with it:

- `-ffile-prefix-map` is `-fdebug-prefix-map` **plus** `-fmacro-prefix-map`. Only the macro half
  rewrites the `__FILE__` strings that libsodium's assert/misuse macros bake into `.rodata`, so
  `-fdebug-prefix-map` alone would not have fixed the case the report described.
- `scripts/build_android.sh` should pass `-g0` for release archives, so no DWARF is produced to
  carry paths in the first place.

sopack's own side is already done: `scripts/build_wbaes.sh` passes both `-ffile-prefix-map` flags
and `-g0`, but those cannot reach strings already compiled into the archive.
