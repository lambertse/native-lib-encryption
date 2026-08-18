# sopack - black-box Android `.so` encryptor / APK repackager

`sopack` takes an **existing APK** and produces a **self-signed APK** in which each
selected `.so` has its code (`.text`) encrypted at rest and transparently decrypted at
load time - **without any access to the library source**. By default every
`lib/<abi>/*.so` in the APK is encrypted; name a specific list in the config file to narrow
that. It is a black-box ELF-injection packer; see [`docs/`](./docs/) for the
full design and reasoning.

> ⚠️ **This is obfuscation, not security.** The decryption key ships inside the
> binary, and plaintext exists in a readable `R-X` mapping at runtime. Any Frida hook
> or `/proc/self/maps` dump recovers everything. Treat this as anti-static-analysis
> only. Also: re-signing gives the APK a **new signing identity** - it cannot be
> installed as an update over the original, and in-app signature checks will see the
> new certificate. Full threat model: [`docs/SECURITY.md`](./docs/SECURITY.md).

```
sopack pack in.apk -o out.apk [--config PATH]
sopack init-config                              # write a commented config.yaml
```

**The command line carries only the input and output APK.** Everything else - cipher, ABIs,
library selection, keystore, signing, logging - lives in a YAML config file. sopack reads
`--config PATH` if you pass one, else `./config.yaml`, else its built-in defaults.

```yaml
cipher: wbaes            # or chacha20 / xor
abis:
  - arm64-v8a            # the only ABI protected in practice; `abis: all` for every one
libraries:
  include:               # omit entirely to encrypt every lib/<abi>/*.so
  exclude: [libmy*]
signing:
  verify: true           # apksigner --print-certs after signing
```

[`config.sample.yaml`](./config.sample.yaml) is the full commented reference, and is exactly
what `sopack init-config` writes. Every key in it is set to its default, so an unedited config
packs identically to no config at all.

An **unknown or misplaced key is an error**, not a warning - a silently ignored
`verify: false` is worse than a typo.

Before the first `wbaes` pack, build the per-ABI artifacts once:

```
git submodule update --init      # the pinned whitebox-cryptography dependency
pip install -e .
./scripts/build_wbaes.sh         # needs the Android NDK, macOS or Linux/x86_64 for O-MVLL,
                                 # and network once
```

That builds the white-box library and a host `wb_keygen` from the submodule and leaves them
where sopack finds them on its own - there is no keygen path to configure. If you would rather
not build anything, `cipher: chacha20` works from a bare checkout.

## Two modes

`cipher: wbaes` is the **default**. `chacha20` and `xor` use the **freestanding stub**
described below: the key ships inside the library, whitened at rest.

`cipher: wbaes` instead protects the key with a **white-box AES-128**, so no portable key
ships at all. It needs a different delivery mechanism (normal-linkage helpers injected as a
`DT_NEEDED`, because the white-box runtime needs libc) and **two** per-ABI skeletons built from
the pinned whitebox-cryptography submodule - a thin per-target helper plus one shared white-box
provider. `./scripts/build_wbaes.sh` produces both; they are host- and ABI-specific, so they are
not committed and a plain `pip install .` from a checkout will not carry them. See
[`docs/technical/ARCHITECTURE.md`](./docs/technical/ARCHITECTURE.md) §11 for how it works and
[`docs/technical/WBAES.md`](./docs/technical/WBAES.md) for the setup and verification
procedure. The rest of this page describes the stub mode.

## How it works

For each selected `lib/<abi>/*.so` inside the APK:

1. **Encrypt `.text`** in place with a stream cipher (ChaCha20 or XOR) - same length,
   same file offsets, so ELF layout is untouched. Random per-library key + nonce.
2. **Inject a freestanding stub** (`stub/stub.c`, compiled per ABI to a flat,
   relocation-free blob) as a new **R+X `PT_LOAD`** segment, 16 KB-aligned.
3. **Hijack load-time execution** so the stub runs before any encrypted code. If the
   library exposes a usable `DT_INIT`, repoint it (chaining the original); otherwise add
   a `DT_INIT` **in place** over the existing `DT_NULL` terminator. `DT_INIT_ARRAY` is
   **never** hijacked - each slot is rewritten by an `R_*_RELATIVE` relocation at load, so
   a file overwrite is silently reverted and the stub never runs. This was the hardest
   part to get right; the full reasoning, including why growing `.dynamic` breaks 16 KB
   loading, is in
   [`docs/technical/ARCHITECTURE.md`](./docs/technical/ARCHITECTURE.md) §5c.
4. **At runtime**, the stub (W^X / SELinux `execmem`-safe):
   `mmap`s anonymous RW scratch → copies the encrypted `.text` page window → decrypts
   the exact `.text` sub-range → `mremap(MREMAP_FIXED)` onto the **original `.text`
   VA** → `mprotect R-X` → flushes the I-cache → chains the original init.
   Moving the decrypted pages back to the original address keeps every PC-relative
   reference, GOT/PLT use and C++ unwind table valid, and keeps the exec transition
   on the allowed `execmem` path (never `execmod`).
5. **Repackage**: write the `.so` back **STORED** (uncompressed), `zipalign -P 16`,
   and `apksigner` self-sign with a generated keystore.

The stub never needs the library's load bias: it reaches `.text` and the original
init via signed byte deltas from the address of its own metadata record (which the
compiler references PC-relatively). See `stub/stub.c` and `stub/decinfo.h`.

## Layout

```
sopack/               Python package (the tool)
  cli.py              `sopack pack …` / `sopack init-config`
  config.py           the YAML config: schema, validation, and the sample it writes
  apk.py              unzip → inject → zipalign → apksigner; keystore mgmt
  elf_inject.py       LIEF: encrypt .text, add segment, hijack init, patch metadata
  cipher.py           ChaCha20 / XOR - MUST match stub/stub_cipher.h; plus AES-128-CTR,
                      which is the wbaes key-wrap primitive
  metadata.py         decinfo pack/parse - MUST match stub/decinfo.h
  provision.py        wbaes: seal one key per ABI, wrap a session key per library
  rt_meta.py          wbaes: both region layouts - MUST match stub/sopk_rt.h
  stubs.py            loads the prebuilt per-ABI blobs and the wbaes skeletons
  stubs/              stub_<abi>.bin + stub_<abi>.json  (built by build_stubs.sh)
stub/                 the injectable runtime stub (C)
  stub.c              entry: mmap/decrypt/mremap-onto-base/mprotect/flush/chain
  syscalls.h          freestanding syscalls (arm64/x86_64/arm), page size, memcpy
  stub_cipher.h       ChaCha20 / XOR - mirror of cipher.py
  stub_log.h          freestanding logd writer (the logging.stub-log line)
  decinfo.h           the 128-byte injector<->stub contract
  stub.ld             link at vaddr 0 → single R+X image
  build_stubs.sh      NDK build → flat blobs + offsets (fails on any relocation)
  sopk_rt.c/.h        wbaes: the thin per-target helper + both region contracts
  sopk_wb.c/.h        wbaes: the shared per-ABI white-box provider
scripts/              build_chacha20.sh / build_wbaes.sh - one entry point per cipher
                      mode; rt_roundtrip.c, the host verification probe
tests/                cipher KATs, metadata + region layouts, wbaes injection, dlopen
  fixtures/           committed aarch64 .so so the wbaes tests need no local APK
config.sample.yaml    the commented reference config (== `sopack init-config` output)
```

## Build & run

**Prerequisites** (not bundled): Python 3.9+, LIEF, PyYAML, a JDK (`keytool`), Android SDK
build-tools (`apksigner`; `zipalign` optional), and LLVM or the NDK (to build the stub
blobs once). Details in [`docs/BUILDING.md`](./docs/BUILDING.md).

```bash
# 1. Build the stub blobs (once). This wrapper also runs the tests and prints
#    the pack command; it uses an NDK if one is set, else plain LLVM on PATH.
./scripts/build_chacha20.sh                                # -> sopack/stubs/*.bin

# 2. Install the tool
pip install -e .                                           # pulls in LIEF + PyYAML

# 3. Point at your SDK (for zipalign/apksigner) if not on PATH
export ANDROID_SDK_ROOT=/path/to/android/sdk

# 4. Pack - every lib/arm64-v8a/*.so, minus the exclusions. With no config.yaml
#    present these are the defaults, so this works as-is.
sopack pack app.apk -o app-packed.apk

# 5. ... or write a config and edit it to narrow the scope
sopack init-config                                         # -> ./config.yaml
#    libraries:
#      include:
#        - libnative-lib.so
sopack pack app.apk -o app-packed.apk                      # picks up ./config.yaml

# 6. Sanity-check the result
python -m pytest tests/
```

### Choosing libraries

```yaml
libraries:
  include:                 # omit / null -> every lib/<abi>/*.so. `[]` is an ERROR.
    - libnative-lib        # bare basename -> that library in every selected ABI
    - lib/arm64-v8a/libapp.so   # or a full APK path; trailing .so is optional
  exclude:                 # fnmatch globs on the basename, trailing .so optional
    - libsopk_*            # ) shipped in every generated config, and
    - libvosWrapperEx      # ) re-applied by sopack whether or not you keep them
    - libflutter           # policy only - delete this one and it gets packed
    - libmy*
```

**Leave `include` out and every `lib/<abi>/*.so` in the APK is encrypted**, for the ABIs
`abis:` selects. In this mode a library that cannot be injected (section-stripped, no
`.dynamic` slack, not 16 KB-compatible …) is **skipped with a warning** and ships in
cleartext rather than aborting the pack - the run ends with a per-ABI summary naming
every library that was skipped and why. Read it: a skipped library is unprotected.

Naming a library explicitly restores the strict behaviour: if it cannot be injected, the
pack **fails** instead of quietly shipping it in cleartext. That asymmetry is why an empty
`include: []` is rejected outright rather than being read as "select everything" - the two
modes have different failure contracts, so widening the scope on an empty list would
silently swap one for the other.

**Exclusion always wins**, including over a name you listed in `include`. Every generated
config spells the list out, so what gets skipped is visible data rather than a hidden
built-in — but two of the entries are also enforced in code, and deleting them from your
config is a no-op:

| Pattern | Delete it from your config? | Why it is there |
| --- | --- | --- |
| `libsopk_*` | **no effect** — re-applied by `apk.build_excludes` | sopack's own injected artifacts: the shared white-box provider and the thin per-target helpers. Encrypting them would encrypt the code that does the decrypting, so this is a correctness invariant of the tool rather than a preference. |
| `libvosWrapperEx` | **no effect** — same | the V-Key/V-OS wrapper, already self-protected: packing it buys nothing and risks tripping its own integrity checks. |
| `libflutter` | **yes**, it gets packed | the stock public Flutter engine, excluded by policy and not necessity. This one lives only in the config. |

`abis:` defaults to `arm64-v8a` alone, since that is the only ABI protected in practice
(the others ship cleartext by deliberate scope choice - see
[`docs/SECURITY.md`](./docs/SECURITY.md)). Use `abis: all` for all three, or list them.

For `cipher: wbaes`, use `./scripts/build_wbaes.sh` in step 1 instead - it builds the
two extra per-ABI skeletons that mode needs.

### Keystore and secrets

```yaml
signing:
  keystore:
    path: ${HOME}/keys/release.jks
    alias: release
    store-pass: ${SOPACK_STORE_PASS}
    key-pass: ${SOPACK_KEY_PASS}
```

`${VAR}` is expanded from the environment **in the keystore block only**, so a committed
config need not hold a real password. A referenced variable that is not set is an error -
sopack will not sign with an empty password it substituted for you. Literals still work,
and `$${VAR}` escapes to a literal `${VAR}`. Leave `path` null to use (and generate)
`~/.sopack/debug.keystore`.

## Verification checklist

- **Static:** `readelf -x .text out.so` (random), `readelf -l out.so` (new `R E`
  LOAD, align `2**14`), `readelf -d out.so | grep TEXTREL` (empty),
  `apksigner verify --print-certs out.apk`.
- **Dynamic:** install & launch; `adb logcat | grep -E 'avc|SIGSEGV'` must be clean;
  a `/proc/<pid>/maps` dump should show plaintext at the original `.text` VA post-load.
- **Decrypt confirmation (opt-in):** pack with `logging.stub-log: true` and the stub emits a
  logcat line on success - `adb logcat -s sopack:I` shows `I sopack: native .text decrypted OK`
  (written straight to `logd`; no liblog dependency). Leave it false for a silent stub.
- **Device matrix:** Android 14 (4 KB) and 15/16 (16 KB emulator + real device),
  each ABI. Run [`stub/execmem-probe/`](./stub/execmem-probe/) on a new device class
  first - it checks the decrypt-and-execute path in isolation, before any packing.

For `cipher: wbaes` the checks differ (two added `.so`s per ABI, different logcat tags, and
a fail-closed abort instead of a silent degrade) - see
[`docs/technical/WBAES.md`](./docs/technical/WBAES.md) Phases 5–6.

## Known limitations

- Per-library fragility (section-stripped libs, exotic init code) - the tool fails
  loudly rather than silently corrupting.
- **Only `arm64-v8a` is protected in practice.** 32-bit ARM and x86_64 stubs exist but need
  the same on-device validation as arm64, so those ABIs ship cleartext `.text` - an analyst
  after the algorithm reads one of those builds instead. See
  [`docs/SECURITY.md`](./docs/SECURITY.md).
- LIEF-rebuilt ELFs occasionally trip strict loaders; validate a real `dlopen`.
- Security is obfuscation only (see the warning above).
