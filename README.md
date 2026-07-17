# sopack — black-box Android `.so` encryptor / APK repackager

`sopack` takes an **existing APK** plus a list of native libraries and produces a
**self-signed APK** in which each listed `.so` has its code (`.text`) encrypted at
rest and transparently decrypted at load time — **without any access to the library
source**. It is the Model-2 ("black-box injection") realization of the design in
[`Handover.md`](./Handover.md).

> ⚠️ **This is obfuscation, not security.** The decryption key ships inside the
> binary, and plaintext exists in a readable `R-X` mapping at runtime. Any Frida hook
> or `/proc/self/maps` dump recovers everything. Treat this as anti-static-analysis
> only. Also: re-signing gives the APK a **new signing identity** — it cannot be
> installed as an update over the original, and in-app signature checks will see the
> new certificate.

```
sopack pack in.apk --libs libs.txt -o out.apk [--cipher chacha20|xor] [--abi ...]
```

## How it works

For each requested `lib/<abi>/*.so` inside the APK:

1. **Encrypt `.text`** in place with a stream cipher (ChaCha20 or XOR) — same length,
   same file offsets, so ELF layout is untouched. Random per-library key + nonce.
2. **Inject a freestanding stub** (`stub/stub.c`, compiled per ABI to a flat,
   relocation-free blob) as a new **R+X `PT_LOAD`** segment, 16 KB-aligned.
3. **Hijack load-time execution** so the stub runs before any encrypted code:
   repoint `DT_INIT` (chaining the original), else overwrite `DT_INIT_ARRAY[0]`, else —
   for libraries with no init hook at all (e.g. Flutter's `libapp.so`) — add a `DT_INIT`
   **in place** by overwriting the existing `DT_NULL` terminator (relying on the
   following `.bss`/zero bytes as the new terminator), which keeps `.dynamic` writable
   and in place and avoids adding a mis-aligned segment that would break 16 KB loading.
4. **At runtime**, the stub (W^X / SELinux `execmem`-safe, per `Handover.md` §3B):
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
  cli.py              `sopack pack …`
  apk.py              unzip → inject → zipalign → apksigner; keystore mgmt
  elf_inject.py       LIEF: encrypt .text, add segment, hijack init, patch metadata
  cipher.py           ChaCha20 / XOR — MUST match stub/stub_cipher.h
  metadata.py         decinfo pack/parse — MUST match stub/decinfo.h
  stubs.py            loads the prebuilt per-ABI blobs
  stubs/              stub_<abi>.bin + stub_<abi>.json  (built by build_stubs.sh)
stub/                 the injectable runtime stub (C)
  stub.c              entry: mmap/decrypt/mremap-onto-base/mprotect/flush/chain
  syscalls.h          freestanding syscalls (arm64/x86_64/arm), page size, memcpy
  stub_cipher.h       ChaCha20 / XOR — mirror of cipher.py
  decinfo.h           the 128-byte injector<->stub contract
  stub.ld             link at vaddr 0 → single R+X image
  build_stubs.sh      NDK build → flat blobs + offsets (fails on any relocation)
tests/                cipher KAT (RFC 8439) + metadata layout
```

## Build & run

**Prerequisites** (not bundled): Python 3.10+, LIEF, a JDK (`keytool`), Android SDK
build-tools (`zipalign`, `apksigner`), and the NDK (to build the stub blobs once).

```bash
# 1. Build the stub blobs (once, needs the NDK)
ANDROID_NDK_HOME=/path/to/ndk ./stub/build_stubs.sh        # -> sopack/stubs/*.bin

# 2. Install the tool
pip install -e .                                           # pulls in LIEF

# 3. Point at your SDK (for zipalign/apksigner) if not on PATH
export ANDROID_SDK_ROOT=/path/to/android/sdk

# 4. Pack
printf 'libnative-lib.so\n' > libs.txt
sopack pack app.apk --libs libs.txt -o app-packed.apk --verify

# 5. Sanity-check the result
python -m pytest tests/
```

`libs.txt` entries may be bare basenames (`libfoo.so` → matches every selected ABI)
or full APK paths (`lib/arm64-v8a/libfoo.so`).

## Verification checklist

- **Static:** `readelf -x .text out.so` (random), `readelf -l out.so` (new `R E`
  LOAD, align `2**14`), `readelf -d out.so | grep TEXTREL` (empty),
  `apksigner verify --print-certs out.apk`.
- **Dynamic:** install & launch; `adb logcat | grep -E 'avc|SIGSEGV'` must be clean;
  a `/proc/<pid>/maps` dump should show plaintext at the original `.text` VA post-load.
- **Decrypt confirmation (opt-in):** pack with `--log` and the stub emits a logcat line
  on success — `adb logcat -s sopack:I` shows `I sopack: native .text decrypted OK`
  (written straight to `logd`; no liblog dependency). Omit `--log` for a silent stub.
- **Device matrix:** Android 14 (4 KB) and 15/16 (16 KB emulator + real device),
  each ABI. See `stub/phase0/` for a standalone runtime-path spike to run first.

## Known limitations

- Per-library fragility (section-stripped libs, exotic init code) — the tool fails
  loudly rather than silently corrupting.
- 32-bit ARM and x86_64 stubs exist but need the same on-device validation as arm64.
- LIEF-rebuilt ELFs occasionally trip strict loaders; validate a real `dlopen`.
- Security is obfuscation only (see the warning above).
