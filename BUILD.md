# BUILD / RUN guide

The `sopack` source is complete **and validated end-to-end**. This guide runs it on a
machine with Python 3.10+, a JDK, the Android SDK build-tools, and (optionally) the NDK.

## What has been verified (aarch64 Linux, no NDK, no root)

The whole pipeline was exercised on an ARM64 host using only user-space tools
(Miniforge Python + LIEF, conda LLVM, conda OpenJDK, `apksigner.jar`):

- **Stub blobs** for all 3 ABIs compile to flat, **relocation-free** images with the
  correct syscalls and the full arm64 cache-flush sequence
  (`dc cvau`/`dsb`/`ic ivau`/`dsb`/`isb`).
- **Injector**: encrypts `.text`, injects the R+X stub segment (16 KB-aligned),
  hijacks `DT_INIT`, and passes the 5-point self-verification.
- **Runtime (real ARM64)**: the injected `.so`, `dlopen`ed, has its `.text` decrypted
  at load by the stub (mmap → ChaCha20 → mremap-onto-original-base → mprotect → cache
  flush). `.rodata` references still resolve. Both ChaCha20 and XOR round-trip.
- **APK path**: repackage (STORED libs) → **16 KB alignment** → `apksigner` sign +
  verify. The library extracted from the *signed* APK still decrypts and runs.
- **Real Flutter APK**: encrypted `lib/arm64-v8a/libapp.so` (3.1 MB of Dart AOT `.text`,
  a library with *no* init hook). On-disk `.text` entropy 4.32→7.997 bits/byte;
  `dlopen` round-trips to the exact original Dart instructions. Confirms the in-place
  `DT_INIT` path and the whole pipeline on a production-shaped library.

The only step that requires your hardware is confirming the same runtime behavior on
an actual **Android** device (the host above lacks Android's SELinux `execmem` policy,
which the Handover establishes is granted to apps). Run `stub/phase0` there first.

## Two toolchain notes learned during validation

- **No NDK needed for the stubs.** `stub/build_stubs.sh` falls back to plain
  `clang`/`llvm-objcopy`/`llvm-readelf` on PATH when `ANDROID_NDK_HOME` is unset
  (the stub is freestanding — no Android sysroot). Use the NDK if you want to pin a
  specific API level.
- **aarch64 hosts / no matching `zipalign`.** `sopack` includes a built-in Python 16 KB
  aligner and uses it automatically when a runnable `zipalign` isn't found. `apksigner`
  can be pointed at its jar via `SOPACK_APKSIGNER_JAR=/path/to/apksigner.jar` (it runs
  on any arch through the JDK).

---

The remainder of this guide assumes your own workstation.

## 0. Prerequisites & env

```bash
python3 --version                 # >= 3.10
which apksigner zipalign          # from $ANDROID_SDK_ROOT/build-tools/<ver>/
which keytool                     # from the JDK
export ANDROID_SDK_ROOT=/path/to/Android/sdk
export ANDROID_NDK_HOME=/path/to/Android/sdk/ndk/<version>
```

## 1. Build the injectable stub blobs (needs the NDK)

```bash
cd stub
ANDROID_NDK_HOME=$ANDROID_NDK_HOME ./build_stubs.sh 24     # API level arg optional
# -> sopack/stubs/stub_{arm64-v8a,armeabi-v7a,x86_64}.{bin,json}
```

`build_stubs.sh` **fails hard** if any ABI's blob ends up with a dynamic relocation or
an undefined external symbol — that guarantees the blob is self-contained and safe to
inject. If it fails, the stub is reaching outside itself (e.g. a `__clear_cache`
libcall crept back in); fix before continuing.

## 2. Install the tool

```bash
cd ..
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # pulls LIEF>=0.15
pip install pytest          # for the tests
```

## 3. Run the unit tests (validates the C<->Python contract)

```bash
python -m pytest tests/ -v
# test_cipher.py  -> ChaCha20 matches RFC 8439 (so the C stub, a line-for-line mirror,
#                    produces the same keystream)
# test_metadata.py-> decinfo stays 128 bytes and round-trips
```

## 4. Phase 0 — prove the runtime path on a device FIRST

Before trusting the injector, confirm mremap-onto-base executes under W^X/SELinux:
see `stub/phase0/README.md`. Build `libphase0.so`, load it from a **debuggable app**
(so it runs in the `untrusted_app` domain), and check:

```bash
adb logcat -s sopack-phase0        # expect: target(5) = 38 ... mremap-onto-base OK
adb logcat | grep -i 'avc: denied' # must be empty
```

Do this on Android 14 (4 KB pages) and Android 15/16 (16 KB pages), each ABI you ship.

## 5. Pack an APK

```bash
printf 'libnative-lib.so\n' > libs.txt      # bare name = all ABIs; or lib/arm64-v8a/...
sopack pack app.apk --libs libs.txt -o app-packed.apk --verify
```

The injector runs a **desktop self-verification** on every library (round-trip decrypt,
`.text` vaddr stability, 16 KB segment congruence, hook target, no `TEXTREL`) and aborts
with a clear error rather than emitting a silently-broken `.so`.

## 6. Verify the output

```bash
unzip -o app-packed.apk lib/arm64-v8a/libnative-lib.so -d /tmp/chk
readelf -x .text /tmp/chk/lib/arm64-v8a/libnative-lib.so | head    # random bytes
readelf -l /tmp/chk/lib/arm64-v8a/libnative-lib.so | grep LOAD     # new R E, align 2**14
readelf -d /tmp/chk/lib/arm64-v8a/libnative-lib.so | grep TEXTREL  # empty
apksigner verify --print-certs app-packed.apk
```

Install and launch on device; watch `adb logcat | grep -E 'avc|SIGSEGV'` (clean), and
confirm the app's native features still work.

## Reminders

- Re-signing = **new signing identity**: cannot update-install over the original; in-app
  signature checks will see the new cert.
- Security is **obfuscation only** — the key ships in the binary.
- arm64 is the reference ABI; get it green before trusting armv7 / x86_64.
