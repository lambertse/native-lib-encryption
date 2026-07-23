# Building & running sopack

A short, practical guide: install the toolchain, build the stub blobs once, pack an
APK, and verify the result. For *why* any of this is shaped the way it is, see
[`architecture.md`](./architecture.md); when something breaks, see
[`troubleshooting.md`](./troubleshooting.md).

---

## 1. Prerequisites

| Tool | Minimum | Used for |
|------|---------|----------|
| **Python** | 3.9+ | runs the packer (`requires-python = ">=3.9"`) |
| **LIEF** | 0.15+ | ELF rewriting (`pip` pulls it in; tested with 1.0) |
| **LLVM or Android NDK** | clang + lld + llvm-objcopy + llvm-readelf; **NDK r19+** (recommend r26–r28) | compiles the stub blobs **once** |
| **JDK** | 17+ (8 works) | `keytool` + running `apksigner` |
| **Android SDK build-tools** | 34.0.0+ | `apksigner`, and `zipalign` if you have an arch-matching one |

Notes:

- **No NDK required for the stubs.** The stub is freestanding (no Android sysroot), so
  any modern LLVM works. `build_stubs.sh` uses the NDK when `ANDROID_NDK_HOME` is set,
  otherwise plain `clang`/`lld`/`llvm-objcopy`/`llvm-readelf` on `PATH`.
  A valid NDK version looks like `27.0.12077973`; `4.8.0` is **not** a valid NDK and
  will fail with `invalid linker name '-fuse-ld=lld'`.
- **`apksigner` runs on any architecture** through the JDK. If you don't have an
  arch-matching launcher, point at the jar: `export SOPACK_APKSIGNER_JAR=/path/to/apksigner.jar`.
- **`zipalign` is optional.** sopack has a built-in Python 16 KB aligner and uses it
  automatically when a runnable `zipalign` isn't found (e.g. on aarch64 hosts).

---

## 2. Build the stub blobs (once)

Compiles the per-ABI decryption stub into `sopack/stubs/stub_<abi>.bin` (+ `.json`
offsets). Run it once, and again only when you change anything under `stub/`.

```bash
# with the NDK:
ANDROID_NDK_HOME=/path/to/Android/sdk/ndk/<version> bash stub/build_stubs.sh 24
# or with plain LLVM on PATH (leave ANDROID_NDK_HOME unset):
bash stub/build_stubs.sh 24
# -> sopack/stubs/stub_{arm64-v8a,armeabi-v7a,x86_64}.bin
```

`24` is the Android API level (any modern level is fine). The script **fails hard** if
any blob ends up with a dynamic relocation, an undefined external symbol, or (on
arm64) an `adrp` instruction — those guarantee the blob is self-contained and
alignment-independent. A clean run means good blobs.

> Run it with **bash**, not `sh` (`bash stub/build_stubs.sh 24`). It is bash-3.2
> compatible, so the macOS system bash works.

---

## 3. Install the tool

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .          # installs the `sopack` command + LIEF
pip install pytest        # for the tests
python -m pytest -q       # cipher KAT + metadata layout + dlopen integration
```

If `zipalign`/`apksigner` aren't on `PATH`, point sopack at your SDK/JDK:

```bash
export ANDROID_SDK_ROOT=/path/to/Android/sdk
# or, to run apksigner from its jar on any arch:
export SOPACK_APKSIGNER_JAR="$ANDROID_SDK_ROOT/build-tools/34.0.0/lib/apksigner.jar"
```

---

## 4. Pack an APK

```bash
sopack pack in.apk \
    --lib libapp.so,libother.so \
    -o out.apk \
    --abi arm64-v8a,armeabi-v7a,x86_64 \
    --cipher chacha20 \
    --log \
    --keystore "$HOME/.sopack/debug.keystore" \
    --verify
```

- `--lib` names the libraries to encrypt. It is **repeatable and/or comma-separated**
  (`--lib a.so,b.so`, `--lib a.so --lib b.so`, or a mix). A bare basename (`libapp.so`)
  matches that library in **every** selected ABI; a full path
  (`lib/arm64-v8a/libapp.so`) targets one ABI. For many libraries you can instead use
  `--libs libs.txt` (one entry per line; `#` comments allowed).
- `--abi` — omit to encrypt all three ABIs by default.
- `--cipher` — `chacha20` (default) or `xor`.
- `--log` — the stub emits a logcat confirmation on the device (see §5). Omit for a
  silent stub.
- `--obfuscate` — recompile a **per-pack-unique, heavily-obfuscated (polymorphic)** arm64
  stub via O-MVLL instead of shipping the prebuilt blob (see §4a). Off by default.
- `--keystore` — auto-generated on first use (self-signed, password `sopack`). Reuse
  the same file to keep a stable signing identity across rebuilds. Defaults to
  `~/.sopack/debug.keystore`.
- `--verify` — print the signer certificate after signing.

The injector runs a **self-verification** on every library (round-trip decrypt, vaddr
stability, 16 KB congruence, correct hook target, no `TEXTREL`) and aborts with a clear
error rather than emitting a silently-broken `.so`.

### 4a. `--obfuscate` (polymorphic stub)

By default the stub is byte-identical across every packed app, so reversing it once yields
a universal offline unpacker. `--obfuscate` breaks that: it recompiles the stub per pack
through [O-MVLL](https://github.com/open-obfuscator/o-mvll) with a fresh random seed —
control-flow flattening + MBA + control-flow breaking on the decrypt/whiten logic — so every
app's stub is structurally unique and individually far more expensive to reverse. See
[`static-analysis-hardening.md`](./static-analysis-hardening.md) §Method 5 for the honest
scope and ceiling.

It is **opt-in** and needs the obfuscation toolchain at pack time (the plain build in §2 does
not). The toolchain is x86_64-only; the supported, reproducible way to get it — including
Rosetta emulation on Apple-Silicon — is the container in
[`../assets/Dockerfile`](../assets/Dockerfile):

```bash
docker build -f assets/Dockerfile/Dockerfile -t sopack .
docker run --rm -v "$PWD:/work" -w /work sopack \
    pack in.apk --lib libapp.so --abi arm64-v8a -o out.apk --obfuscate
```

To run it outside Docker, set `ANDROID_NDK_HOME`, `OMVLL_PLUGIN`, and `OMVLL_PYTHONPATH` to a
matching NDK + O-MVLL plugin (see the Dockerfile for the exact versions); `--obfuscate` fails
fast with an actionable message if they are unset. Obfuscation is applied to **arm64-v8a**
only (other ABIs get the normal stub), and packing is slower (a full stub recompile per pack).

---

## 5. Verify the output

**Static** — confirm the library is encrypted and well-formed:

```bash
# extract one lib (no unzip needed: python works too)
python3 -c "import zipfile; zipfile.ZipFile('out.apk').extract('lib/arm64-v8a/libapp.so','/tmp/chk')"

llvm-readelf -x .text /tmp/chk/lib/arm64-v8a/libapp.so | head   # bytes look random
llvm-readelf -lW      /tmp/chk/lib/arm64-v8a/libapp.so | grep LOAD   # a new R E LOAD, align 2**14
llvm-readelf -dW      /tmp/chk/lib/arm64-v8a/libapp.so | grep -E 'INIT|TEXTREL'  # DT_INIT present, no TEXTREL
apksigner verify --print-certs out.apk        # or: java -jar "$SOPACK_APKSIGNER_JAR" verify --print-certs out.apk
```

**On device** — install and watch for the decrypt confirmation and any denials:

```bash
adb install -r out.apk
adb logcat -s sopack:I
#   expect (with --log):  I sopack : native .text decrypted OK
adb logcat | grep -iE 'avc: denied|SIGSEGV|SIGILL'   # must stay empty
```

One `sopack` line appears per encrypted library that actually loads (normally just the
one for the device's ABI). No line ⇒ either you didn't pass `--log`, the device loaded
a different (unencrypted) ABI, or decryption didn't run.

---

## 6. Reminders

- **Re-signing = new signing identity.** The output can't update-install over the
  original, and in-app signature/integrity checks will see the new certificate.
  Uninstall the original first if needed.
- **Encrypt the library that holds *your* code.** For Flutter that's `libapp.so` (the
  Dart AOT snapshot). `libflutter.so` is the stock public engine — encrypting it costs
  load time and fragility while protecting nothing proprietary (the tool handles it
  correctly, it's just rarely worth it).
- **arm64 is the reference ABI** — get it green before trusting armv7 / x86_64.
- **Rebuild stubs only when you change `stub/`.** Packing itself doesn't need the
  NDK/LLVM once `sopack/stubs/*.bin` exist.
