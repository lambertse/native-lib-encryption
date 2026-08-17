# Building & running sopack

A short, practical guide: install the toolchain, build the stub blobs once, pack an
APK, and verify the result. For *why* any of this is shaped the way it is, see
[`technical/ARCHITECTURE.md`](./technical/ARCHITECTURE.md); when something breaks, see
[`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md).

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

Easiest is the per-cipher wrapper, which also runs the tests and prints the pack command:

```bash
./scripts/build_chacha20.sh              # plain LLVM on PATH, or an NDK from the environment
./scripts/build_chacha20.sh --ndk /path/to/Android/sdk/ndk/<version> --api 24
```

For `--cipher wbaes` the equivalent is `./scripts/build_wbaes.sh`, which additionally builds
the white-box artifacts and **both** per-ABI skeletons (the thin helper and the shared
provider) - see [technical/WBAES.md](./technical/WBAES.md). It needs the
whitebox-cryptography SDK and an NDK; `--host-only` runs the parts that do not.

Or drive the stub build directly:

```bash
# with the NDK:
ANDROID_NDK_HOME=/path/to/Android/sdk/ndk/<version> bash stub/build_stubs.sh 24
# or with plain LLVM on PATH (leave ANDROID_NDK_HOME unset):
bash stub/build_stubs.sh 24
# -> sopack/stubs/stub_{arm64-v8a,armeabi-v7a,x86_64}.bin
```

Either way this **rewrites tracked files** (`sopack/stubs/stub_*.bin`/`.json` are committed
package data), so expect a dirty tree afterwards.

`24` is the Android API level (any modern level is fine). The script **fails hard** if
any blob ends up with a dynamic relocation, an undefined external symbol, or (on
arm64) an `adrp` instruction - those guarantee the blob is self-contained and
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
    -o out.apk \
    --exclude-lib 'libc++_shared,libmy*' \
    --cipher chacha20 \
    --log \
    --keystore "$HOME/.sopack/debug.keystore"
```

`--cipher chacha20` is spelled out here because the **default is `wbaes`**, which needs the
per-ABI artifacts `./scripts/build_wbaes.sh` builds. `--log` is a stub-cipher option, so the
two go together. `--verify` is the default and is omitted.

- **Library selection is optional.** Omit `--lib`/`--libs` and every `lib/<abi>/*.so` in
  the APK is encrypted, for the ABIs `--abi` selects.
- `--lib` names the libraries to encrypt explicitly. It is **repeatable and/or
  comma-separated** (`--lib a.so,b.so`, `--lib a.so --lib b.so`, or a mix). A bare basename
  (`libapp.so`) matches that library in **every** selected ABI; a full path
  (`lib/arm64-v8a/libapp.so`) targets one ABI. For many libraries you can instead use
  `--libs libs.txt` (one entry per line; `#` comments allowed).
- **Failure semantics differ between the two.** A library that cannot be injected aborts
  the pack when you named it explicitly, but is **skipped with a warning** under
  auto-select (it then ships in cleartext). Either way the run prints a per-ABI summary of
  what was injected, skipped, and not selected - check it before shipping.
- `--exclude-lib` - fnmatch globs against the basename, `.so` suffix optional; repeatable
  and/or comma-separated. **Exclusion always wins**, including over an explicit `--lib`.
  Applied on top of two built-in sets: `libsopk_*` (sopack's own injected provider and thin
  helpers - **never** removable, they are what performs the decryption) and `libflutter`
  (excluded by policy; `--no-default-exclude` turns that one off).
- `--abi` - defaults to **`arm64-v8a` alone**, the only ABI protected in practice. Pass
  `--abi all` for all three, or a comma list such as `--abi arm64-v8a,x86_64`.
- `--cipher` - `wbaes` (**default**), `chacha20`, or `xor`. The latter two use the
  freestanding stub and need no build step, but ship the raw key in the binary (whitened).
  `wbaes` is white-box AES-128 key wrapping via injected helpers: it ships no portable key,
  but it has prerequisites the other modes do not - whitebox-cryptography >= 3.0.0 (the
  pinned submodule), a host `wb_keygen`, and **two** per-ABI skeletons in `sopack/stubs/`:
  the thin helper `sopk_rt_<abi>.so` **and** the shared white-box provider
  `sopk_wb_<abi>.so`. `./scripts/build_wbaes.sh` produces all of them in one command; read
  [technical/WBAES.md](./technical/WBAES.md) before using this mode.
- There is **no `--wb-keygen`**. `provision.find_wb_keygen` probes, in order:
  `vendor/wbc/bin/wb_keygen` (what `build_wbaes.sh` installs), the portable bundle beside an
  installed venv, `$SOPACK_WBKEYGEN`, then `PATH`. The env var deliberately ranks *below* the
  local build, so a stale export cannot beat the keygen the build just verified.
- `--no-verify` - skip the post-signing `apksigner` certificate dump. Verification is **on by
  default**. `--verify` still exists for explicitness; the two are last-flag-wins, so
  `--no-verify --verify` verifies.
- `--min-sdk` - minimum SDK passed through to `apksigner`.
- `--allow-helper-log` - permit packing a *tracing* wbaes skeleton (built with
  `-DSOPK_RT_LOG`). Warns on every pack; the result is **not shippable**. Only for a first
  device bring-up.
- `--log` - the stub emits a logcat confirmation on the device (see §5). Omit for a
  silent stub. (Stub ciphers only - for `wbaes` tracing, see `--allow-helper-log` above.)
- `--keystore` - auto-generated on first use (self-signed, password `sopack`). Reuse
  the same file to keep a stable signing identity across rebuilds. Defaults to
  `~/.sopack/debug.keystore`.
- `--verify` - print the signer certificate after signing.

The injector runs a **self-verification** on every library (round-trip decrypt, vaddr
stability, 16 KB congruence, correct hook target, no `TEXTREL`) and aborts with a clear
error rather than emitting a silently-broken `.so`. For `--cipher wbaes` it additionally
checks, after all libraries are done, that every thin helper's provider was emitted - a
per-library check cannot see that, and a missing provider fails on every device launch.

---

## 5. Verify the output

**Static** - confirm the library is encrypted and well-formed:

```bash
# extract one lib (no unzip needed: python works too)
python3 -c "import zipfile; zipfile.ZipFile('out.apk').extract('lib/arm64-v8a/libapp.so','/tmp/chk')"

llvm-readelf -x .text /tmp/chk/lib/arm64-v8a/libapp.so | head   # bytes look random
llvm-readelf -lW      /tmp/chk/lib/arm64-v8a/libapp.so | grep LOAD   # a new R E LOAD, align 2**14
llvm-readelf -dW      /tmp/chk/lib/arm64-v8a/libapp.so | grep -E 'INIT|TEXTREL'  # DT_INIT present, no TEXTREL
apksigner verify --print-certs out.apk        # or: java -jar "$SOPACK_APKSIGNER_JAR" verify --print-certs out.apk
```

**On device** - install and watch for the decrypt confirmation and any denials:

```bash
adb install -r out.apk
adb logcat -s sopack:I
#   expect (with --log):  I sopack : native .text decrypted OK
adb logcat | grep -iE 'avc: denied|SIGSEGV|SIGILL'   # must stay empty
```

One `sopack` line appears per encrypted library that actually loads (normally just the
one for the device's ABI). No line ⇒ either you didn't pass `--log`, the device loaded
a different (unencrypted) ABI, or decryption didn't run.

For `--cipher wbaes` the tags are different - `sopk_rt` (each thin helper) and `sopk_wb`
(the shared provider) - and a release build logs **nothing** at all; it fails closed with
an abort instead. Use `adb logcat -s sopk_rt sopk_wb DEBUG`, and see
[technical/WBAES.md](./technical/WBAES.md) Phase 6 for the full device procedure.

---

## 6. The two harness scripts

Neither is on the critical path for a single pack, and both are easy to miss.

### `scripts/device_test.sh` - the whole corpus, on a real device

Packs every APK in `test_apks/` with `--cipher wbaes`, installs and launches each one, and
reports whether the injected helper actually decrypted what the packer claims it encrypted.
The pass criterion is deliberately stricter than "no crash": a library that was packed but
whose helper constructor never ran produces **no crash and no message**, so the script
compares the number of libraries that logged a decrypt against the number `sopack pack` said
it injected, and calls a mismatch `WARN`.

```bash
./scripts/device_test.sh                        # every test_apks/*.apk
./scripts/device_test.sh --only Flappy          # just the matching ones
./scripts/device_test.sh --apks ~/other-apks    # a different corpus
./scripts/device_test.sh --dry-run              # preflight only, touch no device
```

It builds `--trace` skeletons, so the APKs it produces need `pack --allow-helper-log` and log
the target name, `.text` address and size. **They are diagnostic builds; do not ship them.**
Results land in `output/testrun/`, one directory per APK plus a `summary.md`.

### `scripts/artifact_generation.sh` - a portable bundle for a second machine

Builds `artifacts/`: everything another macOS machine needs to run `sopack pack`, and nothing
it does not. Only **one** file in it is host-specific - the stub blobs and both wbaes skeletons
are Android target ELFs and do not care which machine packed them, and sopack itself is pure
Python, while `wb_keygen` is a native host binary. That split is the whole reason a bundle is
possible, and it is why the script refuses to run anywhere but macOS unless you pass
`--allow-foreign-host` (which drops `wb_keygen` and leaves you a chacha20/xor-only bundle).

The bundle carries **the tool as well as its artifacts**: a `py3-none-any` wheel with that ABI's
skeletons baked in as package data. So the receiving machine clones nothing. The wheel is built
from a **staged copy** of the tree in `$TMP`, never from the repo, and the `stubs/*.so`
package-data line is an overlay applied only to that copy - `pyproject.toml` on `master`
deliberately does not ship `.so` as package data (`.gitignore:12-15` calls those a local
artifact), so that no ordinary `pip install .` can embed whatever skeleton happens to be sitting
in `sopack/stubs/`, including a `--trace` build. Gate 7 then reads the built wheel back and
asserts it carries the two gated skeletons byte-for-byte and no others: a package-data glob that
silently fails to match produces a wheel that installs cleanly and only fails at pack time, on
the machine with no toolchain to diagnose it.

```bash
./scripts/artifact_generation.sh --tar            # build, bundle, and archive it
./scripts/artifact_generation.sh --skip-build     # bundle what is already in sopack/stubs/
```

If you last ran `device_test.sh`, `sopack/stubs/` holds its **`--trace`** skeletons and this
script refuses them - they log the target `.text` address and size, and `sopack pack` rejects
them without `--allow-helper-log`. Both scripts write to the same paths, so the refusal is
expected, not a bug: re-run `./scripts/build_wbaes.sh` (release is the default) first, or drop
`--skip-build` and let the generator do it.

On the receiving machine:

```bash
cd /path/to/bundle && ./install.sh
./venv/bin/sopack pack app.apk --cipher wbaes -o packed.apk --verify
```

`install.sh` verifies the checksums (**before** it installs anything - the wheel is inside the
bundle), checks the host can run `bin/wb_keygen`, creates a virtualenv at `./venv`, installs the
wheel into it, and then probes the result. The venv is not tidiness: Homebrew's `python3` on
macOS is externally managed (PEP 668), so installing the wheel into it directly dies with
`error: externally-managed-environment` and a message that never mentions sopack. `--python
PATH`, `--no-venv` and `--no-keygen` are the escape hatches.

That machine needs Python >= 3.9 with `venv`, network once (pip fetches LIEF), a JDK and
`apksigner` - the generated `artifacts/README.md` lists them - but **no sopack checkout, no NDK,
no cmake/ninja and no whitebox-cryptography checkout**.

The post-install probe replaces the region-version/build-marker cross-check older bundles ran
against a receiving *checkout*. Tool and skeletons now ship in one wheel and cannot drift from
each other, so what is left to check is that the install is what actually gets imported (an old
editable checkout on that machine would shadow it), that the skeletons are **reachable** and not
merely present in the zip, and that LIEF resolved. Each of those is otherwise silent until an APK
is packed.

The bundle is an **output**. It is regenerated, never edited in place, and `artifacts/` is
gitignored along with `test_apks/` (the APK corpus) and `vendor/` (the third-party
`libwbcrypto.a` + `wbcrypto.h` that `build_wbaes.sh` copies out of your whitebox-cryptography
checkout).

---

## 7. Reminders

- **Re-signing = new signing identity.** The output can't update-install over the
  original, and in-app signature/integrity checks will see the new certificate.
  Uninstall the original first if needed.
- **Encrypt the library that holds *your* code.** For Flutter that's `libapp.so` (the
  Dart AOT snapshot). `libflutter.so` is the stock public engine - encrypting it costs
  load time and fragility while protecting nothing proprietary (the tool handles it
  correctly, it's just rarely worth it).
- **arm64 is the reference ABI** - get it green before trusting armv7 / x86_64.
- **Rebuild stubs only when you change `stub/`.** Packing itself doesn't need the
  NDK/LLVM once `sopack/stubs/*.bin` exist.
