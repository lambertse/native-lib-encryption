# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sopack` is a **black-box Android `.so` encryptor / APK repackager**. Input: an existing
APK, optionally narrowed to a list of native library names (omit it and every
`lib/<abi>/*.so` is selected). Output: a self-signed APK in which each selected
library's `.text` is encrypted at rest and transparently decrypted at load by an injected
freestanding stub - **with no access to the library source**. It is an ELF-injection
packer (same class as Tencent Legu). Security value is obfuscation only: the key ships in
the binary (whitened, not plaintext - see below) and plaintext exists in a readable `R-X`
mapping at runtime. The stub ships identical in every packed app, so reversing it once
yields a universal offline unpacker for that version - the hardening raises the *cost* of
that one-time reverse, it does not remove the ceiling. Do not oversell it as crypto.

Read [`docs/technical/ARCHITECTURE.md`](./docs/technical/ARCHITECTURE.md) before making non-trivial changes -
it explains the constraints that force nearly every design decision.

## Commands

```bash
pip install -e .                            # install the CLI (pulls in LIEF + PyYAML)

# One entry point per cipher mode - each gets that mode to a packable state and prints the
# pack command to run next. Prefer these over the raw steps: they turn every PASS signal in
# docs/technical/WBAES.md into a hard gate, which matters because this mode's failure
# modes are mostly SILENT (see the invariants below).
./scripts/build_chacha20.sh [--api N]       # stub ciphers: build the per-ABI blobs + test
./scripts/build_wbaes.sh                    # wbaes: Phases 1-4 of docs/technical/WBAES.md
./scripts/build_wbaes.sh --host-only        #   Phases 1-3 only; no NDK/cmake/ninja needed
./scripts/build_wbaes.sh --trace            #   opt into -DSOPK_RT_LOG tracing (NOT shippable:
                                            #   needs `logging.allow-helper-log: true`). Release,
                                            #   stripped, is the DEFAULT.
./scripts/build_wbaes.sh --no-omvll         #   unobfuscated Android lib; --omvll is the DEFAULT
                                            #   and now works on macOS AND Linux/x86_64 (the
                                            #   submodule pins a plugin for each). Any other
                                            #   host still needs this flag.
# WBC comes from the PINNED SUBMODULE at third_party/whitebox-cryptography, which this script
# initialises on demand - so a clean clone needs no arguments and no out-of-band drop. Override
# with --wbc/$WBC for a dev working copy (a sibling ../whitebox-cryptography is also honoured).
# It drives WBC's OWN build scripts and deposits both artifacts where sopack finds them unaided:
#   scripts/gen_blob.sh    -> build-host/wb_keygen -> copied to vendor/wbc/bin/wb_keygen
#   scripts/build_android.sh -> build-android/libwbcrypto.a -> copied to vendor/wbc/
# gen_blob.sh, NOT the similarly-named build_host.sh: upstream ships both, and only gen_blob.sh
# refuses $ZIG_BIN/$EXTRA_CXXFLAGS so no cross toolchain or O-MVLL plugin can leak into a
# PROVISIONING tool. Upstream's own header calls build-host/wb_keygen "part of the consumer
# contract" with this repo, by name. Do not switch it to build_host.sh.
# NEEDS NETWORK on the first run: WBC's third_party/fetch_deps.sh downloads libsodium (and the
# O-MVLL release) as SHA256-pinned tarballs. They are not submodules - WBC has no nested ones,
# so `git submodule update --init` takes no --recursive.
# NDK from the environment, else --ndk, else prompts. SOPACK is always the repo the script
# lives in. --force redoes cached phases; --help lists everything.

# The raw stub build the chacha20 script wraps (needed after ANY change to stub/*.c/*.h).
# Uses the NDK if ANDROID_NDK_HOME/ANDROID_NDK_ROOT is set, else clang+lld+llvm-* on PATH.
# Hard-fails if the blob has any relocation, undefined symbol, or (arm64) adrp.
bash stub/build_stubs.sh [API_LEVEL]        # default API 24 -> sopack/stubs/*.bin + *.json

# Harness scripts (see "Directory layout" below for how these four directories differ)
./scripts/device_test.sh [--only PAT]       # pack every test_apks/*.apk with wbaes, install and
                                            #   launch each on a device, and assert
                                            #   decrypted-library COUNT == injected COUNT. Builds
                                            #   --trace skeletons: its output is NOT shippable.
./scripts/artifact_generation.sh [--tar]    # build artifacts/: the portable pack bundle for
                                            #   another machine of THIS host's OS/arch (macOS or
                                            #   Linux). --skip-build bundles what is in
                                            #   sopack/stubs/ already; --allow-foreign-host drops
                                            #   bin/wb_keygen (chacha20/xor-only bundle);
                                            #   --allow-unobfuscated-provider is the explicit
                                            #   opt-out from O-MVLL. For a Linux/x86_64 bundle
                                            #   built in a container, see docker/README.md.

# Pack an APK. THE COMMAND LINE CARRIES ONLY THE INPUT AND OUTPUT APK - everything else is in
# a YAML config (sopack/config.py). This changed: every setting used to be a flag.
sopack pack in.apk -o out.apk [--config PATH]
sopack init-config [-o PATH]                # write a commented config.yaml ('-' = stdout)
# CONFIG LOOKUP: --config PATH (must exist, else error) -> ./config.yaml -> built-in defaults.
# A missing ./config.yaml is NOT an error, so a bare pack still works; the CLI prints which of
# the three it used. A ./config.yml near-miss IS an error rather than a silent fall-through.
# config.sample.yaml at the repo root is the commented reference and is byte-identical to
# config.SAMPLE_YAML (a test pins both directions). Every key in it is its DEFAULT, so an
# unedited config packs exactly like no config.
#
# The schema, and what each key replaced:
#   cipher: wbaes                     DEFAULTS TO wbaes, the white-box AES-128 KEY-WRAP mode
#                                     (see "wbaes mode" below): the long-term key is sealed into
#                                     a white-box blob and never reconstructed at runtime, so no
#                                     portable key ships. chacha20/xor are the opt-out (stub
#                                     cipher, raw key whitened in the binary). This changed:
#                                     chacha20 used to be the default, because wbaes was
#                                     unreachable from a clean clone - the WBC submodule fixed
#                                     that.
#   abis: [arm64-v8a]                 DEFAULTS TO arm64-v8a ALONE (stubs.DEFAULT_ABIS) - the only
#                                     ABI protected in practice. `abis: all` = SUPPORTED_ABIS.
#                                     This changed: it used to default to all three. Validation
#                                     lives in config.py, NOT the CLI (argparse never had
#                                     `choices` for --abi, so the move could have dropped it).
#   libraries.include:                LIBRARY SELECTION IS OPTIONAL. Absent or null -> every
#                                     lib/<abi>/*.so in the input APK, for the ABIs `abis:`
#                                     selects. Entries match through _match_lib_pattern, the
#                                     SAME matcher as libraries.exclude: bare basename, full
#                                     APK path, fnmatch glob, trailing .so optional.
#                                     An EMPTY LIST IS AN ERROR - see "Library selection" below
#                                     for why, and for why auto-select SKIPS an un-injectable
#                                     library where an explicitly named one ABORTS.
#   libraries.exclude:                fnmatch globs on the basename, trailing .so optional.
#                                     DEFAULTS to config.DEFAULT_EXCLUDES =
#                                     ("libsopk_*", "libvosWrapperEx", "libflutter") - absent
#                                     means that list, `[]` means none of it (and unlike
#                                     `include: []` that is VALID, because it can only narrow
#                                     protection, never widen the pack). The first two are ALSO
#                                     enforced in apk.build_excludes, so deleting them from a
#                                     config is a no-op; libflutter lives only here.
#                                     `libraries.default-excludes` was REMOVED - config.py
#                                     gives it a targeted message via _REMOVED_KEYS.
#   signing.sign: true                false == the old --no-sign.
#   signing.verify: true              DEFAULTS ON; false skips the post-signing apksigner dump.
#   signing.min-sdk:                  apksigner minSdkVersion override.
#   signing.keystore.{path,alias,store-pass,key-pass}
#                                     path null -> apk.DEFAULT_KEYSTORE_PATH
#                                     (~/.sopack/debug.keystore), generated on demand. ${VAR} is
#                                     expanded from the environment IN THIS BLOCK ONLY, and an
#                                     unset variable is an ERROR - never an empty password, which
#                                     apksigner would accept and ship. `$${VAR}` escapes.
#                                     Unlike the old --keystore gate, the CLI builds a
#                                     KeystoreInfo unconditionally, so an alias or password set
#                                     without a path now applies instead of being ignored.
#   logging.stub-log: false           the old --log.
#   logging.allow-helper-log: false   the old --allow-helper-log.
#   logging.file.*                    THE HOST log, unrelated to the two DEVICE keys above -
#                                     nested under `file:` precisely so the two cannot be misread
#                                     as one another. `enabled: true`, `dir:` (null ->
#                                     ~/.sopack/logs; $SOPACK_LOG_DIR OUTRANKS the config, since
#                                     the caller who needs to redirect is the tool invoking
#                                     sopack, which cannot edit the user's YAML), `level: debug`
#                                     (file only - the terminal is untouched), `max-size-mb: 50`,
#                                     `max-files: 5` (counting the live file, so backupCount is
#                                     max-files-1), `max-runs: 200`, `max-index-lines: 5000`.
#                                     All five caps go through _as_positive_int, NOT _as_int:
#                                     `max-files: 0` makes RotatingFileHandler stop rotating and
#                                     `max-runs: 0` would delete each record as it is written, so
#                                     a user setting either to "off" would get the opposite of a
#                                     bounded log. `enabled: false` is the off switch.
#
# AN UNKNOWN OR MISPLACED KEY IS AN ERROR, at every nesting level, and only the dash spelling is
# accepted. This is the guard that replaces argparse: `--ciper xor` used to fail, so `ciper: xor`
# must not quietly pack with the default cipher. Duplicate keys are rejected too (yaml.safe_load
# silently keeps the last). Removed flags get a targeted message naming their config key
# (cli._REMOVED_FLAGS) rather than argparse's bare "unrecognized arguments".
#
# SIGNING IS BEST-EFFORT. With no apksigner reachable, sopack WARNS and leaves the output
# unsigned rather than aborting - the pack itself is done by then, and a pipeline that signs with
# its own production key later still wants the artifact. `signing.sign: false` makes that explicit
# (and skips generating ~/.sopack/debug.keystore). apksigner is resolved BEFORE the keystore for
# that reason: probing the other way round generated a key pair and only then found nothing to
# sign with. RepackResult.signed carries this, verify is skipped when false, and the CLI's last
# line says the APK cannot be installed as-is. Alignment is unaffected: signing preserves it, so
# signing later is equivalent.
# THERE IS NO --wb-keygen, AND NO CONFIG KEY FOR IT EITHER. provision.find_wb_keygen probes, in
# order: vendor/wbc/bin/wb_keygen (what build_wbaes.sh installs), the portable bundle beside an
# installed venv, $SOPACK_WBKEYGEN, then PATH. Note the env var ranks BELOW the local build on
# purpose - a stale export must not beat the keygen build_wbaes.sh just gated. A config key would
# re-open "where does it rank?" against that order; the omission is deliberate, not an oversight.
# wbaes still needs whitebox-cryptography >= 3.0.0 and a per-ABI helper skeleton in
# sopack/stubs/ built from the CURRENT stub/sopk_rt.c. Both come from ./scripts/build_wbaes.sh
# or from a portable bundle; a plain `pip install .` from a checkout carries NEITHER (the
# skeletons are gitignored and not package data), so use `pip install -e .` + build_wbaes.sh,
# install a bundle, or set `cipher: chacha20`.
# Note: section-header stripping was researched and REMOVED - modern Android bionic
# (Android 14+) requires a section table to exist and rejects a stripped lib at load
# (confirmed on-device). Whitening (below) is the load-safe hardening. See
# docs/technical/HARDENING.md §Method 3.

# Tests
python -m pytest tests/                     # all
python -m pytest tests/test_cipher.py       # ChaCha20/XOR + the wbaes key-wrap KAT + whitening
python -m pytest tests/test_metadata.py     # decinfo layout vs decinfo.h
python -m pytest tests/test_rt_meta.py      # both region layouts vs stub/sopk_rt.h (wbaes)
python -m pytest tests/test_provision.py    # the blob-header gate: v>=4 + light KDF tier
python -m pytest tests/test_config.py       # the YAML config: sample, defaults, every rejection
python -m pytest tests/test_lib_select.py   # auto-select, exclusions, the CLI surface, fail-soft
python -m pytest tests/test_wbaes.py        # wbaes guards, the strip, and real injection
                                           #   (2 tests skip w/o a host wb_keygen)
python -m pytest tests/test_diag.py         # the host log: rotation, retention, redaction,
                                           #   concurrent index appends, run-id sanitisation
python -m pytest tests/test_exitcodes.py    # the exception->code map + the 8-bit subprocess check
python -m pytest tests/test_report.py       # report.json / index.jsonl shape and the schema
python -m pytest tests/test_integration.py -k init_array   # a single test by name
```

`tests/test_integration.py` builds real `.so` fixtures, injects, and `dlopen`s them - the
arm64 decrypt-and-run assertions only exercise fully on an aarch64 host.

## Directory layout (one tracked dependency + three gitignored)

They look interchangeable and are not - one is the dependency SOURCE, one is test input, one
holds build OUTPUTS of that source, one is the shippable output. Three of them were a single
`assets/` until they were split, and that name is now retired: `assets/` is a *real Android APK
directory*, so it read as "files bundled into the APK" in a tool whose whole job is unpacking
APKs. Do not merge them back, and do not reintroduce `assets/`.

- **`third_party/whitebox-cryptography/`** - the WBC dependency, a **tracked git submodule**
  pinned to a commit (`8a3c941` at time of writing) on `lambertse/whitebox-cryptography`. The
  only one of the four that is **source**, and the only one committed. It used to arrive out of
  band, which meant three scripts each guessed a different path and `MANIFEST.txt` recorded
  `wbc-rev: unknown` whenever the guess was not a readable git repo. Its *own* `third_party/`
  (libsodium, O-MVLL, a CPython stdlib) is a SHA256-pinned tarball fetch run by its
  `fetch_deps.sh`, **not** nested submodules - which is why nothing here passes `--recursive`,
  and why the first build needs network.
- **`test_apks/`** - the local APK corpus `scripts/device_test.sh` globs (`*.apk`, non-recursive).
  Pure test **input**. Nothing in `sopack/` reads it.
- **`vendor/wbc/`** - the **build outputs** of that submodule: `libwbcrypto.a` + `wbcrypto.h`,
  plus `bin/wb_keygen`. `scripts/build_wbaes.sh` refreshes all three on **every** run. Host- and
  ABI-specific, so it is generated per machine and never committed - which is exactly why
  `build_wbaes.sh` symbol-checks the archive for `wbc_blob_kdf_tier` before the copy rather than
  trusting whatever is there. `bin/wb_keygen` is the **first** thing `provision.find_wb_keygen`
  probes, and that is what removed the need for a `--wb-keygen` flag (and for a config key).
- **`artifacts/`** - the portable pack bundle, an **output** of `scripts/artifact_generation.sh`.
  Regenerate it; never edit it in place. It carries the Android artifacts (host-neutral),
  `bin/wb_keygen` (the only host-specific file), and **the tool itself** as a `py3-none-any`
  wheel with that ABI's skeletons baked in as package data - so the receiving machine clones
  nothing and needs no checkout. `install.sh` there verifies checksums, then installs the wheel
  into a venv it creates beside itself (Homebrew python is PEP 668 externally-managed, so a bare
  `pip install` of the wheel fails), then probes the result: `import sopack` must resolve inside
  that install (an old editable checkout would shadow it), the skeletons must be **reachable**,
  and LIEF must have resolved. The old marker cross-check against a receiving checkout is gone
  because wheel-and-skeletons cannot drift; the probe covers what can still fail silently.
  The wheel is built from a **staged copy** in `$TMP` with the `stubs/*.so` package-data line
  applied as an overlay - `pyproject.toml` must NOT gain it (see the `.gitignore` note above),
  or any `pip install .` would embed whatever skeleton is lying in `sopack/stubs/`, including a
  `--trace` build. Gate 7 reads the built wheel back and asserts it carries the two **gated**
  skeletons byte-for-byte and no others, because a package-data glob that silently misses
  produces a wheel that installs cleanly and only fails at pack time.
  `--tar` writes the archive **beside** the bundle, never inside it.
  A bundle is **pinned to the OS/arch that generated it** (only `bin/wb_keygen` makes it so), and
  `install.sh` refuses a mismatched host. `docker/` builds the Linux/x86_64 one.

**`docker/`** is a fifth directory and the odd one out: tracked, but not part of the tool. It is
a `linux/amd64` builder image for `artifact_generation.sh` - pinned NDK r29 (the version O-MVLL's
plugin is built against), the static-link toolchain, and the WBC deps baked in so a run is
offline. It exists because a bundle that installs on Linux must be generated on Linux. See
`docker/README.md`.

## Architecture (the parts that span files)

Three components + a thin CLI (`sopack/cli.py`) + the config layer (`sopack/config.py`, which
owns every user-facing default; `apk.repackage`'s own signature defaults are library API and are
left alone, so the long-standing `wbaes`/`chacha20` skew between the two is simply unreachable):

1. **Runtime stub** - `stub/stub.c`, compiled per ABI by `stub/build_stubs.sh` into flat,
   relocation-free blobs shipped in `sopack/stubs/`. Freestanding (raw syscalls, no
   libc/PLT/GOT/relocations). At load it: mmaps anon RW scratch → copies the encrypted
   `.text` page window → decrypts the exact `.text` sub-range → `mremap(MREMAP_FIXED)` onto
   the **original `.text` VA** → `mprotect R-X` → flushes I-cache → chains the original init.
   The key and cipher params live in the injected `sopk_decinfo` record, **whitened at rest**:
   the stub first de-whitens the 128-byte record with a keystream keyed by a checksum over
   its own code bytes (see the whitening invariant below), then proceeds. The stub
   `SOPK_FLAG_*` set is `CHAIN_INIT`, `NEED_ICACHE`, `LOG` (see `stub/decinfo.h`).

2. **ELF injection engine** - `sopack/elf_inject.py` (LIEF). Encrypts `.text`, appends the
   stub as a new R+X `PT_LOAD`, hijacks load-time init, and patches the metadata record.

3. **APK repackager** - `sopack/apk.py`. unzip → inject each **selected** `lib/<abi>/*.so` →
   libs written STORED + 16 KB-aligned → `apksigner` self-sign with a generated keystore.
   For `cipher: wbaes` it also **adds** files into `lib/<abi>/` (STORED + 16 KB) - the only
   add-file path in the tool: one thin helper per protected library, plus **one**
   `libsopk_wb.so` per ABI. It also seals ONE white-box key per ABI before the entry loop and
   asserts pack-level closure afterwards (every staged thin helper's provider is present) -
   a per-target verifier structurally cannot see that.

### Library selection (`apk.py:_classify` / `build_excludes`)

`repackage(..., wanted_libs)` takes `None` to mean **auto-select every `lib/<abi>/*.so`**, or a
list for explicit selection. `None` and `[]` are NOT interchangeable - `config.py` rejects
`libraries.include: []` rather than silently widening the scope to the whole APK (it used to be
`cli.py` rejecting an empty `--libs` file; the invariant is the same one).

- **Exclusion is checked before selection**, so `libraries.exclude` overrides a name in
  `libraries.include`.
  Patterns are fnmatch globs on the basename with an **optional `.so`** (`libflutter` matches
  `libflutter.so` but not `libflutterx.so`); full APK paths also match.
- **The exclusion list is visible DATA in the config, but two entries are enforced in code.**
  `config.DEFAULT_EXCLUDES = ("libsopk_*", "libvosWrapperEx", "libflutter")` is what every
  generated config ships, so a reader can see what is skipped without running a pack. Of those,
  `ALWAYS_EXCLUDE_PATTERNS = ("libsopk_*", "libvosWrapperEx")` is **also** prepended by
  `build_excludes` unconditionally - not overridable by naming one in `libraries.include`, and
  not removable by deleting it from a config. The two entries are there for **different**
  reasons and the old single-sentence comment was untrue of the tuple it sat above:
  - `libsopk_*` - the tool's own injected artifacts (`rt_meta.PROVIDER_SONAME` + the
    `libsopk_rt_<target>.so` thin helpers). Auto-select on an already-packed APK would otherwise
    feed the *decryptor* through `inject_so`. The `apk.py` collision guard does not cover this:
    it guards the *add-entry* path, not inject. This one is a correctness invariant.
  - `libvosWrapperEx` - the V-Key/V-OS wrapper, already self-protected, so packing it buys
    nothing and risks tripping its own integrity checks. (Added in `ac9b1e8` with **no** recorded
    rationale; this is the reconstruction, from its presence in `test_apks/vsa.apk` and its
    byte-identical passthrough in the committed `vsa-encrypted.apk`.)
- `libflutter` is **user preference, not a technical workaround**, and lives ONLY in
  `config.DEFAULT_EXCLUDES` - delete it from a config and it gets packed. Do not annotate it with
  the old `DT_INIT_ARRAY`-hijack SIGILL - that root cause is fixed (`DT_INIT-hijack`/
  `DT_INIT-inplace` are the only strategies `master` emits). `DEFAULT_EXCLUDE_PATTERNS` in
  `apk.py` and the `default-excludes` toggle are **gone**; `repackage()` no longer knows about
  libflutter at all, so a direct library call must pass it in `exclude_libs`.
- **Fail-soft is scoped to auto-select.** An `InjectError` is demoted to a skip (original entry
  written back verbatim, recorded in `RepackResult.failed`) *only* when `wanted_libs is None`; an
  explicitly named library re-raises, prefixed with the APK entry name. The rationale is
  asymmetric intent - the user vouched for a library they named, but auto-select contains
  libraries they never considered, and one stripped prebuilt must not kill the run. Zero packed
  libraries is always an error. Every cleartext library must appear in the CLI summary
  (`cli._print_summary`); silent skipping is worse than aborting.
- **The wbaes provider loop is keyed on `thin_by_abi`, not `pack_keys`.** The white-box key is
  sealed lazily *before* `inject_so`, so an ABI whose every target was skipped has a `pack_keys`
  entry and no consumer - emitting its provider would add ~936 KB of dead white-box to the APK.
- Enumeration reads only `zin.infolist()` of the **input** APK, so helpers added after the entry
  loop can never be re-selected within a run.

### `cipher: wbaes` mode (white-box AES-128 key wrapping) - the alternative to the stub

Requires **whitebox-cryptography >= 3.0.0**. Removes the "raw key ships in the binary"
weakness: the long-term AES-128 key is sealed offline into a white-box blob (diffused into
lookup tables, **never reconstructed at runtime**), so no portable key ships. Because the
white-box runtime is C++/libsodium (needs libc/dynamic linker) it **cannot** run in the
freestanding stub, so decryption moves to a normal-linkage **helper** injected as a
`DT_NEEDED` of the target; bionic runs its constructor before the target's own init, and it
decrypts `.text` in place (same mmap→decrypt→mremap-onto-VA→mprotect R-X→icache dance as the
stub, but with libc).

**The white-box never touches bulk data.** It runs at well under 1 MB/s, so a 5.5 MB
`libapp.so` took *minutes* inside a constructor; 2.0.0 deleted the bulk entry points
(`wbc_crypt_ctr`, `wbc_encrypt_ecb`) to make that shape unexpressible. Instead it wraps a
**32-byte session key** (two blocks, fixed cost) and that key drives sopack's own ChaCha20 over
`.text`. The cost breakdown, and why the per-library `wbc_open` scales with **library count**
rather than size (and why the `light` KDF tier made it cheap), is in `docs/technical/ARCHITECTURE.md` §11b.
Pieces:

- **Host provisioning** (`sopack/provision.py`): per target, generate a long-term key `kek`
  and seal it with a **host** `wb_keygen` at the **`light`** KDF tier (`./scripts/build_wbaes.sh`
  builds one via the submodule's `scripts/gen_blob.sh` and installs it at
  `vendor/wbc/bin/wb_keygen`, where `find_wb_keygen` looks first - nothing to configure. Any
  `wb_keygen` delivered out of band is an *Android* build and does NOT run on the pack host;
  `_host_incompatible_reason` detects that by file magic and skips it). Then generate a 32-byte
  session key `sk` and **compute the wrap in pure Python**:
  `wrapped = wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)`. That is byte-identical to what
  the device's `wbc_wrap_key` emits, because the white-box IS standard AES-128 and the wrap is
  plain CTR under it (`src/sdk/wbcrypto.cpp:CtrSessionKey`) - so **no new host tool is needed**
  and `wb_keygen`'s CLI is unchanged. Finally ChaCha20-encrypt `.text` with `sk`, whiten the
  passphrase off the blob, and DISCARD both keys. Only the sealed blob + wrapped key + nonce +
  whitened pass ship.
- **Two hand-built skeletons per ABI** (region v3). The USER builds both with the NDK + O-MVLL;
  `./scripts/build_wbaes.sh` does it in one step, and Phase 4 has the manual recipe.
  - `stub/sopk_wb.c` → **`libsopk_wb.so`, ONE shared white-box provider per ABI.** It links
    **only** `libwbcrypto.a` (it bundles libsodium since 2.0.0; `libwbvm.a`/`libwbprovision.a`
    carry the provisioning surface and must NOT ship), carries the single sealed blob + whitened
    passphrase, and exports exactly one symbol, `sopk_wb_k`. Use **`clang++` with
    `-static-libstdc++`**, not `clang`: the archive is C++, so the C driver leaves the whole C++
    runtime unresolved, and a *shared* libc++ would add a `DT_NEEDED` the packer rejects.
    `sopk_wb.c` itself is C, so pass it as `-x c sopk_wb.c -x none`. Add
    `-Wl,--exclude-libs,ALL` so the `wbc_*` symbols are not re-exported - `-fvisibility=hidden`
    and `-DWBC_STATIC` cannot do that, since `WBC_API` visibility is baked into the archive's
    objects - and `-Wl,--no-undefined`. **`-Wl,-soname,libsopk_wb.so` is load-bearing**: each thin
    helper's `DT_NEEDED` is whatever the linker recorded here, so without it lld records the file
    *path* and the APK cannot load. The packer asserts it and **never renames this artifact**.
    It has **no constructor** - all work is lazy inside `sopk_wb_k`, so there is no ordering
    question about it - and it is **stateless** (open → unwrap → close per call, no cached
    `wbc_ctx`, which also sidesteps `wbc_ctx` not being thread-safe).
  - `stub/sopk_rt.c` → **`sopk_rt_<abi>.so`, the THIN per-target helper.** Links **no** white-box
    at all, so it is a few KB rather than ~465 KB; it must be linked *against* the provider so
    `--no-undefined` holds and the `DT_NEEDED` string comes from the provider's `DT_SONAME`. The
    packer clones it per target, renames its `DT_SONAME`, and appends that target's region.
    Its ctor finds its own region by **magic-scan** of its own program headers (no patched
    symbol), `dl_iterate_phdr`s the target by soname basename, calls `sopk_wb_k` for its session
    key, then ChaCha20-decrypts and wipes the key.
- **Why the trigger stays 1:1 with the target.** bionic runs a shared object's constructors
  **exactly once**, so a single helper shared by N targets would only decrypt the libraries mapped
  when the *first* target loads - a `libapp.so` that Flutter `dlopen`s later would never be
  decrypted. Keeping one thin helper per target is the only thing that makes "is my target mapped
  when my ctor runs?" answerable. Only the *provider* is shared, and it is not a trigger.

- **The helper ctor FAILS CLOSED** (unlike the stub). Every failure path calls `sopk_fail(code)`
  → records the reason in `volatile sopk_fail_code` → `abort()`. Do not "restore" fail-open here:
  the helper has no fallback (decryption is its only job), so returning leaves the target running
  encrypted `.text` and SIGILLing inside the target with nothing pointing at the cause. The stub's
  fail-open (§4c/§9b) is different - it can chain the original init and genuinely degrade.
- **Stale-skeleton guard.** The skeleton is built by hand outside this repo, and on device a stale
  one is undiagnosable: the ctor requires an exact region-version match, finds none, and aborts
  with no explanation. So `sopk_rt.c` embeds `SOPK_RT_BUILD_MARKER_BYTES` in a retained variable
  and `_emit_helper` **refuses** a skeleton lacking it. Bump the marker on any region/flow change,
  in both `stub/sopk_rt.h` and `rt_meta.HELPER_BUILD_MARKER` (a test pins that they agree). Keep
  it in an `SHF_ALLOC` section (`.rodata`) - the packer strips everything else, and its own guard
  is a byte-scan.
- **The emitted helper is STRIPPED at pack time, and a tracing helper is REFUSED.** `_emit_helper`
  removes every non-`SHF_ALLOC` section (`_strip_nonalloc`, raw surgery - LIEF regenerates
  `.symtab` on write and leaves a multi-MB hole; see docs/technical/HARDENING.md §Method 5)
  and refuses a skeleton that imports `__android_log_print`/needs `liblog.so` unless
  `logging.allow-helper-log: true` is set, which warns on every pack. On the reference (pre-split, so
  provider-sized) artifact a default build ships **~2.3 MB of DWARF** inside **2,785,024 bytes
  (~2.7 MB) of total non-ALLOC sections** - naming every function plus the host build paths;
  that is what let a static-analysis report reconstruct the whole design in an hour. Quote
  whichever figure you mean with its span; they are not the same number. **This is not the
  rejected §Method 3** - the section header table and `.shstrtab` survive, which is what bionic
  requires. The same strip runs on the provider via `emit_provider`.
- **Injection** (`elf_inject.py:_inject_wbaes`): encrypt `.text`, then add the `DT_NEEDED` via
  **raw ELF surgery, NOT LIEF `add_library`** - `add_library` grows `.dynamic`/`.dynstr` and
  spills 4 KB-aligned segments on tight libs (e.g. `libapp.so`), breaking 16 KB loading.
  Instead append a 16 KB-aligned copy of `.dynstr`+soname via `add(seg)`, repoint
  `DT_STRTAB`/`DT_STRSZ`, and overwrite the `.dynamic` `DT_NULL` terminator in place with
  `DT_NEEDED` (`_add_needed_inplace`; refuses loudly if `.dynamic` has no terminator slack).
  Then emit the thin per-target helper (`libsopk_rt_<target>.so`) carrying that target's region,
  plus **one** `libsopk_wb.so` per ABI carrying the shared blob (emitted in `apk.py` after the
  entry loop, since it cannot be produced per target). No stub / decinfo / DT_INIT surgery - so
  this mode also handles `INIT_ARRAY`-only libs for free.

Only `arm64-v8a` is protected in practice, by deliberate scope choice - and since the `abis:`
default is now `stubs.DEFAULT_ABIS = ("arm64-v8a",)`, that is also what the tool does unless the
user sets `abis: all`. The other ABIs ship cleartext `.text`, so an analyst after the *algorithm*
reads the x86_64 build and never touches the encryption. State the value accordingly: this raises
device-level attack cost on arm64; it does not keep algorithms secret. The CLI's per-ABI summary
exists to keep that visible rather than letting a bare "Injected N libraries" imply full coverage.

Security ceiling is unchanged (obfuscation, not a key vault): the white-box is Chow-style AES
(academically broken by BGE-class attacks - protects against *static* analysis, not dynamic;
plaintext `.text` still exists in an R-X mapping at runtime). Key wrapping narrows it slightly
in one specific way, which upstream documents and we should not paper over: the **session** key
is an ordinary key in ordinary memory between the unwrap and the `wbc_wipe`, so a process dump
yields it without attacking the white-box at all. The *long-term* key keeps its full
protection. Do not oversell it.

**The KDF tier - why startup used to be the problem, and is not now.** One helper per library
still means one `wbc_open` per library, serialised in the loader at startup. That used to cost
~230 ms on a host / **266 ms on device** plus a transient **64 MiB** allocation, because the
seal's KDF was a compile-time Argon2id constant. Since wbcrypto 3.0.0 the KDF cost is a per-blob
tier chosen at seal time, and sopack pins **`light`** (`--kdf light` → `WBC_KDF_NONE`,
HKDF-SHA256): measured 1.1 ms, with the 64 MiB gone. Host round-trip for a 5.5 MB `.text` is now
**13.7 ms total** (open 1.1 + unwrap 0.83 + ChaCha20 11.8), so the bulk cipher dominates again.

This is **security-neutral here**, not a weakening: the whitened passphrase ships in the helper
beside the blob and its whitening key comes from that blob's own first 1024 bytes, so an attacker
with the APK has the passphrase and guesses nothing - Argon2id only ever slowed *guessing*. It is
128 bits of machine entropy, which is exactly what `WBC_KDF_NONE` presumes. The tier is inside the
seal's AEAD associated data, so a shipped blob cannot be tier-downgraded. `provision.py`'s
`assert_light_blob` refuses to pack anything but a v≥4 tier-0 blob, and the helper ctor reads the
tier back via `wbc_blob_kdf_tier` (which is also the 3.0.0 version tripwire - a pre-3.0.0 header
fails to compile, a pre-3.0.0 archive fails to link).

**What is still deferred:** `wbc_open` is not free - `Unseal` AEAD-decrypts the ~455 KB blob and
builds the VM image **once per library**, because the provider is stateless. Caching its
`wbc_ctx` is the remaining optimisation, and it is declined on purpose (it keeps the ~400 KB
table image resident and dumpable for the process lifetime, and `wbc_ctx` is not thread-safe).
The **APK-size** collapse is NOT deferred - it shipped as the v3 provider split: one KEK, one
blob and one `libsopk_wb.so` per ABI, with each extra library costing only a few-KB thin helper.
Note the shape named in earlier drafts of this file - "one helper carrying N regions" - **cannot
work**: bionic runs a shared object's constructors once, so a helper shared by N targets only
decrypts the libraries mapped when the first target loads, and a late-`dlopen`ed one (the
Flutter `libapp.so` case) never gets decrypted. That is why the *trigger* stays 1:1 with the
target and only the *provider* is shared. See `docs/technical/ARCHITECTURE.md` §11b and
`docs/technical/IMPROVEMENTS.md`.

### Diagnostics: the host log, the run record, and exit codes

Three small modules serve *callers* rather than humans, because sopack is increasingly driven by
other tools and its output used to be human-only.

- **`sopack/diag.py`** - terminal output, the rotating log, and per-run records. **It is named
  `diag`, NOT `log`, and that is load-bearing**: `apk.repackage()` has a `log: bool` parameter
  (`apk.py:218`), which would shadow a module named `log` inside that function body so
  `log.debug(...)` would resolve to a bool and raise. `repackage`'s signature is library API, so
  the module was renamed instead of the parameter. Do not "tidy" this back.
- **`sopack/exitcodes.py`** - the code constants + status slugs, one source of truth.
- **`sopack/report.py`** - `RepackResult` + `Config` → `report.json` and the `index.jsonl` line.
- **`sopack/errors.py`** - `ToolMissingError` and `InputError`, both `FileNotFoundError`
  subclasses. It imports nothing from sopack, so any layer can use it without a cycle.

**All output already funnelled through three seams, so nothing was scattered:** `cli.py`'s ~24
prints, the `logger=print` keyword `apk.repackage` already accepted (`apk.py:223`, 11 call sites -
now passed `diag.emit`, no signature change), and `elf_inject._warn`. **No new dependency**: stdlib
`logging` + `json` only, which matters because adding one is a three-file change (see §Environment).

Layout under `~/.sopack/logs/` (beside `debug.keystore`; `logging.file.dir` or `$SOPACK_LOG_DIR`):

```
sopack.log[.1-.4]   rotating firehose, all runs interleaved, pid-tagged   (max-size-mb x max-files)
index.jsonl         ONE COMPACT LINE PER RUN, append-only: the batch view
.lock               flock target for pruning / index trimming
runs/<run-id>/      report.json + run.log - the self-contained unit you attach to a bug report
```

**Why per-run records and not one `last-run.json`.** The driving use case is a *batch* - customers
pack many APKs repeatedly - so a single overwritten file would preserve one run and destroy the
other 39, and a batch is exactly where "three of these failed and I don't know which" happens. A
run's `run.log` and `report.json` are created and pruned **together**, so they cannot disagree.

**Exit code = status class ONLY; the count lives in the record.** `0` ok, `1` internal, `2` usage,
`3` config, `4` input, `5` selection, `6` nothing-encrypted, `7` toolchain, `8` inject, `9` signing,
`10` output. Three properties are deliberate and were the reason the originally-proposed encoding
(negative codes for errors, `>0` = number encrypted, `0` = nothing encrypted) was not used:

- **An exit status is 8 bits unsigned.** `sopack.cli:main` is wrapped by setuptools as
  `sys.exit(main())` and CPython masks the value, so `sys.exit(-1)` arrives as **255**. Negative
  codes cannot cross the process boundary at all. `tests/test_exitcodes.py` pins this with a real
  subprocess, because an in-process `main() == N` assertion cannot detect truncation.
- **One byte cannot carry a class and a count** - `exit 3` would mean both "config error" and "3
  libraries encrypted".
- **`0` must keep meaning success**, or the case most worth flagging (nothing protected) becomes
  the one `set -e` and every CI runner reads as fine. It is code `6` instead, and it stays a
  failure, matching the pre-existing invariant at `apk.py:397-409`.

**`2` is reserved for a malformed command line and nothing else may take it** - argparse exits 2 on
its own, so sharing it would make "you typed the command wrong" indistinguishable. The two
`SystemExit(str)` paths (`cli._reject_removed_flags`, `init-config` refusing to clobber) map here;
they previously exited **1**, reporting a stale `--cipher` - the most likely automation failure
after the flags-to-YAML move - as an *internal error*. `_Usage` splits the two halves that conflict:
the code goes to `SystemExit.__init__` (so `.code == 2`), the message is kept on the instance with
`__str__` returning it, and `main` prints it before re-raising. Both fire **before** `open_run`, so
neither leaves a run record - correct, since nothing was packed, and documented as such.

`NothingPackedError`/`SelectionError` in `apk.py` replaced three bare `RuntimeError`s; both stay
`RuntimeError` subclasses so `cli.main`'s pre-existing except-tuple and every library caller are
unaffected. The `_CODE_FOR` mapping is an **ordered tuple, not a dict**, because `SelectionError ⊂
NothingPackedError`, `ConfigError ⊂ ValueError` and `StubMissingError ⊂ FileNotFoundError` - a dict
would make precedence depend silently on insertion order.

### Invariants that will break things silently if violated

- **The terminal output must stay byte-for-byte identical, on both streams separately.** The
  console handler emits `record.getMessage()` with no level prefix and no timestamp, `INFO` to
  stdout and `WARNING`+ to stderr, mirroring the old `print()`/`print(file=sys.stderr)` split. Do
  not add a level prefix: `cli._print_summary`'s report carries meaning in its indentation. Verify
  with **separate** captures (`>out 2>err`, diffing each) - a merged `2>&1` diff can fail on
  interleaving without a real regression, or hide one.
- **Logging must never fail a pack.** Handler installation and every prune are wrapped in
  `try/except OSError`; an unwritable log directory warns once and continues console-only. A packer
  that refuses to run because it cannot open its own log file is a worse tool.
- **`diag` must work without `bootstrap()`.** `elf_inject._warn` promises its warnings cannot be
  ignored, and `elf_inject`/`apk` are importable as a library, so `_ensure_console()` installs the
  console pair lazily. It keys on **our handler type**, not on `log.handlers` being empty: pytest's
  caplog (and any embedding app) attaches handlers to this logger, and an emptiness test let a
  foreign handler silently swallow every warning. For the same reason `bootstrap`/`reset` remove
  only handlers tagged `_sopack_owned`, and `reset` restores `propagate = True` - leaving a
  module-level logger permanently non-propagating outlives our run and swallows records for
  whoever imports sopack next (in-process, that is the next test).
- **The console handler must resolve `sys.stdout`/`sys.stderr` at EMIT time** (`_StdStreamHandler`).
  A plain `StreamHandler` captures the stream once and keeps writing to it forever, so anything that
  replaces the stream afterwards - pytest's capsys, an embedder redirecting output - loses every
  message.
- **`index.jsonl` appends must be one `os.write` on an `O_APPEND` fd**, never `open(path, "a")`:
  buffered text I/O makes no promise about how many syscalls it issues, and the guarantee relied on
  is that `O_APPEND` makes seek-to-end-and-write atomic against other writers. (This is *not* a
  `PIPE_BUF` argument - that concerns pipes.) Hence the line carries **counts only**; the
  per-library arrays live in `report.json`, and a pathological field is truncated with
  `"truncated": true`.
- **Index retention is decoupled from run-directory retention, on purpose.** Run directories are
  the bulky artifact; an index line is ~300 bytes. Trimming the index down to the surviving
  directories would erase the batch history the index exists for - with "many APKs, many times",
  `max-runs` can be a single afternoon. So a pruned run **keeps** its line with `"dir": null` and
  `"detail_pruned": true`, and `max-index-lines` (5000) is deliberately far above `max-runs` (200).
  A test pins that the two defaults cannot converge.
- **Secrets are scrubbed at the single chokepoint.** `diag.redact` masks secret-looking dataclass
  fields (the keystore passwords arrive via `${VAR}` expansion, so the resolved `Config` holds
  plaintext) and `diag.scrub_argv` masks `--ks-pass pass:…`, `--ks-pass=pass:…`, `-storepass …` and
  `-keypass …`. Scrubbing lives inside `log_subprocess` rather than at each call site because a
  missed call site leaks silently and permanently into a file the user is invited to email.
  `provision._seal` elides `--key`/`--pass` itself, since neither has a prefix the pattern catches.
- **`FileNotFoundError` must never be mapped directly to an exit code.** It was doing triple duty -
  missing input APK, missing *host tool*, unwritable output path - and because it is also an
  `OSError` subclass, mapping it to `INPUT` **shadowed the `OSError → OUTPUT` entry entirely**. Two
  concrete bugs resulted: `provision.find_wb_keygen` raised a bare `FileNotFoundError`, so "could
  not find a host wb_keygen" (the first section of `docs/TROUBLESHOOTING.md`, and the most-hit
  failure on a fresh checkout) reported exit **4** while the docs promised **7**; and
  `-o /no/such/dir/out.apk` also reported 4, blaming the input. Hence `errors.ToolMissingError`
  (raised by all four tool probes: `apksigner_cmd`, `find_keytool`, `find_build_tool`,
  `find_wb_keygen`) and `errors.InputError` (raised by an explicit up-front `isfile` check in
  `_cmd_pack`), both listed **above** the generic entry. Both subclass `FileNotFoundError` on
  purpose so `repackage`'s best-effort signing path still catches a missing apksigner and demotes
  it to a warning. A bare `FileNotFoundError` now means OUTPUT.
  **The general lesson: a table that matches `code_for()` is not evidence it matches reality.**
  Codes 7-10 were table-tested and wrong; `test_exitcodes.py` now drives every documented code
  through a real code path, and `test_every_documented_code_is_reachable` fails if a code has only
  a `code_for()` assertion behind it.
- **`NothingPackedError`/`SelectionError` carry the partial `RepackResult`.** Raising discards the
  accumulated per-library skips, and those are the diagnosis - the message even ends with "see the
  per-library reasons above", i.e. terminal output, which is what the run record exists to replace.
  `cli.main` recovers it via `getattr(e, "result", None)`, so a code-6 `report.json` lists all 53
  candidates and why each was skipped instead of just `failed_count: 0`.
- **`InjectResult.entry` is filled in by `apk.py`, not `elf_inject`.** `inject_so` only ever sees a
  temp copy and cannot know the APK entry name, so the run report could not say *which* library it
  encrypted until `apk.py` stamped it (`ir.entry = name`). `failed`/`untouched` were already keyed
  on the entry, so this is also what makes the three lists line up.

- **An unknown or misplaced config key must be an ERROR, at every nesting level.** This is the
  guard that replaces argparse, and it is the failure mode the whole config design has to
  prevent: `--ciper xor` used to be an argparse error, so `ciper: xor` must not quietly pack
  with the default cipher, and a `verify: false` written at the top level instead of under
  `signing:` must not be silently ignored. A user who believes they turned something off and
  did not is worse off than one who got a typo message. `config._check_keys` validates each
  mapping against that level's key set, accepts **only** the dash spelling (taking `store_pass`
  too would mean keeping both working forever), and the strict YAML loader rejects duplicate
  keys - `yaml.safe_load` keeps the last of a repeated key and says nothing. `tests/test_config.py`
  parametrizes stale names, flattened keys, right-key-wrong-section and underscore spellings.

- **The config's exclude list is VISIBILITY; `apk.build_excludes` is the enforcement point.**
  `libsopk_*` and `libvosWrapperEx` are written into every generated config so a reader can see
  them, and prepended unconditionally by `build_excludes` so deleting them there is a no-op. Keep
  both halves: dropping the code half means a minimal hand-written config (or `exclude: []`,
  which is legal) silently packs sopack's own decryptor on a re-pack; dropping the config half
  puts the list back in hiding, which is what this design existed to end. `build_excludes`
  de-duplicates precisely because the two halves overlap by design.
  `tests/test_config.py` pins that `Config.default().libraries.exclude` stays a superset of
  `ALWAYS_EXCLUDE_PATTERNS`, so the visible list cannot drift from the enforced one.

- **`libraries.include` absent/null is not `include: []`.** Absent or null means auto-select
  every `lib/<abi>/*.so`; an empty list is an ERROR. The two are not interchangeable downstream
  (`apk.repackage` branches on `wanted_libs is None`) and the failure contracts differ: under
  auto-select an un-injectable library is skipped with a warning and ships in cleartext, while
  an explicitly named one aborts the pack. Widening the scope on an empty list would silently
  swap one for the other. YAML makes these easy to collapse in a dataclass; do not.
  `exclude: []` is the mirror image and is **valid** - it can only narrow protection back to the
  enforced minimum, never widen the pack. Absent is not `[]` there either: absent means the
  documented default list, so a config that never mentions `exclude` still skips libflutter.

- **`config.SAMPLE_YAML` is a module constant, never package data.**
  `scripts/artifact_generation.sh` stages the portable wheel with `cp "$SOPACK"/sopack/*.py`,
  so a `sopack/config.sample.yaml` would silently not reach the wheel and `sopack init-config`
  would fail on exactly the toolchain-less machine the bundle exists for. Gate 7 would not
  catch it either - its "and nothing else" clause is scoped to `sopack/stubs/*.so`. The repo-root
  `config.sample.yaml` is a pinned copy of the constant, and a test asserts both that they are
  byte-identical and that the sample parses to exactly `Config.default()`.

- **Cross-language contracts must stay byte-identical.** Change one side, change the
  other, and re-run the KAT/layout tests:
  - `sopack/cipher.py` ⇄ `stub/stub_cipher.h` (ChaCha20/XOR **and** the whitening
    `sopk_whiten_key` + `SOPK_WHITEN_NONCE` + `WHITEN_SPAN`).
  - `sopack/metadata.py` ⇄ `stub/decinfo.h` (the 128-byte `sopk_decinfo` struct).
  - `sopack/rt_meta.py` ⇄ `stub/sopk_rt.h` (`cipher: wbaes` only): the **96-byte** v3
    `sopk_rt_region` (`'SRTT'`, in each thin helper) **and** the **24-byte** `sopk_wb_region`
    (`'SRTW'`, in the shared provider). `tests/test_rt_meta.py` pins both layouts, both build
    markers, and that a foreign region version is rejected. **The magic is the drift gate, not
    the size**: v3 kept the target header at 96 bytes and `_FMT` textually identical
    (`pass_len`/`blob_len` became `flags`/`reserved`), so a size assertion passes either way. The wbaes passphrase whitening
    (`cipher.whiten_pass`) reuses the same `whiten_key`/`WHITEN_NONCE`, keyed off the sealed
    blob's first `WHITEN_SPAN` bytes. Bump `REGION_VERSION` **and** the build marker together
    when this layout changes - the on-device version gate fails *open*, so the marker is the
    only thing that turns a mismatch into a visible error.
  - `cipher.aes128_ctr` ⇄ the SDK's `wbc_wrap_key`/`wbc_unwrap_key`
    (`src/sdk/wbcrypto.cpp:CtrSessionKey`): the host builds `wrapped` itself, so the CTR
    convention (full 16-byte IV as the initial big-endian counter) must not drift. Pinned by a
    KAT captured from the real 2.0.0 `wbc_unwrap_key` in `tests/test_cipher.py`.

- **The helper skeleton must DEFINE every `wbc_*` it uses, never import one.** A `-shared`
  link permits unresolved symbols, so a skeleton built against a **1.x** `libwbcrypto.a` (no
  `wbc_wrap_key`/`wbc_unwrap_key`/`wbc_wipe`/`wbc_random`/`wbc_bulk_*`) links **cleanly** and
  leaves them as `UND` imports. bionic then cannot load the helper, so `dlopen` of the
  **target** fails too, and the app dies inside whatever was loading it - nowhere near the
  cause, and with no helper ctor to log anything. This shipped in a real APK alongside the
  dynstr bug below, either one of which was sufficient to crash it. Build the skeleton with
  `-Wl,--no-undefined` so it fails at link time, and `_emit_helper` refuses any skeleton with
  an undefined `wbc_*`/`sodium_*`. Note `DT_NEEDED` and export checks do **not** catch this -
  the leftover imports are undefined symbols, not dependencies.

- **Symbol COUNT comes from the `.dynsym` section header, strings come from `DT_STRTAB`.**
  `_LoaderView.dynsym_count()` uses `DT_HASH`'s `nchain` when present, else `.dynsym`'s
  `sh_size` - safe because sopack never moves or rewrites `.dynsym`, unlike `.dynstr`. Do
  **not** reintroduce a `DT_GNU_HASH` chain-walk fallback: GNU_HASH only covers *defined,
  exported* symbols from `symoffset` on, so it cannot see undefined imports, and when a library
  exports nothing (precisely the helper skeleton) the bucket array is empty and the walk reads
  past it - it reported 10 symbols for a 20-symbol `.so` and hid three unresolved `wbc_*`.

- **An injection must never change the target's dynamic symbol names.** `cipher: wbaes`
  supersedes `.dynstr` with an appended copy and repoints `DT_STRTAB` at it, so the copy has to
  be the table `.dynsym`'s `st_name` offsets actually index. **LIEF rebuilds `.dynstr` with the
  strings sorted during `write()` and rewrites every `st_name` to match**, so a copy taken
  *before* the write desynchronises every offset: names then resolve mid-string and `dlsym`
  returns NULL. This shipped once - Flutter got null Dart snapshot pointers and SIGSEGV'd in
  `performNativeAttach`, ~1 s after launch, with nothing pointing at the packer. Therefore:
  read the table with `_effective_strtab()` **after** `binary.write()` (never from
  `get_section(".dynstr").content`), and `_self_verify_wbaes` compares `_dynsym_names()` of
  input vs output and refuses to pack on any difference. Resolve symbols the way bionic does
  (`DT_SYMTAB`/`DT_STRTAB`/`DT_HASH` via `_LoaderView`), never via section headers - the two
  legitimately disagree in this mode. `tests/test_wbaes.py` pins it against a 2,991-symbol
  real `.so`; a fixture whose symbol order already matches alphabetical order would not
  detect the bug.

- **The `.text` cipher must stay length-preserving.** `.text` ciphertext lives in the target's
  own section bytes, so the bulk cipher has to be a stream cipher. That is why wbaes mode does
  NOT use the SDK's `wbc_bulk_seal`/`wbc_bulk_open` even though they are its documented data
  mover - the AEAD's 40 bytes of framing have nowhere to live. Full reasoning in
  `docs/technical/ARCHITECTURE.md` §11c; do not "simplify" this back to the AEAD without reading it.

- **At-rest whitening of `sopk_decinfo` (anti-static-analysis).** The shipped record is
  XOR-masked with a ChaCha20 keystream whose key is a checksum (`sopk_whiten_key`, FNV-1a-64
  + splitmix64) over the `WHITEN_SPAN` (1024) stub bytes **immediately before** `g_decinfo`
  - real code/rodata the injector never rewrites. Consequences enforced by the code:
  - The constant `SOPK` magic **never appears in a packed output** (the old "grep SOPK, read
    the 128-byte struct, lift the key" attack finds nothing). `_self_verify` asserts this.
  - The injector patches decinfo at its **known blob offset** (`seg_file_off + decinfo_off`)
    and no longer scans for magic; it checks the placeholder magic is there *first*, then
    whitens. `magic`/`version` are the post-de-whiten **integrity sentinel** - a tampered
    stub de-whitens to garbage, the magic gate fails, and the stub **fails open** (chains).
  - The span is anchored on `&g_decinfo` only. Do **not** anchor on `&sopk_entry` or any
    function symbol - that emits an unresolved arm64 relocation the build guard rejects.
  - The Python↔C whitening mirror is locked by the aarch64 `dlopen` integration test (it
    only decrypts if both sides agree); `test_metadata.py` pins the Python side via KAT.

- **Init-hijack policy (the core correctness insight).** If the library has a usable
  `DT_INIT`, repoint it to the stub and chain the original (`DT_INIT-hijack`). Otherwise
  add a `DT_INIT` **in place** (`DT_INIT-inplace`, via `_add_dtinit_inplace`): overwrite the
  `.dynamic` `DT_NULL` terminator with `DT_INIT` and rely on the following zero word as the
  new terminator (raw, class-aware ELF surgery). This keeps `.dynamic` writable and in
  place, so no mis-aligned segment is added. **Never hijack `DT_INIT_ARRAY`**: on every
  (position-independent) Android `.so` each array slot is written by an `R_*_RELATIVE`
  relocation at load, so a file overwrite is reverted by the loader and the stub never runs
  (this was the `libflutter.so` SIGILL). `DT_INIT` is not relocated and bionic runs it
  before `DT_INIT_ARRAY`. When the in-place terminator slot is genuinely unusable
  (file-backed with a non-`DT_NULL` tag - some x86-64 no-init libs), the tool **refuses
  loudly** rather than corrupt the lib. `DT_INIT-hijack` and `DT_INIT-inplace` are the
  **only** strategies `master` emits (`_self_verify` enforces this). See
  `docs/technical/ARCHITECTURE.md` §5c. *(A 3-tier chain that also handles those x86-64 cases -
  `DT_INIT-repurpose-hash` / `DT_INIT-grow-dynamic` - lives on the unmerged
  `feature/dtinit-repurpose-hash` branch (commit `0bab138`, also on `origin`), which carries
  its own updated `docs/`; it is not in `master`.)*

- **The stub must never gain a relocation, undefined symbol, or (arm64) `adrp`.** It has no
  load bias: it reaches `.text` and the original init via signed byte deltas from the
  address of its own `g_decinfo` record (compiler-referenced PC-relatively). arm64 builds
  with `-mcmodel=tiny` to force `adr` (byte-relative) over `adrp` (page-relative), which is
  wrong when LIEF places the segment at a non-page-aligned vaddr. `build_stubs.sh` asserts
  all of this - do not weaken those guards.

- **`g_decinfo` is `volatile`.** The injector patches it after compilation; without
  `volatile` the compiler constant-folds `text_size==0` and deletes the whole stub.

- **W^X / SELinux: decrypt into anonymous memory, never in place.** Executing from a
  file-backed mapping the process modified is an `execmod` check (denied to apps);
  executing from anonymous memory is `execmem` (allowed). The mremap-onto-original-VA dance
  exists to land on the `execmem` path while keeping every PC-relative ref / GOT / unwind
  table valid.

- **16 KB page alignment (Android 15+).** Page size is read at runtime from auxv
  `AT_PAGESZ`, never hardcoded; the injected segment and APK libs are 16 KB-aligned. 16 KB
  page hardware is **arm64-only**, so the congruence check should apply to `arm64-v8a` output
  only - armeabi-v7a / x86_64 inputs commonly ship 4 KB-aligned LOAD segments and must not be
  rejected over a device class that can't run them. **Only the wbaes path implements that:**
  `_assert_16k_and_no_textrel` gates on `if abi == "arm64-v8a"` and is called only from
  `_self_verify_wbaes` / `_self_verify_provider`. The stub path's `_self_verify` takes **no
  `abi` argument** and checks every `PT_LOAD` unconditionally on every ABI. Treat the gating
  as an intent the stub path does not yet implement, not as a mode difference by design - and
  check this before touching either, rather than assuming which one is right. The
  `DEFAULT_ABIS` change shrank the blast radius (non-arm64 libs are no longer packed by
  default) and auto-select's fail-soft turns a hit into a per-library skip rather than a dead
  pack, but neither is a fix - `abis: all` still runs the unconditional check.

## Environment note

Toolchain (NDK/LLVM, JDK, Android SDK build-tools) is **not** bundled. Per standing user
preference, **ask before installing any package or toolchain, even in auto mode.**

**Two hosts can GENERATE a bundle: macOS and Linux/x86_64.** This used to be macOS-only, and the
two things that were actually macOS-specific have both been fixed rather than worked around:

- `bin/wb_keygen` is the one host-specific file in a bundle. On Linux `build_wbaes.sh` links it
  **statically** (a `HOST_CXX` wrapper adding `-static -static-libstdc++ -static-libgcc`, the one
  seam `gen_blob.sh` leaves open since it refuses `EXTRA_CXXFLAGS`), so it carries no glibc floor
  and a bundle built on Debian installs on a RHEL-ish target. `artifact_generation.sh` gate 4
  **requires** this on Linux - zero `DT_NEEDED`, hard fail - which makes it a stronger check than
  the macOS `otool` allow-list, not a weaker one. Do not make it a warning: "cannot tell" is not
  "static", and the failure it prevents (`version GLIBC_2.xx not found`) surfaces at first pack on
  the machine with no toolchain.
- O-MVLL used to be macOS-only here because the submodule pinned only the Mach-O release. It now
  pins the **Linux x86_64** plugin too (`omvll_ndk_r29.so`), chosen by `omvll_plugin_path` in
  `fetch_deps.sh` - one definition, sourced by `build_android.sh`. The plugin is built against
  **NDK r29**'s clang and loads into nothing else, so the NDK and O-MVLL pins move together.

`docker/` builds the Linux bundle in a `linux/amd64` image; see `docker/README.md`. Not a
preference: Google publishes no `linux-aarch64` NDK toolchain and the O-MVLL Linux plugin is
x86_64-only, so both `build_wbaes.sh` and `build_android.sh` refuse aarch64 Linux with a message
naming the reason. Note also that **NDKs are per-host and cannot be shared**: a macOS NDK contains
only `toolchains/llvm/prebuilt/darwin-x86_64`, so bind-mounting one into a Linux container fails.

An unobfuscated provider is reachable only via an explicit `--allow-unobfuscated-provider`, never
inferred from the host or from a plugin that failed to load, and it is recorded in `MANIFEST.txt`
as `provider-obfuscation: none` so the bundle says what it is. "It built" must never quietly mean
"it built unobfuscated".

**LIEF >= 1.0 is a hard floor** (`pyproject.toml`), because LIEF - not sopack - chooses where the
appended segments land. A macOS host on LIEF `0.17.0` emitted a 4 KB-aligned LOAD injecting a
1.66 MB arm64 library, which `_assert_16k_and_no_textrel` then (correctly) refused; `1.0.0` on
Linux is verified clean on all three wbaes artifacts for that same library - version and host
both varied, so treat the version as the leading suspect, not a proven sole cause. If a 16 KB
error appears, check
`lief.__version__` before looking for a packer bug - the error prints it. Three different
artifacts reach that check (target / thin helper / shared provider) and the message names which.

**sopack has exactly two dependencies, and adding one is a three-file change.** `lief>=1.0` and
`pyyaml>=6` (`pyproject.toml`). Two build paths deliberately pre-stage them so they need no
network at run time, and both name their packages explicitly - a dependency added to
`pyproject.toml` alone breaks them:

- `docker/Dockerfile`'s system `pip3 install` layer. `docker-entrypoint.sh` creates the venv with
  `--system-site-packages` and then runs `pip install -e`, so a package missing from that layer
  sends that install to PyPI and an **offline run dies there** - after the ~2.5 GB of NDK layers.
  Prove it with `docker run --rm --network none`; without `--network none` the check silently
  passes by downloading.
- the bundle's generated `install.sh` (`scripts/artifact_generation.sh`), whose post-install probe
  imports each one by name. That probe exists because a dependency pip failed to resolve is
  otherwise invisible until the first pack, on the machine least equipped to diagnose it.
