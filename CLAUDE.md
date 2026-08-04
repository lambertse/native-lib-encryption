# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sopack` is a **black-box Android `.so` encryptor / APK repackager**. Input: an existing
APK + a list of native library names. Output: a self-signed APK in which each listed
library's `.text` is encrypted at rest and transparently decrypted at load by an injected
freestanding stub — **with no access to the library source**. It is an ELF-injection
packer (same class as Tencent Legu). Security value is obfuscation only: the key ships in
the binary (whitened, not plaintext — see below) and plaintext exists in a readable `R-X`
mapping at runtime. The stub ships identical in every packed app, so reversing it once
yields a universal offline unpacker for that version — the hardening raises the *cost* of
that one-time reverse, it does not remove the ceiling. Do not oversell it as crypto.

Read [`docs/architecture.md`](./docs/architecture.md) before making non-trivial changes —
it explains the constraints that force nearly every design decision.

## Commands

```bash
pip install -e .                            # install the CLI (pulls in LIEF)

# One entry point per cipher mode — each gets that mode to a packable state and prints the
# pack command to run next. Prefer these over the raw steps: they turn every PASS signal in
# docs/wbaes-verification.md into a hard gate, which matters because this mode's failure
# modes are mostly SILENT (see the invariants below).
./scripts/build_chacha20.sh [--api N]       # stub ciphers: build the per-ABI blobs + test
./scripts/build_wbaes.sh                    # wbaes: Phases 1-4 of docs/wbaes-verification.md
./scripts/build_wbaes.sh --host-only        #   Phases 1-3 only; no NDK/cmake/ninja needed
./scripts/build_wbaes.sh --release          #   skeleton without -DSOPK_RT_LOG tracing
# Takes WBC/NDK from the environment, else --wbc/--ndk, else prompts. SOPACK is always the
# repo the script lives in. --force redoes cached phases; --help lists everything.

# The raw stub build the chacha20 script wraps (needed after ANY change to stub/*.c/*.h).
# Uses the NDK if ANDROID_NDK_HOME/ANDROID_NDK_ROOT is set, else clang+lld+llvm-* on PATH.
# Hard-fails if the blob has any relocation, undefined symbol, or (arm64) adrp.
bash stub/build_stubs.sh [API_LEVEL]        # default API 24 -> sopack/stubs/*.bin + *.json

# Pack an APK
sopack pack in.apk --lib libfoo.so,libbar.so -o out.apk \
    [--abi arm64-v8a,...] [--cipher chacha20|xor|wbaes] [--min-sdk N] [--log] \
    [--wb-keygen PATH] [--keystore PATH --ks-alias A --ks-pass P --key-pass P] [--verify]
sopack pack in.apk --libs libs.txt -o out.apk        # or a file, one .so per line
# --cipher wbaes = white-box AES-128 KEY-WRAP mode (see "wbaes mode" below): the long-term key
# is sealed into a white-box blob and never reconstructed at runtime, so no portable key ships.
# Needs whitebox-cryptography >= 2.0.0, a HOST wb_keygen (--wb-keygen / $SOPACK_WBKEYGEN) and a
# per-ABI helper skeleton in sopack/stubs/ built from the CURRENT stub/sopk_rt.c.
# Note: section-header stripping was researched and REMOVED — modern Android bionic
# (Android 14+) requires a section table to exist and rejects a stripped lib at load
# (confirmed on-device). Whitening (below) is the load-safe hardening. See
# docs/static-analysis-hardening.md §Method 3.

# Tests
python -m pytest tests/                     # all
python -m pytest tests/test_cipher.py       # ChaCha20/XOR + the wbaes key-wrap KAT + whitening
python -m pytest tests/test_metadata.py     # decinfo layout vs decinfo.h
python -m pytest tests/test_rt_meta.py      # sopk_rt_region layout vs stub/sopk_rt.h (wbaes)
python -m pytest tests/test_wbaes.py        # real wbaes injection (skips w/o a host wb_keygen)
python -m pytest tests/test_integration.py -k init_array   # a single test by name
```

`tests/test_integration.py` builds real `.so` fixtures, injects, and `dlopen`s them — the
arm64 decrypt-and-run assertions only exercise fully on an aarch64 host.

## Architecture (the parts that span files)

Three components + a thin CLI (`sopack/cli.py`):

1. **Runtime stub** — `stub/stub.c`, compiled per ABI by `stub/build_stubs.sh` into flat,
   relocation-free blobs shipped in `sopack/stubs/`. Freestanding (raw syscalls, no
   libc/PLT/GOT/relocations). At load it: mmaps anon RW scratch → copies the encrypted
   `.text` page window → decrypts the exact `.text` sub-range → `mremap(MREMAP_FIXED)` onto
   the **original `.text` VA** → `mprotect R-X` → flushes I-cache → chains the original init.
   The key and cipher params live in the injected `sopk_decinfo` record, **whitened at rest**:
   the stub first de-whitens the 128-byte record with a keystream keyed by a checksum over
   its own code bytes (see the whitening invariant below), then proceeds. The stub
   `SOPK_FLAG_*` set is `CHAIN_INIT`, `NEED_ICACHE`, `LOG` (see `stub/decinfo.h`).

2. **ELF injection engine** — `sopack/elf_inject.py` (LIEF). Encrypts `.text`, appends the
   stub as a new R+X `PT_LOAD`, hijacks load-time init, and patches the metadata record.

3. **APK repackager** — `sopack/apk.py`. unzip → inject each matched `lib/<abi>/*.so` →
   libs written STORED + 16 KB-aligned → `apksigner` self-sign with a generated keystore.
   For `--cipher wbaes` it also **adds** the per-target helper `.so` into `lib/<abi>/`
   (STORED + 16 KB) — the only add-file path in the tool.

### `--cipher wbaes` mode (white-box AES-128 key wrapping) — the alternative to the stub

Requires **whitebox-cryptography >= 2.0.0**. Removes the "raw key ships in the binary"
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
`.text`. The cost breakdown, and why `wbc_open`'s Argon2id dominates and scales with **library
count** rather than size, is in `docs/architecture.md` §11b. Pieces:

- **Host provisioning** (`sopack/provision.py`): per target, generate a long-term key `kek`
  and seal it with a **host** `wb_keygen` (the delivered `assets/wbc/wb_keygen` is an *Android*
  build and does NOT run on the pack host — build one from the whitebox-cryptography repo
  `scripts/gen_blob.sh`; point `--wb-keygen`/`$SOPACK_WBKEYGEN` at it). Then generate a 32-byte
  session key `sk` and **compute the wrap in pure Python**:
  `wrapped = wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)`. That is byte-identical to what
  the device's `wbc_wrap_key` emits, because the white-box IS standard AES-128 and the wrap is
  plain CTR under it (`src/sdk/wbcrypto.cpp:CtrSessionKey`) — so **no new host tool is needed**
  and `wb_keygen`'s CLI is unchanged. Finally ChaCha20-encrypt `.text` with `sk`, whiten the
  passphrase off the blob, and DISCARD both keys. Only the sealed blob + wrapped key + nonce +
  whitened pass ship.
- **Helper skeleton** (`stub/sopk_rt.c` + `stub/sopk_rt.h`): the USER builds this per ABI with
  the NDK + O-MVLL, statically linking **only** `libwbcrypto.a` (it bundles libsodium since
  2.0.0; `libwbvm.a`/`libwbprovision.a` carry the provisioning surface and must NOT ship). Use
  **`clang++` with `-static-libstdc++`**, not `clang`: the archive is C++, so the C driver leaves
  the whole C++ runtime unresolved, and a *shared* libc++ would add a `DT_NEEDED` the packer
  rejects. `sopk_rt.c` itself is C, so pass it as `-x c sopk_rt.c -x none`. Add
  `-Wl,--exclude-libs,ALL` so the `wbc_*` symbols are not re-exported — `-fvisibility=hidden`
  and `-DWBC_STATIC` cannot do that, since `WBC_API` visibility is baked into the archive's
  objects — and `-Wl,--no-undefined` (see the invariant below). The exact line lives in
  `stub/sopk_rt.c`'s header comment and `docs/wbaes-verification.md` Phase 4. Drop the result at
  `sopack/stubs/sopk_rt_<abi>.so`. Its ctor finds its appended
  metadata region by **magic-scan** of its own program headers (no patched symbol),
  `dl_iterate_phdr`s the target by soname basename, de-whitens the pass, `wbc_open`s,
  `wbc_unwrap_key`s, closes the ctx (freeing the ~400 KB VM image), then ChaCha20-decrypts and
  `wbc_wipe`s the session key. `SOPK_MAX_PASS` bounds the pass.
- **Stale-skeleton guard.** The skeleton is built by hand outside this repo, and a stale one is
  SILENT: the ctor requires an exact region-version match, finds none, fails open, and the
  target runs still-encrypted `.text` → SIGILL with nothing pointing at the cause. So
  `sopk_rt.c` embeds `SOPK_RT_BUILD_MARKER_BYTES` in a retained variable and
  `_emit_helper` **refuses** a skeleton lacking it. Bump the marker on any region/flow change,
  in both `stub/sopk_rt.h` and `rt_meta.HELPER_BUILD_MARKER` (a test pins that they agree).
- **Injection** (`elf_inject.py:_inject_wbaes`): encrypt `.text`, then add the `DT_NEEDED` via
  **raw ELF surgery, NOT LIEF `add_library`** — `add_library` grows `.dynamic`/`.dynstr` and
  spills 4 KB-aligned segments on tight libs (e.g. `libapp.so`), breaking 16 KB loading.
  Instead append a 16 KB-aligned copy of `.dynstr`+soname via `add(seg)`, repoint
  `DT_STRTAB`/`DT_STRSZ`, and overwrite the `.dynamic` `DT_NULL` terminator in place with
  `DT_NEEDED` (`_add_needed_inplace`; refuses loudly if `.dynamic` has no terminator slack).
  Then emit the per-target helper (`libsopk_rt_<target>.so`) carrying the region. No stub /
  decinfo / DT_INIT surgery — so this mode also handles `INIT_ARRAY`-only libs for free.

Security ceiling is unchanged (obfuscation, not a key vault): the white-box is Chow-style AES
(academically broken by BGE-class attacks — protects against *static* analysis, not dynamic;
plaintext `.text` still exists in an R-X mapping at runtime). Key wrapping narrows it slightly
in one specific way, which upstream documents and we should not paper over: the **session** key
is an ordinary key in ordinary memory between the unwrap and the `wbc_wipe`, so a process dump
yields it without attacking the white-box at all. The *long-term* key keeps its full
protection. Do not oversell it.

**Known deferred cost:** one helper per library means one `wbc_open` per library, each ~230 ms
of Argon2id plus a transient **64 MiB** allocation (`crypto_pwhash_MEMLIMIT_INTERACTIVE`),
serialised in the loader at app startup. N libraries pay both N times. The fix is one KEK +
one blob + one helper carrying N regions; deliberately deferred until device numbers exist
(see docs/wbaes-verification.md Phase 6, which captures startup time and peak RSS).

### Invariants that will break things silently if violated

- **Cross-language contracts must stay byte-identical.** Change one side, change the
  other, and re-run the KAT/layout tests:
  - `sopack/cipher.py` ⇄ `stub/stub_cipher.h` (ChaCha20/XOR **and** the whitening
    `sopk_whiten_key` + `SOPK_WHITEN_NONCE` + `WHITEN_SPAN`).
  - `sopack/metadata.py` ⇄ `stub/decinfo.h` (the 128-byte `sopk_decinfo` struct).
  - `sopack/rt_meta.py` ⇄ `stub/sopk_rt.h` (the **96-byte** v2 `sopk_rt_region` header + tail;
    `--cipher wbaes` only). `tests/test_rt_meta.py` pins the layout, the build marker, and
    that a foreign region version is rejected. The wbaes passphrase whitening
    (`cipher.whiten_pass`) reuses the same `whiten_key`/`WHITEN_NONCE`, keyed off the sealed
    blob's first `WHITEN_SPAN` bytes. Bump `REGION_VERSION` **and** the build marker together
    when this layout changes — the on-device version gate fails *open*, so the marker is the
    only thing that turns a mismatch into a visible error.
  - `cipher.aes128_ctr` ⇄ the SDK's `wbc_wrap_key`/`wbc_unwrap_key`
    (`src/sdk/wbcrypto.cpp:CtrSessionKey`): the host builds `wrapped` itself, so the CTR
    convention (full 16-byte IV as the initial big-endian counter) must not drift. Pinned by a
    KAT captured from the real 2.0.0 `wbc_unwrap_key` in `tests/test_cipher.py`.

- **The helper skeleton must DEFINE every `wbc_*` it uses, never import one.** A `-shared`
  link permits unresolved symbols, so a skeleton built against a **1.x** `libwbcrypto.a` (no
  `wbc_wrap_key`/`wbc_unwrap_key`/`wbc_wipe`/`wbc_random`/`wbc_bulk_*`) links **cleanly** and
  leaves them as `UND` imports. bionic then cannot load the helper, so `dlopen` of the
  **target** fails too, and the app dies inside whatever was loading it — nowhere near the
  cause, and with no helper ctor to log anything. This shipped in a real APK alongside the
  dynstr bug below, either one of which was sufficient to crash it. Build the skeleton with
  `-Wl,--no-undefined` so it fails at link time, and `_emit_helper` refuses any skeleton with
  an undefined `wbc_*`/`sodium_*`. Note `DT_NEEDED` and export checks do **not** catch this —
  the leftover imports are undefined symbols, not dependencies.

- **Symbol COUNT comes from the `.dynsym` section header, strings come from `DT_STRTAB`.**
  `_LoaderView.dynsym_count()` uses `DT_HASH`'s `nchain` when present, else `.dynsym`'s
  `sh_size` — safe because sopack never moves or rewrites `.dynsym`, unlike `.dynstr`. Do
  **not** reintroduce a `DT_GNU_HASH` chain-walk fallback: GNU_HASH only covers *defined,
  exported* symbols from `symoffset` on, so it cannot see undefined imports, and when a library
  exports nothing (precisely the helper skeleton) the bucket array is empty and the walk reads
  past it — it reported 10 symbols for a 20-symbol `.so` and hid three unresolved `wbc_*`.

- **An injection must never change the target's dynamic symbol names.** `--cipher wbaes`
  supersedes `.dynstr` with an appended copy and repoints `DT_STRTAB` at it, so the copy has to
  be the table `.dynsym`'s `st_name` offsets actually index. **LIEF rebuilds `.dynstr` with the
  strings sorted during `write()` and rewrites every `st_name` to match**, so a copy taken
  *before* the write desynchronises every offset: names then resolve mid-string and `dlsym`
  returns NULL. This shipped once — Flutter got null Dart snapshot pointers and SIGSEGV'd in
  `performNativeAttach`, ~1 s after launch, with nothing pointing at the packer. Therefore:
  read the table with `_effective_strtab()` **after** `binary.write()` (never from
  `get_section(".dynstr").content`), and `_self_verify_wbaes` compares `_dynsym_names()` of
  input vs output and refuses to pack on any difference. Resolve symbols the way bionic does
  (`DT_SYMTAB`/`DT_STRTAB`/`DT_HASH` via `_LoaderView`), never via section headers — the two
  legitimately disagree in this mode. `tests/test_wbaes.py` pins it against a 2,991-symbol
  real `.so`; a fixture whose symbol order already matches alphabetical order would not
  detect the bug.

- **The `.text` cipher must stay length-preserving.** `.text` ciphertext lives in the target's
  own section bytes, so the bulk cipher has to be a stream cipher. That is why wbaes mode does
  NOT use the SDK's `wbc_bulk_seal`/`wbc_bulk_open` even though they are its documented data
  mover — the AEAD's 40 bytes of framing have nowhere to live. Full reasoning in
  `docs/architecture.md` §11c; do not "simplify" this back to the AEAD without reading it.

- **At-rest whitening of `sopk_decinfo` (anti-static-analysis).** The shipped record is
  XOR-masked with a ChaCha20 keystream whose key is a checksum (`sopk_whiten_key`, FNV-1a-64
  + splitmix64) over the `WHITEN_SPAN` (1024) stub bytes **immediately before** `g_decinfo`
  — real code/rodata the injector never rewrites. Consequences enforced by the code:
  - The constant `SOPK` magic **never appears in a packed output** (the old "grep SOPK, read
    the 128-byte struct, lift the key" attack finds nothing). `_self_verify` asserts this.
  - The injector patches decinfo at its **known blob offset** (`seg_file_off + decinfo_off`)
    and no longer scans for magic; it checks the placeholder magic is there *first*, then
    whitens. `magic`/`version` are the post-de-whiten **integrity sentinel** — a tampered
    stub de-whitens to garbage, the magic gate fails, and the stub **fails open** (chains).
  - The span is anchored on `&g_decinfo` only. Do **not** anchor on `&sopk_entry` or any
    function symbol — that emits an unresolved arm64 relocation the build guard rejects.
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
  (file-backed with a non-`DT_NULL` tag — some x86-64 no-init libs), the tool **refuses
  loudly** rather than corrupt the lib. `DT_INIT-hijack` and `DT_INIT-inplace` are the
  **only** strategies `master` emits (`_self_verify` enforces this). See
  `docs/architecture.md` §5c. *(A 3-tier chain that also handles those x86-64 cases —
  `DT_INIT-repurpose-hash` / `DT_INIT-grow-dynamic` — lives on the unmerged
  `feature/dtinit-repurpose-hash` branch, documented in
  `docs/copilot-docs/docs_x86_64-dtinit-support.md`; it is not in `master`.)*

- **The stub must never gain a relocation, undefined symbol, or (arm64) `adrp`.** It has no
  load bias: it reaches `.text` and the original init via signed byte deltas from the
  address of its own `g_decinfo` record (compiler-referenced PC-relatively). arm64 builds
  with `-mcmodel=tiny` to force `adr` (byte-relative) over `adrp` (page-relative), which is
  wrong when LIEF places the segment at a non-page-aligned vaddr. `build_stubs.sh` asserts
  all of this — do not weaken those guards.

- **`g_decinfo` is `volatile`.** The injector patches it after compilation; without
  `volatile` the compiler constant-folds `text_size==0` and deletes the whole stub.

- **W^X / SELinux: decrypt into anonymous memory, never in place.** Executing from a
  file-backed mapping the process modified is an `execmod` check (denied to apps);
  executing from anonymous memory is `execmem` (allowed). The mremap-onto-original-VA dance
  exists to land on the `execmem` path while keeping every PC-relative ref / GOT / unwind
  table valid.

- **16 KB page alignment (Android 15+).** Page size is read at runtime from auxv
  `AT_PAGESZ`, never hardcoded; the injected segment and APK libs are 16 KB-aligned. 16 KB
  page hardware is **arm64-only**, so `_self_verify` asserts per-segment 16 KB congruence
  for `arm64-v8a` output only — armeabi-v7a / x86_64 inputs commonly ship 4 KB-aligned
  LOAD segments and must not be rejected over a device class that can't run them.

## Environment note

Toolchain (NDK/LLVM, JDK, Android SDK build-tools) is **not** bundled. Per standing user
preference, **ask before installing any package or toolchain, even in auto mode.**
