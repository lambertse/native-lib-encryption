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
# Build the per-ABI stub blobs (needed once, and after ANY change to stub/*.c/*.h).
# Uses the NDK if ANDROID_NDK_HOME/ANDROID_NDK_ROOT is set, else clang+lld+llvm-* on PATH.
# The script hard-fails if the blob has any relocation, undefined symbol, or (arm64) adrp.
bash stub/build_stubs.sh [API_LEVEL]        # default API 24 -> sopack/stubs/*.bin + *.json

pip install -e .                            # install the CLI (pulls in LIEF)

# Pack an APK
sopack pack in.apk --lib libfoo.so,libbar.so -o out.apk \
    [--abi arm64-v8a,...] [--cipher chacha20|xor] [--min-sdk N] [--log] \
    [--keystore PATH --ks-alias A --ks-pass P --key-pass P] [--verify]
sopack pack in.apk --libs libs.txt -o out.apk        # or a file, one .so per line
# Note: section-header stripping was researched and REMOVED — modern Android bionic
# (Android 14+) requires a section table to exist and rejects a stripped lib at load
# (confirmed on-device). Whitening (below) is the load-safe hardening. See
# docs/static-analysis-hardening.md §Method 3.

# Tests
python -m pytest tests/                     # all
python -m pytest tests/test_cipher.py       # ChaCha20/XOR KAT vs stub_cipher.h
python -m pytest tests/test_metadata.py     # decinfo layout vs decinfo.h
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

### Invariants that will break things silently if violated

- **Two cross-language contracts must stay byte-identical.** Change one side, change the
  other, and re-run the KAT/layout tests:
  - `sopack/cipher.py` ⇄ `stub/stub_cipher.h` (ChaCha20/XOR **and** the whitening
    `sopk_whiten_key` + `SOPK_WHITEN_NONCE` + `WHITEN_SPAN`).
  - `sopack/metadata.py` ⇄ `stub/decinfo.h` (the 128-byte `sopk_decinfo` struct).

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
