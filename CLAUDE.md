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
./scripts/build_wbaes.sh --trace            #   opt into -DSOPK_RT_LOG tracing (NOT shippable:
                                            #   needs `pack --allow-helper-log`). Release,
                                            #   stripped, is the DEFAULT.
# Takes WBC/NDK from the environment, else --wbc/--ndk, else prompts. SOPACK is always the
# repo the script lives in. --force redoes cached phases; --help lists everything.

# The raw stub build the chacha20 script wraps (needed after ANY change to stub/*.c/*.h).
# Uses the NDK if ANDROID_NDK_HOME/ANDROID_NDK_ROOT is set, else clang+lld+llvm-* on PATH.
# Hard-fails if the blob has any relocation, undefined symbol, or (arm64) adrp.
bash stub/build_stubs.sh [API_LEVEL]        # default API 24 -> sopack/stubs/*.bin + *.json

# Pack an APK
sopack pack in.apk --lib libfoo.so,libbar.so -o out.apk \
    [--abi arm64-v8a,...] [--cipher chacha20|xor|wbaes] [--min-sdk N] [--log] \
    [--allow-helper-log] \
    [--wb-keygen PATH] [--keystore PATH --ks-alias A --ks-pass P --key-pass P] [--verify]
sopack pack in.apk --libs libs.txt -o out.apk        # or a file, one .so per line
# --cipher wbaes = white-box AES-128 KEY-WRAP mode (see "wbaes mode" below): the long-term key
# is sealed into a white-box blob and never reconstructed at runtime, so no portable key ships.
# Needs whitebox-cryptography >= 3.0.0, a HOST wb_keygen (--wb-keygen / $SOPACK_WBKEYGEN) and a
# per-ABI helper skeleton in sopack/stubs/ built from the CURRENT stub/sopk_rt.c.
# Note: section-header stripping was researched and REMOVED — modern Android bionic
# (Android 14+) requires a section table to exist and rejects a stripped lib at load
# (confirmed on-device). Whitening (below) is the load-safe hardening. See
# docs/static-analysis-hardening.md §Method 3.

# Tests
python -m pytest tests/                     # all
python -m pytest tests/test_cipher.py       # ChaCha20/XOR + the wbaes key-wrap KAT + whitening
python -m pytest tests/test_metadata.py     # decinfo layout vs decinfo.h
python -m pytest tests/test_rt_meta.py      # both region layouts vs stub/sopk_rt.h (wbaes)
python -m pytest tests/test_provision.py    # the blob-header gate: v>=4 + light KDF tier
python -m pytest tests/test_wbaes.py        # wbaes guards, the strip, and real injection
                                           #   (2 tests skip w/o a host wb_keygen)
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
   For `--cipher wbaes` it also **adds** files into `lib/<abi>/` (STORED + 16 KB) — the only
   add-file path in the tool: one thin helper per protected library, plus **one**
   `libsopk_wb.so` per ABI. It also seals ONE white-box key per ABI before the entry loop and
   asserts pack-level closure afterwards (every staged thin helper's provider is present) —
   a per-target verifier structurally cannot see that.

### `--cipher wbaes` mode (white-box AES-128 key wrapping) — the alternative to the stub

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
rather than size (and why the `light` KDF tier made it cheap), is in `docs/architecture.md` §11b.
Pieces:

- **Host provisioning** (`sopack/provision.py`): per target, generate a long-term key `kek`
  and seal it with a **host** `wb_keygen` at the **`light`** KDF tier (`assets/wbc/` holds only
  `libwbcrypto.a` + `wbcrypto.h`; any `wb_keygen` delivered out of band is an *Android* build and
  does NOT run on the pack host — build one from the whitebox-cryptography repo
  `scripts/gen_blob.sh`; point `--wb-keygen`/`$SOPACK_WBKEYGEN` at it). Then generate a 32-byte
  session key `sk` and **compute the wrap in pure Python**:
  `wrapped = wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)`. That is byte-identical to what
  the device's `wbc_wrap_key` emits, because the white-box IS standard AES-128 and the wrap is
  plain CTR under it (`src/sdk/wbcrypto.cpp:CtrSessionKey`) — so **no new host tool is needed**
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
    `-Wl,--exclude-libs,ALL` so the `wbc_*` symbols are not re-exported — `-fvisibility=hidden`
    and `-DWBC_STATIC` cannot do that, since `WBC_API` visibility is baked into the archive's
    objects — and `-Wl,--no-undefined`. **`-Wl,-soname,libsopk_wb.so` is load-bearing**: each thin
    helper's `DT_NEEDED` is whatever the linker recorded here, so without it lld records the file
    *path* and the APK cannot load. The packer asserts it and **never renames this artifact**.
    It has **no constructor** — all work is lazy inside `sopk_wb_k`, so there is no ordering
    question about it — and it is **stateless** (open → unwrap → close per call, no cached
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
  when the *first* target loads — a `libapp.so` that Flutter `dlopen`s later would never be
  decrypted. Keeping one thin helper per target is the only thing that makes "is my target mapped
  when my ctor runs?" answerable. Only the *provider* is shared, and it is not a trigger.

- **The helper ctor FAILS CLOSED** (unlike the stub). Every failure path calls `sopk_fail(code)`
  → records the reason in `volatile sopk_fail_code` → `abort()`. Do not "restore" fail-open here:
  the helper has no fallback (decryption is its only job), so returning leaves the target running
  encrypted `.text` and SIGILLing inside the target with nothing pointing at the cause. The stub's
  fail-open (§4c/§9b) is different — it can chain the original init and genuinely degrade.
- **Stale-skeleton guard.** The skeleton is built by hand outside this repo, and on device a stale
  one is undiagnosable: the ctor requires an exact region-version match, finds none, and aborts
  with no explanation. So `sopk_rt.c` embeds `SOPK_RT_BUILD_MARKER_BYTES` in a retained variable
  and `_emit_helper` **refuses** a skeleton lacking it. Bump the marker on any region/flow change,
  in both `stub/sopk_rt.h` and `rt_meta.HELPER_BUILD_MARKER` (a test pins that they agree). Keep
  it in an `SHF_ALLOC` section (`.rodata`) — the packer strips everything else, and its own guard
  is a byte-scan.
- **The emitted helper is STRIPPED at pack time, and a tracing helper is REFUSED.** `_emit_helper`
  removes every non-`SHF_ALLOC` section (`_strip_nonalloc`, raw surgery — LIEF regenerates
  `.symtab` on write and leaves a multi-MB hole; see docs/static-analysis-hardening.md §Method 5)
  and refuses a skeleton that imports `__android_log_print`/needs `liblog.so` unless
  `--allow-helper-log` is passed, which warns on every pack. A default build ships 2.7 MB of DWARF
  naming every function plus the host build paths; that is what let a static-analysis report
  reconstruct the whole design in an hour. **This is not the rejected §Method 3** — the section
  header table and `.shstrtab` survive, which is what bionic requires.
- **Injection** (`elf_inject.py:_inject_wbaes`): encrypt `.text`, then add the `DT_NEEDED` via
  **raw ELF surgery, NOT LIEF `add_library`** — `add_library` grows `.dynamic`/`.dynstr` and
  spills 4 KB-aligned segments on tight libs (e.g. `libapp.so`), breaking 16 KB loading.
  Instead append a 16 KB-aligned copy of `.dynstr`+soname via `add(seg)`, repoint
  `DT_STRTAB`/`DT_STRSZ`, and overwrite the `.dynamic` `DT_NULL` terminator in place with
  `DT_NEEDED` (`_add_needed_inplace`; refuses loudly if `.dynamic` has no terminator slack).
  Then emit the thin per-target helper (`libsopk_rt_<target>.so`) carrying that target's region,
  plus **one** `libsopk_wb.so` per ABI carrying the shared blob (emitted in `apk.py` after the
  entry loop, since it cannot be produced per target). No stub / decinfo / DT_INIT surgery — so
  this mode also handles `INIT_ARRAY`-only libs for free.

Only `arm64-v8a` is protected in practice, by deliberate scope choice. The other ABIs ship
cleartext `.text`, so an analyst after the *algorithm* reads the x86_64 build and never touches the
encryption. State the value accordingly: this raises device-level attack cost on arm64; it does not
keep algorithms secret.

Security ceiling is unchanged (obfuscation, not a key vault): the white-box is Chow-style AES
(academically broken by BGE-class attacks — protects against *static* analysis, not dynamic;
plaintext `.text` still exists in an R-X mapping at runtime). Key wrapping narrows it slightly
in one specific way, which upstream documents and we should not paper over: the **session** key
is an ordinary key in ordinary memory between the unwrap and the `wbc_wipe`, so a process dump
yields it without attacking the white-box at all. The *long-term* key keeps its full
protection. Do not oversell it.

**The KDF tier — why startup used to be the problem, and is not now.** One helper per library
still means one `wbc_open` per library, serialised in the loader at startup. That used to cost
~230 ms on a host / **266 ms on device** plus a transient **64 MiB** allocation, because the
seal's KDF was a compile-time Argon2id constant. Since wbcrypto 3.0.0 the KDF cost is a per-blob
tier chosen at seal time, and sopack pins **`light`** (`--kdf light` → `WBC_KDF_NONE`,
HKDF-SHA256): measured 1.1 ms, with the 64 MiB gone. Host round-trip for a 5.5 MB `.text` is now
**13.7 ms total** (open 1.1 + unwrap 0.83 + ChaCha20 11.8), so the bulk cipher dominates again.

This is **security-neutral here**, not a weakening: the whitened passphrase ships in the helper
beside the blob and its whitening key comes from that blob's own first 1024 bytes, so an attacker
with the APK has the passphrase and guesses nothing — Argon2id only ever slowed *guessing*. It is
128 bits of machine entropy, which is exactly what `WBC_KDF_NONE` presumes. The tier is inside the
seal's AEAD associated data, so a shipped blob cannot be tier-downgraded. `provision.py`'s
`assert_light_blob` refuses to pack anything but a v≥4 tier-0 blob, and the helper ctor reads the
tier back via `wbc_blob_kdf_tier` (which is also the 3.0.0 version tripwire — a pre-3.0.0 header
fails to compile, a pre-3.0.0 archive fails to link).

**What is still deferred:** `wbc_open` is not free — `Unseal` AEAD-decrypts the ~455 KB blob and
builds the VM image once per library — and each per-target helper ships ~465 KB of white-box code
plus its own ~455 KB blob, ≈920 KB duplicated N times. So the one-KEK/one-blob collapse is still
open, but the motivation is now **APK size**, not startup. Note the shape named in earlier drafts
of this file — "one helper carrying N regions" — **cannot work**: bionic runs a shared object's
constructors once, so a helper shared by N targets only decrypts the libraries mapped when the
first target loads, and a late-`dlopen`ed one (the Flutter `libapp.so` case) never gets decrypted.
The workable shape is N thin per-target helpers plus one shared white-box provider `.so`. See
`docs/architecture.md` §11b and `docs/potential-improvements.md`.

### Invariants that will break things silently if violated

- **Cross-language contracts must stay byte-identical.** Change one side, change the
  other, and re-run the KAT/layout tests:
  - `sopack/cipher.py` ⇄ `stub/stub_cipher.h` (ChaCha20/XOR **and** the whitening
    `sopk_whiten_key` + `SOPK_WHITEN_NONCE` + `WHITEN_SPAN`).
  - `sopack/metadata.py` ⇄ `stub/decinfo.h` (the 128-byte `sopk_decinfo` struct).
  - `sopack/rt_meta.py` ⇄ `stub/sopk_rt.h` (`--cipher wbaes` only): the **96-byte** v3
    `sopk_rt_region` (`'SRTT'`, in each thin helper) **and** the **24-byte** `sopk_wb_region`
    (`'SRTW'`, in the shared provider). `tests/test_rt_meta.py` pins both layouts, both build
    markers, and that a foreign region version is rejected. **The magic is the drift gate, not
    the size**: v3 kept the target header at 96 bytes and `_FMT` textually identical
    (`pass_len`/`blob_len` became `flags`/`reserved`), so a size assertion passes either way. The wbaes passphrase whitening
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
