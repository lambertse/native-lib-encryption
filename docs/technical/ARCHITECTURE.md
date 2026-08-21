# Architecture & implementation

This document explains **what sopack is, how it is built, and the reasoning behind
each design decision** - including the non-obvious constraints that dictated the shape
of the whole system and the bugs that taught us why the "obvious" approaches don't
work. If you only want to run the tool, read [`BUILDING.md`](../BUILDING.md). If
something crashes, read [`TROUBLESHOOTING.md`](../TROUBLESHOOTING.md).

---

## 1. The goal, and why it forces a "black-box packer"

sopack takes an **already-built APK**, optionally narrowed to a list of native libraries,
and produces a **self-signed APK** in which each selected `.so` has its code section
(`.text`) encrypted at rest and transparently decrypted at load time - **with no access to
the library's source**. Omitting the list selects every `lib/<abi>/*.so` in the APK; see §6
for the selection and exclusion rules.

The "no source" requirement is the whole story. If we had the source we would compile
a decryption stub *into* each library at build time (the classic model). We don't, so
we must take a finished, already-linked, position-independent `.so` and:

1. encrypt its `.text` bytes in the file, and
2. graft in a piece of code that runs **before** any of that encrypted code, decrypts
   it in memory, and then lets the library run normally.

That is an **Android packer** - the same category as commercial tools like Tencent
Legu. The techniques (encrypt `.text`, inject an executable segment, hijack the
library's init hook, decrypt at load) are established, but every step is constrained
by how modern Android actually loads and protects code. Those constraints are next.

> **Security posture, stated up front.** The decryption key ships inside the binary
> (whitened at rest - §9 - not in plaintext), and after decryption the plaintext lives in
> a readable `R-X` mapping. Anyone with Frida or a `/proc/self/maps` dump recovers
> everything. This is **anti-static-analysis obfuscation, not cryptographic protection.**
> The stub ships **byte-identical in every packed app** and contains the whole
> de-obfuscation recipe, so an analyst reverses it **once** and has a universal offline
> unpacker for that version - the hardening in §9 raises the *cost* of that one-time
> reverse (grep-and-decrypt → a real RE session); it does not remove the ceiling.
> Re-signing also gives the APK a **new signing identity** (see §6).

---

## 2. The constraints that dictate the whole design

Four hard properties of modern (API 29+) Android decide the architecture. Getting any
one wrong produces either a load failure, a SELinux denial, or an intermittent crash.

### 2a. W^X and the `execmod` vs `execmem` distinction (the central constraint)

An app targeting `targetSdk ≥ 29` runs in the `untrusted_app` SELinux domain. That
domain is granted `execmem` (make **anonymous** memory executable - this is how ART's
JIT and WebView work) but is **denied `execmod`** (re-add `PROT_EXEC` to a **modified,
file-backed** page).

This kills the textbook UPX-style approach ("`mprotect` the file-mapped `.text` to
writable, decrypt in place, `mprotect` it back to executable"). The final `mprotect`
touches a copy-on-write-dirtied, file-backed page → `avc: denied { execmod }` →
`EACCES`. So we can **never decrypt `.text` in place on its own file mapping.**

The working design: `mmap` fresh **anonymous** RW memory, decrypt into
it, flip it to `R-X` (an `execmem` check - allowed), and put those pages where the
library expects its `.text` to be. See §4 for how "put those pages where `.text` is"
is done without breaking every address in the library.

### 2b. Never map W+X simultaneously

The decrypt buffer is RW while we write plaintext, then R-X before anything executes
from it. It is never writable and executable at the same time.

### 2c. arm64 I-cache coherency

On arm64 the instruction and data caches are not coherent for freshly written code.
After decrypting we must run the Arm-architected maintenance sequence
(`DC CVAU → DSB ISH → IC IVAU → DSB ISH → ISB`) on the thread that will execute the
code, or we get non-deterministic crashes from stale I-cache lines. armv7 uses the
`cacheflush` syscall; x86_64 caches are coherent and need nothing.

### 2d. 16 KB page sizes (Android 15+)

Since Nov 2025, Play requires 64-bit apps to support 16 KB pages. Every segment we add
and every `mmap`/`mprotect`/`mremap` length must be page-aligned to the **runtime**
page size - which we read from the kernel, never hardcode. The injected executable
segment is aligned to 16 KB so the library still loads on 16 KB devices.

An input library that is itself 4 KB-aligned cannot be packed, and cannot be repaired by
the packer either - only re-linked.

Note the split of responsibility once the container is an **AAB**: the ELF-level alignment above is
unchanged and still enforced per library, but the *zip-entry* offset alignment (Step 0 in
`PAGE-ALIGNMENT.md`) is bundletool's, not sopack's - it generates the installable APKs and aligns
them itself, so sopack skips that step for a bundle rather than aligning a zip nobody maps. [`PAGE-ALIGNMENT.md`](./PAGE-ALIGNMENT.md) works that
through end to end: every mapping step from the APK entry offset to the decryptor's
`mremap` window, which of them would crash and how far from the cause, why file padding
is not a fix, and which parts of the refusal are sopack's own limitation.

---

## 3. The three components

```
sopack (CLI)
 ├─ 1. Runtime stub          C, per-ABI, freestanding → flat PIC blobs (built once)
 ├─ 2. ELF injection engine  Python + LIEF: encrypt .text, inject stub, hijack init
 └─ 3. APK repackager+signer unzip → per-.so inject → 16 KB align → apksigner
```

- **Component 1** is authored and compiled once per ABI into a flat binary blob that
  ships inside the Python package (`sopack/stubs/stub_<abi>.bin`). It is the code that
  runs on the device.
- **Component 2** is the desktop-side ELF surgery that encrypts a library and grafts
  the blob into it.
- **Component 3** wraps Component 2 in the APK unzip/rezip/align/sign pipeline.

They meet at one **128-byte binary contract**, `sopk_decinfo`, defined identically in
`stub/decinfo.h` (C) and `sopack/metadata.py` (Python). Everything the stub needs to
know at runtime lives in that record; the injector fills it in.

---

## 4. Component 1 - the runtime decryption stub

Source: `stub/stub.c`, `stub/syscalls.h`, `stub/stub_cipher.h`, `stub/stub_log.h`,
`stub/decinfo.h`, linked by `stub/stub.ld`, built by `stub/build_stubs.sh`.

### 4a. Why it is freestanding

The blob is injected into an arbitrary foreign library. It therefore **cannot have any
external symbols, PLT/GOT entries, or dynamic relocations** - there is nothing to
resolve them against, and a relocation into someone else's library would corrupt it.
So the stub:

- makes raw Linux syscalls directly (no libc) - `stub/syscalls.h` has per-ABI inline
  syscall wrappers for arm64/armv7/x86_64;
- implements its own `memcpy`, page-size probe (reads `AT_PAGESZ` from
  `/proc/self/auxv`), cipher (`stub/stub_cipher.h`), and I-cache flush;
- is linked at vaddr 0 with a tiny linker script (`stub.ld`) and `objcopy`'d to a flat
  binary, so **every symbol's value equals its byte offset in the blob**;
- is checked by the build script, which **fails the build if any dynamic relocation or
  undefined symbol survives** (`build_stubs.sh`).

### 4b. Finding `.text` at runtime without the load bias

The stub can't call `dl_iterate_phdr` or read `/proc/self/maps` cheaply, and hardcoded
addresses are impossible under ASLR. The trick: the stub carries a metadata struct
`g_decinfo` in its own segment, and the compiler references it **PC-relatively**. So at
runtime the stub knows `&g_decinfo` for free. Every target address is then expressed as
a **signed byte delta from `&g_decinfo`**, baked in by the injector:

```
runtime .text base   = &g_decinfo + delta_text
runtime original init = &g_decinfo + delta_init   (only when chaining)
```

No load bias is ever needed. This is why `decinfo.h` stores `delta_text` /
`delta_init` rather than absolute RVAs.

> **Insight that cost a debugging session (arm64):** "the compiler references
> `g_decinfo` PC-relatively" must mean **`adr` (byte-relative)**, not the default
> **`adrp`+`add` (page-relative)**. `adrp` only computes the right address when the
> segment loads at a **page-aligned** virtual address. Some LIEF versions place the
> injected segment at a non-page-aligned vaddr, and then `adrp` mis-addresses
> `g_decinfo` by the low offset → the stub reads the key/flags from the wrong place →
> garbage decrypt. Fix: build the arm64 stub with **`-mcmodel=tiny`** (emits `adr`),
> and a build-script guard rejects any `adrp` in the arm64 blob. x86_64 (RIP-relative)
> and armv7 (literal pools) are byte-relative already.

### 4c. What the stub does (the `execmem` path)

`sopk_entry()` in `stub.c`, invoked as the library's `DT_INIT`:

1. Copy the volatile `g_decinfo` fields into locals (see §4d), verify the magic.
2. Compute the page-aligned window around `.text`, `mmap` **anonymous RW** scratch.
3. `memcpy` the encrypted window in; **decrypt only the exact `.text` sub-range** (the
   partial neighbor bytes in the first/last page were never encrypted, so they're
   copied verbatim).
4. `mremap(..., MREMAP_MAYMOVE | MREMAP_FIXED, win_lo)` to move the decrypted pages
   **onto the original `.text` virtual address**. The destination becomes an anonymous
   mapping, so the later exec transition is an `execmem` check (allowed), never
   `execmod`. Crucially, keeping `.text` at its **original VA** keeps every PC-relative
   reference, GOT/PLT use, and C++ unwind table valid.
   - Fallback: if a device rejects `MREMAP_FIXED` over a file mapping, `munmap` the
     `.text` window and `mmap(MAP_FIXED)` fresh anonymous pages there, then copy the
     decrypted bytes in - same `execmem` result via a different kernel path.
5. `mprotect` the window to `R-X`, flush the I-cache (§2c), then **chain the original
   init** if one was displaced.

Failures "fail open": if a syscall fails the stub jumps to the chain/return path rather
than crashing, so a mis-encrypted library degrades instead of hard-crashing during
diagnosis. (`logging.stub-log` turns on staged `logd` diagnostics so you can see which stage ran.)

### 4d. Two subtle stub correctness requirements

- **`g_decinfo` must be `volatile`.** The injector patches its fields *after*
  compilation. If it were `const`, the compiler would constant-fold the initializer
  (`text_size == 0`) and **compile the entire stub away** (we shipped a 130-byte "stub"
  once because of this). `volatile` forces every field read to go through memory.
- **Raw syscalls return `-errno`, not `-1`.** Error checks use `sopk_is_err()` (return
  in `[-4095, -1]`), not `== MAP_FAILED`. Getting this wrong made a failed `mmap` look
  like success.

### 4e. The cipher

ChaCha20 (RFC 8439) or XOR, both length-preserving stream ciphers so encryption never
changes file size or offsets. The C implementation in `stub_cipher.h` and the Python
implementation in `cipher.py` are line-for-line mirrors, and `tests/test_cipher.py`
pins the Python side to the RFC 8439 test vector - so a green cipher test means the C
stub (same keystream) will decrypt what Python encrypted. The nonce block is
`[0:12] = nonce, [12:16] = little-endian initial counter`; the counter is 32-bit and
wraps without carrying into the nonce, on both sides.

---

## 5. Component 2 - the ELF injection engine

Source: `sopack/elf_inject.py` (plus `cipher.py`, `metadata.py`, `stubs.py`). Uses
LIEF to parse and rewrite the ELF. Per library:

### 5a. Encrypt `.text` (the section, not the segment)

We encrypt the `.text` **section** byte range, not the whole executable `PT_LOAD`
segment. The executable segment also contains `.plt`, `.init`, `.fini`, and code the
loader touches during relocation - encrypting those would corrupt things read before
the stub runs. Encrypting just `.text` is safer and sufficient. `_find_text()` locates
`.text` (or the first `PROGBITS + EXECINSTR` section) and refuses section-stripped
libraries loudly rather than guessing. A random per-library key + nonce is generated,
`.text` is stream-encrypted in place (same length, same offset).

### 5b. Inject the stub as a new R+X segment

The stub blob is appended as a fresh `PT_LOAD` segment with flags `R+X` and 16 KB
alignment via LIEF's segment API (`binary.add(seg)`). LIEF inserts the program header
and re-bases existing content, updating vaddrs/relocations/dynamic entries
consistently.

> **Insight:** LIEF's `add()` **shifts `.text`'s vaddr** (it inserts a program header
> and pushes content down by a page). So `text_rva` must be read **after** `add()`,
> not before, or `delta_text` points a page off. This is subtle because the file
> offset changes too; the injector re-reads the final vaddr post-`add()`.

### 5c. Hijack load-time execution (the part that was hardest to get right)

The stub must run **before any encrypted code**. bionic's
`soinfo::call_constructors()` runs, in order: `DT_INIT`, then `DT_INIT_ARRAY`. Our
policy:

- **Library has a usable `DT_INIT`** → repoint it to the stub and chain the original
  (`strategy = DT_INIT-hijack`, `FLAG_CHAIN_INIT` set, `delta_init` records the
  original). `DT_INIT` lives in `.dynamic` and is **not** relocated, so repointing it
  is stable.
- **No usable `DT_INIT`** (whether or not the library has a `DT_INIT_ARRAY`) → **add a
  `DT_INIT` in place** (`strategy = DT_INIT-inplace`). Because `DT_INIT` runs before
  `DT_INIT_ARRAY`, the stub decrypts `.text` first and the library's own constructors
  then run on decrypted code. No chaining is needed - we displaced nothing.

**Why we never hijack `DT_INIT_ARRAY`.** This is the lesson from the libflutter.so
crash. On position-independent libraries (every Android `.so`) each `INIT_ARRAY` slot
is populated by an `R_*_RELATIVE` relocation **at load time** - the file slot reads `0`
(RELA/arm64, x86_64) or holds the addend (REL/armv7). If we overwrite the file slot
with the stub pointer, the loader applies the relocation and **silently reverts our
write** to the original constructor address. The stub never runs, `.text` stays
encrypted, and the original constructor executes ciphertext → `SIGILL` inside
`call_array`. Adding a `DT_INIT` sidesteps the entire relocation problem. This is a
general correctness fix: "`INIT_ARRAY` but no `DT_INIT`" is the shape of libflutter.so
and **most** NDK-built C++ libraries.

**How "add a `DT_INIT` in place" works without breaking 16 KB loading.** The naive way
- ask LIEF to add a dynamic entry - grows `.dynamic`, which makes LIEF spill it into a
new 4 KB-aligned segment that breaks 16 KB loading; and repointing `PT_DYNAMIC` into a
different segment makes bionic/glibc reject the library. Instead
`_add_dtinit_inplace()` does raw, class-aware (ELF32/ELF64) surgery: it **overwrites
the existing `DT_NULL` terminator with `DT_INIT`** and relies on the following word
being a `DT_NULL` at runtime as the new terminator. `.dynamic` stays writable and in
place; only the 16 KB stub segment is added.

> **Insight (no-init layout):** whether the slot after the terminator reads as
> `DT_NULL` at runtime is decided by the containing `PT_LOAD`'s `filesz`/`memsz`
> (bytes beyond `filesz` are kernel zero-filled), **not** by the file bytes there - a
> non-`SHF_ALLOC` section like `.shstrtab` sitting after `.dynamic` in the file is not
> loaded. And bionic stops at the first entry whose **`d_tag` word** is zero and
> ignores its `d_val`, so a follow-slot with `tag=0` but a non-zero value (seen on
> armv7 libflutter) is a valid terminator. `_add_dtinit_inplace()` checks exactly these
> runtime conditions and refuses loudly when they don't hold.

### 5d. Patch the metadata and self-verify

The injector writes the finalized `sopk_decinfo` (deltas, key, nonce, sizes, flags) at
its **known blob offset** (`seg_file_off + decinfo_off`) - after asserting the placeholder
magic is there - then **whitens** it in place (§9b). It then runs `_self_verify()`, which
re-parses the output and asserts **every invariant the runtime depends on** before the tool
emits a file:

- round-trip: decrypting the output `.text` reproduces the original plaintext;
- whitening round-trip: de-whitening the shipped 128 bytes reproduces the packed record,
  and the `SOPK` magic needle appears **nowhere** in the output;
- `.text` vaddr is unchanged (so `delta_text` is valid);
- every `PT_LOAD` is 16 KB congruent, and the injected segment is `R+X`;
- no `DT_TEXTREL`;
- **loader-aware hook check:** the strategy is a `DT_INIT-*` one and `DT_INIT` actually
  points at the stub entry - i.e. what the loader will call *first*, not a file-slot
  value a relocation would overwrite.

That last check is the one that would have caught the libflutter crash at pack time
instead of on the device; it is deliberately loader-aware now.

---

## 6. Component 3 - APK / AAB repackage and self-sign

Source: `sopack/apk.py`, driven by `sopack/cli.py`, with the format differences isolated in
`sopack/container.py`.

**The input may be an APK or an Android App Bundle, and the format is detected from the
file, not declared** - a root `BundleConfig.pb` means AAB, a root `AndroidManifest.xml`
means APK, and neither is an input error. There is no flag and no config key for it. Only
five things differ, all read off the `Container` descriptor: the entry pattern, where added
artifacts go, whether an injected library is written uncompressed, whether the zip is
16 KB-aligned, and whether sopack signs at all. Steps 2-4 below are therefore the **APK**
path; §6a says what a bundle does instead.

1. Unzip the container; for each **selected** `lib/<abi>/<name>.so` (an APK) or
   `<module>/lib/<abi>/<name>.so` (a bundle), run Component 2. Selection
   is either the explicit `libraries.include` list (by full path, module-relative path, or
   bare basename → all ABIs) or, when that list is omitted, **every** matching entry.
   Exclusion patterns (`libraries.exclude`, which ships listing `libsopk_*`,
   `libvosWrapperEx` and `libflutter`) are checked *before* selection, so they override a
   name in `libraries.include` too. The first two are **also** prepended unconditionally by
   `build_excludes`, so deleting them from a config is a no-op: those are sopack's own
   injected provider and thin helpers, and auto-select on an already-packed APK would
   otherwise encrypt the decryptor.
   Enumeration reads only the **input** zip's entry list, so helpers added later in the
   same run can never be fed back through Component 2.
   Under auto-select an `InjectError` on one library is demoted to a **skip** (the original
   entry is written back verbatim and reported); an explicitly named library still aborts
   the pack. Zero packed libraries is always an error.
2. Write the injected `.so` back **STORED (uncompressed)** so it stays page-mappable;
   drop the old `META-INF` signature.
3. **16 KB-align**: `zipalign -P 16` if a runnable one is found, else a **built-in
   Python aligner** (needed on hosts without an arch-matching `zipalign`, e.g. aarch64)
   that pads each STORED entry's local-header extra field so `.so` data starts on a
   16 KB boundary.
4. **Self-sign** (v2/v3) with `apksigner` using a generated keystore (auto-created on
   first use). `apksigner` can be run as a jar via `SOPACK_APKSIGNER_JAR`, so it works
   on any architecture through the JDK.

> **Consequence to communicate:** re-signing replaces the certificate, so the output is
> effectively a **new app**. It cannot update-install over the original, and any in-app
> signature-pinning / integrity check (common in banking/security apps) will see the
> new cert and may refuse to run - independent of whether the encryption itself
> succeeded.

### 6a. What an AAB does instead of steps 2-4

Nothing about Component 1 or 2 changes - those operate on a `.so`, which does not care what
zip it travelled in, and the ELF's own 16 KB `p_align` checks, `_self_verify_wbaes` and the
`.dynsym`-name guard all still run per library. What changes is the container work:

2'. The injected `.so` keeps the **compression it arrived with** (every `.so` in a real
    bundle is DEFLATED). The old `META-INF/*.{SF,RSA,MF}` is still dropped.
3'. **No alignment.** A bundle is never installed. bundletool reads it and *generates* the
    split APKs, choosing their compression and page alignment from `BundleConfig.pb`'s
    `optimizations.uncompress_native_libraries` - so entry offsets inside the bundle are
    discarded before any device sees them, and forcing STORED would only inflate the
    artifact (a real bundle's libraries are ~100 MB uncompressed). sopack deliberately
    neither reads nor rewrites that setting: it moves together with `extractNativeLibs`,
    so there is no combination in which skipping this breaks loading.
4'. **No signing.** `apksigner` cannot even parse a bundle (`ApkFormatException: Missing
    AndroidManifest.xml` - the manifest is at `<module>/manifest/` in protobuf form), a
    bundle is JAR-signed, and the signature Play verifies is the app's **upload key**.
    sopack has no business holding that, so the output is unsigned **by design**,
    `RepackResult.signed` is `False`, and the CLI points at `jarsigner`. The old signature
    is still stripped because `MANIFEST.MF` digests every entry: a signature that can no
    longer verify is harder to diagnose than none.

Added artifacts land in the **target's own module** directory, and for `cipher: wbaes` the
shared provider is emitted once per `(module, abi)` while the white-box key is sealed once
per **ABI**. That asymmetry is required, not incidental: bionic resolves a `DT_NEEDED`
soname once per process, so every copy of `libsopk_wb.so` for an ABI must carry the same
sealed blob, or a thin helper from one module unwraps against another's and aborts.

Measured on a real 155 MB, 1456-entry bundle (`test_apks/vsa.aab`, `cipher: wbaes`,
`abis: [arm64-v8a]`): 12 s, 23 libraries injected, 1 skipped by the `.dynsym` guard
(the same library the APK of the same app also refuses), 24 entries added, the 3 old
signature entries removed, and all 1430 other entries byte-identical.

---

## 7. How it was built and validated

The build followed the staged plan from the original design brief - prove the riskiest
runtime assumption first, then build outward - so that a failure at any stage was
cheap to localize:

1. **Runtime path first.** Before any ELF surgery, validate the `mmap → decrypt →
   mremap-onto-base → mprotect → cache-flush` sequence in isolation, because the
   `mremap` over a file-backed `.text` mapping is the least-tested corner.
2. **Stub blobs.** Author the freestanding per-ABI stub; the build script enforces the
   "no relocations / no external symbols" property mechanically.
3. **Injection engine.** LIEF encrypt + segment add + init hijack + metadata patch, with
   `_self_verify()` turning silent breakage into hard errors.
4. **APK pipeline.** unzip → inject → 16 KB align → sign, on real APKs.

The whole pipeline was exercised on an aarch64 Linux container using only user-space
tooling (Miniforge Python + LIEF, conda LLVM for the stubs, conda OpenJDK +
`apksigner.jar` for signing) - no NDK and no root required, because the stub is
freestanding and `apksigner` is pure Java. On that host, injected libraries were
`dlopen`'d and shown to decrypt their `.text` at load and run correctly (ChaCha20 and
XOR, with `.rodata` references intact), across arm64 with additional armv7/x86_64
smoke tests under qemu-user. Real Flutter libraries (`libapp.so`, `libflutter.so`) were
packed and verified end-to-end.

**What still requires your hardware:** the on-device Android SELinux `execmem`
behavior. The container validates everything except Android's SELinux policy; a real
device (watch `adb logcat` for `avc` denials and the optional `sopack` decrypt line)
is the final confirmation. Also note: the aarch64 `dlopen` test cross-checks the
Python↔C whitening mirror (§9b) only for **arm64**; the armv7/x86_64 whitening is locked
only by the Python-side KAT (identical integer arithmetic, so low risk, but never run
against the C stub) - confirm those ABIs on device or under qemu-user.

---

## 8. Boundaries and limitations

- **Obfuscation only.** The key ships in the binary (whitened - §9); plaintext is readable
  at runtime.
- **New signing identity.** No update-install over the original; signature-pinned apps
  will notice.
- **Decrypt happens at `DT_INIT`**, i.e. after relocation but before `DT_INIT_ARRAY`.
  Code invoked *before* `DT_INIT` (IFUNC resolvers, `DT_PREINIT_ARRAY`) cannot be
  protected by this approach - not usually a problem, but it's the boundary.
- **Per-library fragility.** Section-stripped libraries or exotic init code are refused
  loudly rather than silently corrupted. LIEF-rebuilt ELFs occasionally trip strict
  loaders, so a real `dlopen`/on-device check is always warranted.
- **Encrypting stock engine libraries is usually not worth it.** `libflutter.so`, for
  example, is the public, byte-identical Flutter engine - encrypting it protects
  nothing proprietary while adding load-time cost and fragility. Encrypt the library
  that holds *your* code (e.g. Flutter's `libapp.so`, the Dart AOT snapshot).

---

## 9. Anti-static-analysis hardening

The default posture is obfuscation (§1). Three measures raise the bar for a **static**
analyst - someone reading the APK without running it - while keeping the freestanding /
prebuilt-blob / 128-byte-contract architecture intact.

### 9a. Why the old layout was trivial to defeat

The v1 record was a fixed 128-byte `sopk_decinfo` beginning with the constant magic
`SOPK` (`0x4B504F53`). Extraction was: grep the file for the magic, read the struct at
that offset, lift `key[32]` / `nonce[16]` / `cipher_id`, and - from `delta_text` /
`text_size` - learn exactly where `.text` is and how big. A ~10-line offline script then
decrypts `.text` without ever running the app. The magic and the plaintext key were two
crown-jewel signposts.

### 9b. Whitening the metadata record (the primary measure)

The 128-byte contract is unchanged; only its **at-rest representation** changes. The whole
record is XOR-masked with a ChaCha20 keystream whose **key is a checksum the stub computes
over its own code bytes** at load. No new secret is stored anywhere - the derivation lives
in the (freestanding) stub.

- **Span.** `sopk_whiten_key` (FNV-1a-64 folded through splitmix64 to 32 bytes, so every key
  byte depends on every span byte) runs over the `SOPK_WHITEN_SPAN` (1024) bytes immediately
  **before** `g_decinfo` - real code/rodata the injector never rewrites. The span is
  anchored on `&g_decinfo` alone; anchoring on a function symbol (`&sopk_entry`) emits an
  unresolved arm64 relocation that the build guard rejects. Mirrored in `sopack/cipher.py` ⇄
  `stub/stub_cipher.h`; the fixed nonce is `SOPK_WHITEN_NONCE`.
- **Pack time** (`elf_inject.py`): patch decinfo at its **known** blob offset
  (`seg_file_off + decinfo_off`, the value `_self_verify` already trusts) - the magic scan
  is gone - then `whiten()` the 128 bytes in place. `_self_verify` de-whitens the shipped
  bytes back to the packed record and asserts the magic needle appears **nowhere** in the
  output.
- **Load time** (`stub.c`): copy the volatile record to a local, `sopk_whiten_key` over the
  span, `sopk_chacha20_apply` to de-whiten, then the existing `magic == SOPK && text_size != 0`
  gate runs on the de-whitened locals. **The magic/version are a post-de-whiten sentinel** -
  present only after a correct derivation, never in the file. A tampered stub checksums
  differently → garbage de-whiten → magic mismatch → **fail open** (chain the original init),
  the same safe degradation as an unpatched blob. (Anti-tamper is a free side effect, not the
  goal - a dynamic analyst never patches the stub, they dump decrypted `.text` from memory.)

What this buys: the grep-magic-read-key attack finds nothing; recovering the key now
requires reproducing the checksum-and-keystream derivation, i.e. reversing the stub.

### 9c. Section-header stripping - researched, rejected on Android 14+, removed

Whitening hides the key but **not** where `.text` is - the ELF **section header** still
gives its name, offset and size, so a pass to detach the section table was implemented and
tested. **Two on-device tests (Android 16 / target_sdk 36) killed it:** (1) zeroing
`e_shoff`/`e_shnum`/`e_shstrndx` → `linker: "...libapp.so" has invalid e_shstrndx`; (2) after
keeping `e_shstrndx` and zeroing only `e_shoff`/`e_shnum` → `linker: "...has no section
headers"` (bionic `ReadSectionHeaders` rejects `e_shnum == 0`). Both → lib never loads →
Flutter `SIGSEGV`. glibc `dlopen` on the host passed both, so host tests can't catch this.
**Conclusion:** bionic (Android 14+) requires a section header table to exist; detaching it
is not viable, so the feature was **removed**. It was also marginal: once whitening holds,
`.text`'s location (derivable from the un-strippable program headers + `PT_DYNAMIC`/`.dynsym`)
gives an analyst nothing. See [`HARDENING.md`](./HARDENING.md)
§Method 3.

### 9d. String hygiene

The logcat **tag** `"sopack"` is the one constant that would name the packer in a `strings`
dump (which scans raw bytes, section table or not). It is stored XOR-obfuscated in
`stub_log.h` and decoded on-stack, so the name never appears in a packed lib. The staged
The staged debug labels (`A:entry`, …) remain in cleartext - they are generic markers, only
emitted under `logging.stub-log`, and not a reliable packer fingerprint; fuller message obfuscation is
a straightforward extension of the same helper.

### 9e. The ceiling, and two ways to break it (not the default)

Everything above lives in the "prebuilt blob + clean architecture" envelope, which shares
one hard limit: the stub is identical across every packed app and holds the *complete*
recipe, so **reverse it once, unpack every app** at that version. Two options break that
ceiling but leave the clean envelope:

- **Polymorphic per-pack stub.** Compile a *different* stub per pack (randomized whitening
  constants / checksum seed, instruction scheduling, junk / opaque predicates) so reversing
  one app does not crack the others. This is the only in-binary way to break the ceiling.
  **Cost:** needs the `build_stubs.sh` toolchain (clang+lld+llvm) **at pack time**, not just
  the shipped blob - it breaks the prebuilt-blob model, slows packs, and must re-run the
  no-reloc/no-`adrp` guards per pack. (Per-pack *data* randomization - a random whitening
  salt, junk in `reserved` - is cheap but does **not** break the ceiling; the logic is still
  identical across apps.)
- **External / server-derived key.** Keep the key out of the `.so`: store a `key_id` + salt,
  have the app derive the key (PBKDF2 from a **server** secret or user credential) and write
  it to `/data/user/<userId>/<pkg>/files/.sopk_<key_id>` before `System.loadLibrary`; the
  stub reads it via raw `openat`/`read` and fails open if absent. **Static resistance is real
  only if the secret is out-of-band** (server/user) - an embedded secret is still in the
  APK's dex, so no gain. **Cost:** a whole app-integration surface (new CLI flags, a keyfile
  reader, a `.keys.json` manifest, reference integration code); not "clean". Composes with
  whitening. (This is the "external-key mode" that earlier docs described but the repo never
  shipped.)

## 10. File map

```
sopack/               the tool (Python)
  cli.py              argument parsing → repackage()
  apk.py              unzip → inject → 16 KB align → apksigner; keystore mgmt
  container.py        APK-vs-AAB detection, and the five things that differ between them
                      (+ adds the wbaes helper .so - the only add-file path)
  elf_inject.py       encrypt .text, add segment, hijack/add init, patch decinfo, self-verify
                      (+ _inject_wbaes: DT_NEEDED surgery + helper emission)
  cipher.py           ChaCha20 / XOR - mirror of stub/stub_cipher.h; plus AES-128-CTR,
                      which is the wbaes KEY-WRAP primitive (see §11)
  metadata.py         sopk_decinfo pack/parse - mirror of stub/decinfo.h
  provision.py        wbaes host provisioning: seal a kek via wb_keygen, wrap a session key
  rt_meta.py          sopk_rt_region pack/parse - mirror of stub/sopk_rt.h
  stubs.py            load prebuilt per-ABI blobs + offsets; locate the wbaes skeleton
  stubs/              stub_<abi>.bin + .json (built artifacts, shipped as package data)
                      sopk_rt_<abi>.so - the wbaes helper skeleton (USER-built, see §11)
stub/                 the injected runtime stub (C)
  stub.c              sopk_entry: mmap/decrypt/mremap-onto-base/mprotect/flush/chain
  syscalls.h          per-ABI raw syscalls, page-size probe, memcpy, I-cache flush
  stub_cipher.h       ChaCha20 / XOR - mirror of cipher.py
  stub_log.h          freestanding logd writer (the logging.stub-log confirmation line)
  decinfo.h           the 128-byte injector↔stub contract
  stub.ld             link at vaddr 0 → flat R+X image
  build_stubs.sh      NDK/LLVM build → flat blobs + offsets; fails on any relocation
  sopk_rt.c           wbaes helper: ctor that unwraps a session key and decrypts .text
  sopk_rt.h           the 96-byte injector↔helper contract (wbaes)
tests/                cipher KAT (RFC 8439), metadata + rt_meta layout, wbaes injection,
                      dlopen integration
docs/                 this documentation
```

---

## 11. `cipher: wbaes` - the white-box key-wrap mode

*For the boundary with the whitebox-cryptography SDK itself - the API surface consumed vs refused,
the artifact flow, the version contract and the upgrade checklist - see
[`WBAES.md`](./WBAES.md). This section is the reasoning behind it.*

An alternative to §4's freestanding stub, selected with `cipher: wbaes`. Everything in
§§1–2 still applies (`execmem` not `execmod`, no W+X, I-cache flush, 16 KB pages); what
changes is *where the decryptor lives* and *where the key lives*.

### 11a. The problem it solves, and the one it does not

The stub ships its ChaCha20 key inside the `.so` (whitened, §9b). Whitening raises the cost
of lifting it but the key is still, in principle, recoverable from the shipped bytes. A
white-box cipher removes that: the AES-128 key is diffused offline into a table network
inside an obfuscated VM, and **never reconstructed at runtime**. Nothing in the shipped
artifacts is a key you can copy out.

The white-box runtime is C++ and needs libc, libsodium and the dynamic linker, so it cannot
live in a freestanding blob. It therefore ships as a normal Android `.so` - a **helper** -
injected as a `DT_NEEDED` of the target. bionic runs a dependency's constructors before the
dependent's init, which gives us the same "before the target's own code" guarantee that
§5c's `DT_INIT` hijack gives, *without any init surgery at all*. As a side effect this mode
handles `INIT_ARRAY`-only libraries (the `libflutter.so` case) for free.

### 11b. Why the white-box does not decrypt `.text` (the redesign that mattered)

The obvious design - encrypt `.text` with the white-box, decrypt it with the white-box -
does not work at scale, and the reason is intrinsic rather than a bug. Each 16-byte block is
thousands of obfuscated VM instructions, and the VM deep-copies a ~400 KB data image per
block. Measured throughput was ~0.02–0.06 MB/s: a 5.5 MB Flutter `libapp.so` needed
**minutes** inside an ELF constructor. The first on-device test crashed at "uptime 2s" in
libflutter, far too early for the decrypt to have finished - the target read still-encrypted
code.

The slowness *is* the obfuscation, so it cannot be optimised away. Upstream drew the same
conclusion and in 2.0.0 **deleted** the bulk entry points (`wbc_crypt_ctr`,
`wbc_encrypt_ecb`), leaving key wrapping as the only shape the SDK offers. sopack follows:

```
white-box  ──wraps──▶  32-byte session key    (2 blocks, ~1.4 ms, FIXED cost)
session key ─drives──▶  ChaCha20 over .text    (~360 MB/s)
```

The white-box charge does not grow with the payload, so only the ChaCha20 term scales.
Measured on an aarch64 host for a 5.5 MiB `.text` (Phase 3's round-trip probe, `light` tier):

| step | cost | scales with `.text`? |
|---|---|---|
| `wbc_blob_kdf_tier` (header read) | ~0 ms | no |
| `wbc_open` (HKDF + `Unseal` of the ~455 KB blob) | **1.1 ms** | no - but once **per library** |
| `wbc_unwrap_key` (2 white-box blocks) | 0.83 ms | no |
| ChaCha20 over `.text` | 11.8 ms (467 MB/s) | yes |
| **total** | **13.7 ms** | |

ChaCha20 is the dominant term again, and it is the only one that grows. That is a deliberate
result, not luck - see the tier discussion below.

#### The KDF tier: why `wbc_open` used to dominate, and does not now

Before wbcrypto 3.0.0 the seal's key-derivation cost was a compile-time constant pinned at
Argon2id 64 MiB / 2 passes. `wbc_open` was ~230 ms on this host and **266 ms on device**, i.e.
91% of the whole load-time cost, plus a transient **64 MiB** allocation - all inside an ELF
constructor at app startup, and paid once *per library*.

3.0.0 moved that cost into the blob header as a per-blob tier, chosen at seal time
(`wb_keygen --kdf light|medium|heavy` → `WBC_KDF_NONE`/`_LOW`/`_HIGH`) and readable afterwards
with `wbc_blob_kdf_tier`. sopack pins **`light`** (HKDF-SHA256): the row above drops from ~230 ms
to 1.1 ms and the 64 MiB allocation disappears entirely. N libraries no longer multiply either.

That is **security-neutral here**, and the reason is worth being precise about. Argon2id makes
each passphrase *guess* expensive. sopack's passphrase is 128 bits of machine entropy that
**ships in the helper beside the blob**, whitened with a key derived from that same blob's first
1024 bytes (§11f) - so an attacker holding the APK holds the passphrase and guesses nothing.
Argon2id was never buying guessing resistance in this threat model; it was pure startup cost.
`light` is the correct construction for a high-entropy machine secret, and upstream documents
the ≥128-bit precondition that `secrets.token_hex(16)` meets exactly. The tier also sits inside
the seal's AEAD associated data, so a shipped blob cannot be tier-downgraded: rewriting the field
changes both the derived key and the authenticated data, and the tag then fails for every
passphrase.

What survives is that `wbc_open` is **not free** - `Unseal` still AEAD-decrypts the ~455 KB blob
and builds the VM image, once per library. So per-library cost still multiplies, just at a much
smaller constant.

That residue is why **APK size**, not startup, is what drove the v3 provider split - which has
**shipped**: before it each per-target helper carried ~465 KB of white-box code plus its own
~455 KB blob, ≈920 KB duplicated N times. §12c–d have the resulting shape; this section only owns
the two constraints that fixed it.

**The trigger cannot be shared, only the provider.** The shape named in earlier drafts - "one
helper carrying N regions" - cannot work: bionic runs a shared object's constructors exactly once,
so a helper shared by N targets decrypts only what was mapped when the *first* target loaded, and
a late-`dlopen`ed library (the Flutter `libapp.so` case) never gets decrypted at all. Hence one
thin helper per target, and a provider that is deliberately not a trigger - it has no constructor,
so it raises no ordering question.

**Caching the provider's `wbc_ctx` stays deferred**, and declined on purpose rather than pending:
it would keep the ~400 KB table image resident and dumpable for the whole process lifetime, and
`wbc_ctx` is not thread-safe. `sopk_wb.c` therefore opens, unwraps and closes per call - `ctx` is
a local, never a static.

### 11c. Why the bulk cipher is sopack's own ChaCha20, not the SDK's AEAD

2.0.0 also ships `wbc_bulk_seal`/`wbc_bulk_open` (XChaCha20-Poly1305) as its data mover. We
do not use them, for three reasons in priority order:

1. **`.text` encryption must be length-preserving.** The ciphertext occupies the target's own
   `.text` bytes. An AEAD adds 40 bytes (24-byte nonce + 16-byte tag) with nowhere to live,
   forcing a split frame; and its in/out-must-not-overlap contract forces a second
   full-size buffer - a transient +5.5 MB inside a constructor at app startup.
2. **No new cross-language contract.** `cipher.py` ⇄ `stub_cipher.h` ChaCha20 is already
   mirrored, KAT-locked and exercised by the aarch64 `dlopen` test. Using the AEAD would mean
   a bit-exact XChaCha20-Poly1305 on the pack side (new Python crypto, or a PyNaCl dependency).
3. **It is faster** here anyway: 14.5 ms vs 17.0 ms per 5.5 MiB. The Poly1305 tag buys
   integrity we have no use for - the threat model is obfuscation, and a tampered `.text`
   crashes visibly regardless.

### 11d. The host side, and why no new tool was needed

`wbc_wrap_key` requires an opened blob, which would seem to force a host tool that links the
white-box runtime. It does not, because of one fact: the white-box **is** bit-exact AES-128
(FIPS-197 anchor `69c4e0d8…`), and the wrap is plain CTR under the sealed key with the IV
prepended (`src/sdk/wbcrypto.cpp:CtrSessionKey`). The pack host still holds that key at the
moment it seals it, so it can compute the wrap directly:

```python
wrapped = wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)   # == wbc_wrap_key(ctx, sk, …)
```

Verified byte-exact against the real 2.0.0 `wbc_unwrap_key` - and unchanged at 3.0.0, whose
release notes keep the runtime ABI and `CtrSessionKey` byte-identical - pinned by a KAT in
`tests/test_cipher.py`. So provisioning stays "pure Python + the unchanged `wb_keygen` CLI",
and `wb_keygen`'s interface did not have to change beyond the `--kdf` flag 3.0.0 added.

### 11e. Finding the metadata without a patched symbol

The stub reaches its `sopk_decinfo` by a known blob offset (§5d). The helper cannot: it is a
real `.so` that LIEF re-bases when the packer appends the region segment, so no file offset
or symbol address baked at build time stays valid. Instead the packer appends the
`sopk_rt_region` as a single **read-only** `PT_LOAD` and the constructor finds it by walking
its **own** program headers (`dl_iterate_phdr`, self-identified by testing whether its own
code address falls inside a module's `PT_LOAD`) and picking the non-writable, non-executable
segment that begins with the `SRTR` magic and the expected version. The target's load base
comes from the same iteration, matched by soname basename.

That version gate, and every other failure path in the ctor, **fails closed**: `sopk_fail()`
records a numbered reason in the `volatile` `sopk_fail_code` and calls `abort()`.

Failing open would be pointless here, and this is the one place the stub's policy (§4c, §9b)
does not transfer. The stub can chain the original `DT_INIT` and degrade to a working, unpacked
library. The helper has no such fallback - decryption is its only job - so a fail-open return
leaves the target executing still-encrypted `.text`, which SIGILLs somewhere inside the target
with nothing pointing at the cause. Aborting does not add a crash; it relocates the same crash
to the actual cause, and the reason code stays readable in the tombstone even in a stripped,
non-logging build. `noreturn` lets the compiler drop the dead code after each call site, so the
policy costs no bytes.

An abort still says nothing about *why*, and the most likely why is a stale hand-built skeleton.
So `sopk_rt.c` embeds an opaque build marker and the packer refuses a skeleton lacking it
(§CLAUDE.md invariants): a pack-time error naming the rebuild beats a device-side SIGABRT.

### 11f. Adding the `DT_NEEDED` without breaking `dlsym` (a bug worth remembering)

`libapp.so` has no `DT_INIT` and no dependencies at all, so the only surgery wbaes needs on the
target is one extra `DT_NEEDED`. LIEF's `add_library` cannot be used for it - on tight libraries
it grows `.dynamic`/`.dynstr` and spills 4 KB-aligned segments that break 16 KB loading (§2d).
So the packer appends a 16 KB-aligned **copy** of `.dynstr` with the helper soname on the end,
repoints `DT_STRTAB`/`DT_STRSZ` at the copy, and overwrites the `.dynamic` `DT_NULL` terminator
with the new `DT_NEEDED` - all in raw file surgery, leaving `.dynamic` and `PT_DYNAMIC` in place.

The subtlety that cost a shipped, crashing APK: **which** copy of `.dynstr`. LIEF's `write()`
rebuilds the string table with the strings **sorted alphabetically** and rewrites every `st_name`
in `.dynsym` to match its new layout. The original code snapshotted `.dynstr` *before* the write,
so after repointing `DT_STRTAB` at that copy every `st_name` indexed the wrong table and landed
mid-string:

```
st_name 104  ->  "otData"                       (was _kDartVmSnapshotInstructions)
st_name  27  ->  "ns"                           (was _kDartIsolateSnapshotInstructions)
st_name  83  ->  "a"                            (was _kDartVmSnapshotData)
```

The library still loaded - `DT_NEEDED` resolved, because the packer owned both sides of that one
offset - but `dlsym(h, "_kDartVmSnapshotData")` returned `NULL`. Flutter stored the nulls and
dereferenced one in `performNativeAttach`, SIGSEGV'ing ~1 s after launch, in *unmodified*
`libflutter.so` code with nothing pointing at the packer. A clean null dereference in a library
you did not touch is the signature of a **load-time lookup failure**, not of executing encrypted
bytes - that distinction is what located this.

Two lessons are now enforced in code. The string table must be read back **from the written
file** via `DT_STRTAB` (`_effective_strtab`), never from the pre-write section. And
`_self_verify_wbaes` compares every dynamic symbol name before and after and refuses to pack on
any change, resolving them the way bionic does (`_LoaderView`: program headers + `.dynamic`, never
section headers, since in this mode the `.dynstr` section header and `DT_STRTAB` legitimately
point at different bytes).

See [`WBAES.md`](./WBAES.md) Part II for the six-phase verification
procedure, including a host round-trip that exercises every one of these contracts without a
device.

---

## 12. Key lifecycle - pack time and runtime, in both modes

Where the key comes from, how it is embedded, and how it is recovered at load. Everything below
is drawn from the code; §§4–5 and §11 argue *why* each step exists.

**There are two key paths, not three.** `cipher: xor` and `cipher: chacha20` share one path
completely - same `sopk_decinfo`, same whitening, same stub, same delivery; only the bulk
primitive differs. Call that **stub mode**. `cipher: wbaes` is the other. Both use the same
16-byte nonce block convention (12-byte ChaCha20 nonce ‖ 4-byte little-endian counter), so the
nonce is never a point of difference.

§§12a–b are stub mode, §§12c–d are `wbaes`, §12e is the placement tail both share, §12f is
the side-by-side, and §12g is the container-level pack sequence for `wbaes` - where the
injection and the added artifacts fit around the key steps.

### 12a. Stub mode - pack time (how the key is embedded)

```
HOST - sopack pack, cipher: chacha20|xor          driver: elf_inject.py:inject_so
─────────────────────────────────────────────────────────────────────────────────
  cipher.gen_key_nonce()                               ← cipher.py:gen_key_nonce
    ├── key32   = urandom(32)
    └── nonce16 = urandom(12) ‖ 00 00 00 00
           │
           ├──▶ apply_cipher(.text, key32, nonce16) ──▶ ciphertext, IN PLACE
           │      ← cipher.py:apply_cipher            (stream cipher: same length)
           └──▶ sopk_decinfo, 128 B   (metadata.py:DecInfo ⇄ stub/decinfo.h)
                  magic 'SOPK' │ version │ cipher_id │ flags
                  delta_text │ text_size │ delta_init   ← signed, vs &g_decinfo
                  key32 │ nonce16 │ reserved[40]
                           │
           stub blob (with the record at decinfo_off) appended as one R+X PT_LOAD
             ← blob + decinfo_off from stubs.py:load_stub
                           │
           WHITEN AT REST - the record is masked in the shipped file:
             span = blob[decinfo_off-1024 : decinfo_off]      ← the stub's OWN
             wkey = cipher.whiten_key(span)                      code/rodata
             shipped128 = ChaCha20(record, wkey, WHITEN_NONCE)
             ← cipher.py:whiten, written by elf_inject.py:_patch_decinfo
                           │
           DT_INIT ──▶ stub entry     (hijack the existing one, or add in place)
             ← elf_inject.py:_hijack_existing_init / :_add_dtinit_inplace
                           │
           output re-read and checked          ← elf_inject.py:_self_verify
```

The whitening key is **derived from the stub's own bytes**, so nothing key-shaped is stored to
carry it. Consequences the code enforces: the literal `SOPK` magic never appears in a packed
output (`_self_verify`), the injector patches at the known offset `seg_file_off + decinfo_off`
rather than scanning for magic, and it refuses to pack if `decinfo_off < WHITEN_SPAN` or the span
has fewer than 16 distinct bytes (a low-entropy span would mean a near-fixed whitening key).
`_self_verify` steps 5a/5b then re-read the output file and check the span is byte-identical to
what was whitened with, and that the shipped 128 bytes de-whiten back to the record.

**This is obfuscation, not secrecy.** The de-whitening key is computable from the shipped file
alone - an analyst who reverses the stub once recovers every key. Whitening raises that one-time
cost; it does not remove the ceiling (§9e).

### 12b. Stub mode - runtime (how the key is retrieved)

```
DEVICE - bionic runs DT_INIT before DT_INIT_ARRAY   all of this: stub/stub.c
─────────────────────────────────────────────────────────────────────────────────
  DT_INIT ──▶ sopk_entry                               ← stub/stub.c:sopk_entry
    │
    │  &g_decinfo reached PC-relatively (adr; -mcmodel=tiny) - no load bias needed
    │
    ├─ copy the shipped 128 bytes byte-by-byte into a STACK local raw[128]
    │     (the segment is R+X: de-whitening in place is not possible)
    ├─ wkey = sopk_whiten_key(&g_decinfo - 1024, 1024)   ← recomputed from own code
    │       stub/stub_cipher.h:sopk_whiten_key   (mirror of cipher.py:whiten_key)
    └─ sopk_chacha20_apply(raw, 128, wkey, SOPK_WHITEN_NONCE)   ← self-inverse
            stub/stub_cipher.h:sopk_chacha20_apply
           │
           ├─ parse raw[] into locals: key32, nonce16, cipher_id, flags,     [A:entry]
           │     delta_text, text_size, delta_init   ← plaintext key material
           │                                           lives HERE, one stack frame
           ├─ GATE: raw.magic == 'SOPK' && text_size != 0 ?
           │     no ──▶ [A:not-patched] ──▶ chain original init - FAIL OPEN
           │            (a tampered stub checksums differently → garbage → here)
           │
           └─ text = &g_decinfo + delta_text                                  [B]
                     │
                     └──▶ shared .text placement tail, §12e      [C][D][E][F]
                                │
                          chain original init via delta_init            [H:… OK]
```

### 12c. `wbaes` mode - pack time (how the key is embedded)

**Two scopes, and keeping them straight is the whole of this section:** `kek` is one per
**(pack, ABI)**, `sk` is one per **target**. The asymmetry is forced, not stylistic - bionic
resolves a `DT_NEEDED` soname once per process, so every copy of `libsopk_wb.so` for an ABI must
carry the *same* sealed blob. Sealing per target would put N KEKs behind one soname and a
helper would unwrap against the wrong blob on essentially every launch.

```
HOST - sopack pack, cipher: wbaes
─────────────────────────────────────────────────────────────────────────────────
ONCE PER (PACK, ABI)                              provision.py:provision_pack
  kek16      = urandom(16)          ← the long-term AES-128 key
  passphrase = token_hex(16)        ← 128 bits: the `light` tier's stated precondition
  seed       = randbits(64)         ← picks the white-box's internal bijections, so two
           │                          packs of the same key never ship comparable blobs
  kek16 ──▶ host wb_keygen --key <hex> --pass <p> --seed <n> --kdf light --out blob
           │        │
           │        └──▶ sealed blob, ~455 KB, format v4
           │             (kek diffused into the table network; NOT recoverable from it)
           │
  wpass = whiten_pass(passphrase, blob)   ← keyed off blob[:WHITEN_SPAN], the blob's OWN bytes
           │
  ✗ kek16 is DISCARDED - never written to any output, never leaves this function

PER TARGET                                        provision.py:provision_text
  sk32, wrap_iv16, nonce16 = urandom(32), urandom(16), urandom(12) ‖ 00 00 00 00
           │
  sk32 ──(AES-128-CTR under kek16)──▶ wrapped = wrap_iv ‖ aes128_ctr(sk, kek, iv)
           │                          48 B - byte-identical to wbc_wrap_key (§11d)
           │
  sk32 ──▶ apply_cipher(CIPHER_CHACHA20, .text, sk32, nonce16) ──▶ ciphertext, IN PLACE
           │                                                       (stream cipher: same length)
  ✗ sk32 is DISCARDED
```

The material then splits across **two** artifacts - that split *is* v3. Each region is appended
to its artifact as one read-only 16 KB-aligned `PT_LOAD` and found on device by magic-scanning
that artifact's own program headers, never a patched symbol or a file offset (§11e):

```
  'SRTT' sopk_rt_region v3, 96-B header + tail        rt_meta.py ⇄ stub/sopk_rt.h
     magic │ version │ text_rva │ text_size │ wrapped[48] │ nonce16[16] │
     soname_len │ flags │ reserved
     tail: the TARGET's soname ONLY - no blob and no passphrase since v3
           │
     ──▶ thin helper skeleton clone, DT_SONAME := libsopk_rt_<target>.so
         ONE PER TARGET, a few KB
         ← elf_inject.py:_emit_helper, skeleton from stubs.py:helper_skeleton_path

  'SRTW' sopk_wb_region v3, 24-B header + tail
     magic │ version │ blob_len │ pass_len │ flags │ reserved0 │ reserved1
     tail: wpass, then the sealed blob
           │
     ──▶ provider skeleton, DT_SONAME stays exactly libsopk_wb.so (never renamed)
         ONE PER (MODULE, ABI), ~465 KB + the blob
         ← elf_inject.py:emit_provider, skeleton from stubs.py:provider_skeleton_path

  target: + DT_NEEDED libsopk_rt_<target>.so   ← elf_inject.py:_add_needed_inplace
          raw ELF surgery - no DT_INIT hijack, no decinfo, no stub in this mode
          then checked by elf_inject.py:_self_verify_wbaes / :_self_verify_provider
```

Note the last line of each: the provider is emitted once per **(module, ABI)** so a multi-module
bundle gets one beside each module's helpers, but every copy for a given ABI carries the single
`pack_keys[abi]` blob. Emission scope and sealing scope are deliberately different.

`wpass` and the blob **must stay in the same artifact**: the whitening key is derived from the
blob's own first `WHITEN_SPAN` bytes, so splitting them across two `.so` files would turn any
provider/helper skew into a silent `wbc_open` failure rather than a version error.

What ships is the sealed blob, the wrapped session key, the nonce and the whitened passphrase.
**No shipped byte is a key that can be copied out and used** - the long-term key exists only as a
table network, and the session key only as ciphertext under it.

### 12d. `wbaes` mode - runtime (how the key is retrieved)

Since v3 the thin helper links **no white-box at all**. It calls `sopk_wb_k`, the provider's one
export, and the provider owns every `wbc_*` call. The division is worth naming because it is the
answer to "why not one helper for N libraries": the helper is the **trigger** and must stay 1:1
with its target, since bionic runs a shared object's constructors exactly once and a shared
trigger would never fire for a late-`dlopen`ed library; the provider is a **key service** -
shared, stateless, and with no constructor at all, so it raises no ordering question.

```
DEVICE - bionic runs a dependency's constructors BEFORE the dependent's init
  thin helper: stub/sopk_rt.c        shared provider: stub/sopk_wb.c
─────────────────────────────────────────────────────────────────────────────────
  dlopen(target) ──▶ load libsopk_rt_<target>.so ──▶ its own DT_NEEDED pulls in
                     libsopk_wb.so ──▶ sopk_rt_ctor
                                       ← stub/sopk_rt.c:sopk_rt_ctor
    │
    ├─ magic-scan own program headers for 'SRTT' + EXACT version  (§11e)
    │     no match ──▶ return - FAIL OPEN, SILENTLY
    │     (that silence is why _emit_helper demands the build marker at pack time)
    ├─ dl_iterate_phdr ──▶ target load base, matched by soname basename
    │     not mapped ──▶ sopk_fail(NO_TARGET) ──▶ abort()
    │
    ├─ sopk_wb_k(abi, region.wrapped[48], out sk32) ──▶ into libsopk_wb.so:
    │                                    ← stub/sopk_wb.c:sopk_wb_k, its ONE export
    │                                    magic-scan own phdrs for 'SRTW'
    │                                    pass = whiten(wpass, blob[:WHITEN_SPAN])
    │                                    wbc_blob_kdf_tier(blob)  ← must be 0; also the
    │                                                               3.0.0 link tripwire
    │                                    ctx  = wbc_open(blob, pass)          1.1 ms
    │                                    sk32 = wbc_unwrap_key(ctx, wrapped)  0.83 ms
    │                                    wbc_close(ctx)   frees the ~400 KB VM image
    │   ◀── SOPK_WB_OK, or a reason code the helper folds into its 10..19 fail band
    │       (the provider never aborts; the helper owns failing closed, so the
    │        tombstone names the step instead of blaming the shared object)
    │
    │  ★ sk32 is now an ORDINARY key in ORDINARY memory - the one window a process
    │    dump can exploit without attacking the white-box at all (§11a)
    │
    ├─ text = target_base + region.text_rva
    ├─ mmap anon RW ‖ copy window ‖ ChaCha20(text…, sk32, nonce16)   11.8 ms  ─┐
    ├─ sopk_wipe(sk32, 32)  ← the helper's OWN wipe: this file no longer links   │ §12e
    │                         the white-box, so wbc_wipe is unavailable. Called  │
    │                         as soon as the decrypt is done, BEFORE placement.  │
    └─ mremap onto the original VA ‖ mprotect R-X ‖ icache flush               ─┘
```

**~13.7 ms per library** at the `light` tier, and only the ChaCha20 term grows with `.text` - the
white-box charge is two blocks regardless of payload. `wbc_open` is still paid **once per
library** because the provider is stateless by choice; §11b has the full breakdown, the ~230 ms /
+64 MiB Argon2id history this replaced, and why the tier change is security-neutral here.

The long-term key `kek` is **never reconstructed on device**, at any point. That is the entire
security difference between the two modes.

### 12e. The shared `.text` placement tail (identical in both modes)

Implemented twice, once per decryptor: `stub/stub.c:sopk_entry` for stub mode,
`stub/sopk_rt.c:sopk_rt_ctor` for `wbaes`. Both end the same way, and the shape is forced by §2a - executing bytes the process
modified in a *file-backed* mapping is `execmod` (denied to apps); executing from *anonymous*
memory is `execmem` (allowed). Hence: never decrypt in place. The bracketed letters are stub
mode's logcat stages - the ones [`TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) has you read.

```
  pg = AT_PAGESZ                     ← read at runtime; 4 KB or 16 KB, never hardcoded
  win = [align_down(text,pg), align_up(text+len,pg))
  ├─ [C] mmap(anon, RW, win_len)                    ← scratch, no file behind it
  ├─      memcpy(scratch, win_lo, win_len)          ← the encrypted page window
  ├─ [D] decrypt exactly [text, text+text_size) inside the scratch
  ├─ [E] mremap(scratch, MREMAP_MAYMOVE|MREMAP_FIXED → win_lo)
  │        fails on some devices ──▶ [E2] munmap + mmap(MAP_FIXED) + copy
  ├─ [F] mprotect(win, R-X)                         ← never W+X simultaneously
  └─      icache flush (arm/arm64)                  ← §2c
```

Landing back on the **original** VA is what keeps every PC-relative reference, GOT entry and
unwind table valid, so nothing else in the library needs rewriting.

### 12f. The two paths side by side

| | stub mode (`chacha20` / `xor`) | `wbaes` mode |
|---|---|---|
| bulk cipher over `.text` | ChaCha20 or XOR | ChaCha20 (always) |
| key used for `.text` | `key32`, generated per library | `sk32`, the unwrapped session key |
| what ships | the key itself, **whitened** | sealed blob + wrapped key + whitened passphrase |
| where the metadata lives | `sopk_decinfo`, 128 B, inside the R+X stub segment | TWO v3 regions in RO segments: `'SRTT'` 96 B + soname per target, `'SRTW'` 24 B + wpass + blob per ABI |
| found at runtime by | known offset from `&g_decinfo` (PC-relative) | magic-scan of the helper's own phdrs |
| decryptor | freestanding stub, raw syscalls, no libc | two normal `.so`s: a few-KB thin helper per target (libc only) + one ~465 KB provider per ABI (C++ + libsodium) |
| delivery | `DT_INIT` hijack or in-place add | `DT_NEEDED` on the target |
| files added to the container | none - the stub rides inside the target | 1 thin helper per target + 1 provider per (module, ABI); the tool's only add-file path |
| works on `INIT_ARRAY`-only libs | yes, via the added `DT_INIT` | yes, for free |
| gate on bad metadata | `magic` / `text_size` check → chain original (fail open, logs `A:not-patched`) | exact region version → `abort()` (**fails closed**, reason in `sopk_fail_code`) |
| symbols / debug info shipped | n/a (flat blob, no symbol table) | none: the packer strips every non-ALLOC section |
| plaintext key in memory | the de-whitened stack copy, for one frame; **not** explicitly zeroed on exit | `sk32`, only between the unwrap and the explicit `sopk_wipe` (the helper's own - it no longer links the white-box) |
| startup cost | ~15 ms per 5.5 MiB | ~13.7 ms per library at the `light` tier (ChaCha20 dominates; §11b) |
| **long-term key recoverable from the shipped files?** | **yes** - reverse the stub once | **no** - never reconstructed on device |

For the SDK-boundary view of the `wbaes` column - which WBC calls and artifacts each step uses -
see [`WBAES.md`](./WBAES.md).

### 12g. `wbaes` mode - the container-level sequence (where inject fits)

§§12c–d follow the *key*. This follows the *pack*, because the ordering inside
`apk.repackage` is load-bearing in three places and none of it is visible from the per-library
view. One entry loop over `zin.infolist()` of the **input** only, so artifacts added later can
never be re-selected within a run.

```
sopack pack in.apk -o out.apk                                     apk.py:repackage
─────────────────────────────────────────────────────────────────────────────────
  detect container from CONTENTS                  BundleConfig.pb → AAB
    ← container.py:detect                         AndroidManifest.xml → APK
  build_excludes()  ← apk.py:build_excludes; ALWAYS_EXCLUDE_PATTERNS prepended
                      unconditionally, so an already-packed APK cannot feed
                      libsopk_* back through inject
           │
  FOR EACH ENTRY matching the container's lib pattern:
    │
    ├─ _classify → candidate?   ← apk.py:_classify, via apk.py:_match_lib_pattern
    │                             (exclusion is checked BEFORE selection)
    │
    ├─ if this ABI has no pack key yet:  provision_pack(abi)   ← SEALED LAZILY, on
    │     provision.py:provision_pack, which shells out to the host wb_keygen
    │     found by provision.py:find_wb_keygen.  Lazy means: sealed on
    │     this ABI's FIRST target, not up front. Safe only because every
    │     intermediate lives in `tmp` and out_apk is not written until signing, so
    │     a stale pre-3.0.0 wb_keygen raising mid-loop leaves no partial output.
    │     Do not hoist the output write into the loop without hoisting this.
    │
    ├─ inject_so → _inject_wbaes (elf_inject.py), six steps:
    │     1. encrypt .text under a fresh session key            (§12c, per target)
    │     2. reserve a 16 KB-aligned placeholder segment for a .dynstr copy
    │        NOT LIEF add_library: it grows .dynamic/.dynstr and spills 4 KB-aligned
    │        segments on tight libs, breaking 16 KB loading
    │     3. binary.write(), THEN read _effective_strtab() and fill the placeholder;
    │        raw-repoint DT_STRTAB/DT_STRSZ and overwrite .dynamic's DT_NULL with
    │        DT_NEEDED in place. Post-write is mandatory - LIEF re-sorts .dynstr and
    │        rewrites every st_name during write(), so a copy taken earlier
    │        desynchronises every symbol name and dlsym returns NULL (§11f)
    │     4. emit the thin helper carrying this target's 'SRTT' region, strip every
    │        non-ALLOC section, refuse a skeleton missing the build marker
    │     5. _self_verify_wbaes: dynsym names unchanged vs input, 16 KB + no TEXTREL,
    │        no kek/sk byte present in the output
    │     6. (standalone callers only) emit a provider beside the helper
    │
    └─ InjectError under auto-select ──▶ SKIP: original entry written back verbatim,
       recorded in RepackResult.failed, ships in CLEARTEXT and is named in the CLI
       summary. An EXPLICITLY NAMED library re-raises instead (§Library selection).
           │
  AFTER THE LOOP - the provider cannot be produced per target:
    ├─ for each (module, abi) in thin_by_slot:  emit_provider(pack_keys[abi])
    │     ← elf_inject.py:emit_provider
    │     Keyed on thin_by_slot, NOT pack_keys: an ABI whose every target was skipped
    │     has a pack key and no consumer, and its provider would be ~936 KB of dead
    │     white-box. All copies for one ABI carry the SAME blob (§12c).
    ├─ add the helpers + providers as new entries - the tool's ONLY add-file path.
    │     STORED for an APK (page-mappable in place); DEFLATED for a bundle, since
    │     bundletool re-packs them into the splits it generates.
    │     A helper name collision warns and keeps the existing bytes; a PROVIDER
    │     collision is FATAL - reusing a foreign blob means no session key unwraps.
    └─ PACK-LEVEL CLOSURE: assert every staged slot's provider entry exists.
       _self_verify_wbaes runs per target and structurally cannot see this, and a
       missing provider fails 100% of launches inside whatever dlopen'd the target.
           │
  zero packed libraries ──▶ NothingPackedError (exit 6), carrying the partial result
           │
  APK: 16 KB zip-align, then apksigner self-sign (best-effort; warns if absent)
  AAB: no align, NEVER signed - META-INF/*.{SF,RSA,MF} stripped, go run jarsigner
```

The three orderings that matter, restated because each was a bug once: **seal before
`inject_so`** (the wrap needs the KEK), **emit the provider after the loop** (it depends on
knowing which slots actually staged helpers), and **read `.dynstr` after `binary.write()`** (LIEF
rewrites it during the write).
