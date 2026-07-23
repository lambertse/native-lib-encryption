# Architecture & implementation

This document explains **what sopack is, how it is built, and the reasoning behind
each design decision** — including the non-obvious constraints that dictated the shape
of the whole system and the bugs that taught us why the "obvious" approaches don't
work. If you only want to run the tool, read [`building.md`](./building.md). If
something crashes, read [`troubleshooting.md`](./troubleshooting.md).

---

## 1. The goal, and why it forces a "black-box packer"

sopack takes an **already-built APK** plus a list of native libraries, and produces a
**self-signed APK** in which each listed `.so` has its code section (`.text`)
encrypted at rest and transparently decrypted at load time — **with no access to the
library's source**.

The "no source" requirement is the whole story. If we had the source we would compile
a decryption stub *into* each library at build time (the classic model). We don't, so
we must take a finished, already-linked, position-independent `.so` and:

1. encrypt its `.text` bytes in the file, and
2. graft in a piece of code that runs **before** any of that encrypted code, decrypts
   it in memory, and then lets the library run normally.

That is an **Android packer** — the same category as commercial tools like Tencent
Legu. The techniques (encrypt `.text`, inject an executable segment, hijack the
library's init hook, decrypt at load) are established, but every step is constrained
by how modern Android actually loads and protects code. Those constraints are next.

> **Security posture, stated up front.** The decryption key ships inside the binary
> (whitened at rest — §9 — not in plaintext), and after decryption the plaintext lives in
> a readable `R-X` mapping. Anyone with Frida or a `/proc/self/maps` dump recovers
> everything. This is **anti-static-analysis obfuscation, not cryptographic protection.**
> The stub ships **byte-identical in every packed app** and contains the whole
> de-obfuscation recipe, so an analyst reverses it **once** and has a universal offline
> unpacker for that version — the hardening in §9 raises the *cost* of that one-time
> reverse (grep-and-decrypt → a real RE session); it does not remove the ceiling.
> Re-signing also gives the APK a **new signing identity** (see §6).

---

## 2. The constraints that dictate the whole design

Four hard properties of modern (API 29+) Android decide the architecture. Getting any
one wrong produces either a load failure, a SELinux denial, or an intermittent crash.

### 2a. W^X and the `execmod` vs `execmem` distinction (the central constraint)

An app targeting `targetSdk ≥ 29` runs in the `untrusted_app` SELinux domain. That
domain is granted `execmem` (make **anonymous** memory executable — this is how ART's
JIT and WebView work) but is **denied `execmod`** (re-add `PROT_EXEC` to a **modified,
file-backed** page).

This kills the textbook UPX-style approach ("`mprotect` the file-mapped `.text` to
writable, decrypt in place, `mprotect` it back to executable"). The final `mprotect`
touches a copy-on-write-dirtied, file-backed page → `avc: denied { execmod }` →
`EACCES`. So we can **never decrypt `.text` in place on its own file mapping.**

The working design: `mmap` fresh **anonymous** RW memory, decrypt into
it, flip it to `R-X` (an `execmem` check — allowed), and put those pages where the
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
page size — which we read from the kernel, never hardcode. The injected executable
segment is aligned to 16 KB so the library still loads on 16 KB devices.

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

## 4. Component 1 — the runtime decryption stub

Source: `stub/stub.c`, `stub/syscalls.h`, `stub/stub_cipher.h`, `stub/stub_log.h`,
`stub/decinfo.h`, linked by `stub/stub.ld`, built by `stub/build_stubs.sh`.

### 4a. Why it is freestanding

The blob is injected into an arbitrary foreign library. It therefore **cannot have any
external symbols, PLT/GOT entries, or dynamic relocations** — there is nothing to
resolve them against, and a relocation into someone else's library would corrupt it.
So the stub:

- makes raw Linux syscalls directly (no libc) — `stub/syscalls.h` has per-ABI inline
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
     decrypted bytes in — same `execmem` result via a different kernel path.
5. `mprotect` the window to `R-X`, flush the I-cache (§2c), then **chain the original
   init** if one was displaced.

Failures "fail open": if a syscall fails the stub jumps to the chain/return path rather
than crashing, so a mis-encrypted library degrades instead of hard-crashing during
diagnosis. (`--log` turns on staged `logd` diagnostics so you can see which stage ran.)

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
pins the Python side to the RFC 8439 test vector — so a green cipher test means the C
stub (same keystream) will decrypt what Python encrypted. The nonce block is
`[0:12] = nonce, [12:16] = little-endian initial counter`; the counter is 32-bit and
wraps without carrying into the nonce, on both sides.

---

## 5. Component 2 — the ELF injection engine

Source: `sopack/elf_inject.py` (plus `cipher.py`, `metadata.py`, `stubs.py`). Uses
LIEF to parse and rewrite the ELF. Per library:

### 5a. Encrypt `.text` (the section, not the segment)

We encrypt the `.text` **section** byte range, not the whole executable `PT_LOAD`
segment. The executable segment also contains `.plt`, `.init`, `.fini`, and code the
loader touches during relocation — encrypting those would corrupt things read before
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
  then run on decrypted code. No chaining is needed — we displaced nothing.

**Why we never hijack `DT_INIT_ARRAY`.** This is the lesson from the libflutter.so
crash. On position-independent libraries (every Android `.so`) each `INIT_ARRAY` slot
is populated by an `R_*_RELATIVE` relocation **at load time** — the file slot reads `0`
(RELA/arm64, x86_64) or holds the addend (REL/armv7). If we overwrite the file slot
with the stub pointer, the loader applies the relocation and **silently reverts our
write** to the original constructor address. The stub never runs, `.text` stays
encrypted, and the original constructor executes ciphertext → `SIGILL` inside
`call_array`. Adding a `DT_INIT` sidesteps the entire relocation problem. This is a
general correctness fix: "`INIT_ARRAY` but no `DT_INIT`" is the shape of libflutter.so
and **most** NDK-built C++ libraries.

**How "add a `DT_INIT` in place" works without breaking 16 KB loading.** The naive way
— ask LIEF to add a dynamic entry — grows `.dynamic`, which makes LIEF spill it into a
new 4 KB-aligned segment that breaks 16 KB loading; and repointing `PT_DYNAMIC` into a
different segment makes bionic/glibc reject the library. Instead
`_add_dtinit_inplace()` does raw, class-aware (ELF32/ELF64) surgery: it **overwrites
the existing `DT_NULL` terminator with `DT_INIT`** and relies on the following word
being a `DT_NULL` at runtime as the new terminator. `.dynamic` stays writable and in
place; only the 16 KB stub segment is added.

> **Insight (no-init layout):** whether the slot after the terminator reads as
> `DT_NULL` at runtime is decided by the containing `PT_LOAD`'s `filesz`/`memsz`
> (bytes beyond `filesz` are kernel zero-filled), **not** by the file bytes there — a
> non-`SHF_ALLOC` section like `.shstrtab` sitting after `.dynamic` in the file is not
> loaded. And bionic stops at the first entry whose **`d_tag` word** is zero and
> ignores its `d_val`, so a follow-slot with `tag=0` but a non-zero value (seen on
> armv7 libflutter) is a valid terminator. `_add_dtinit_inplace()` checks exactly these
> runtime conditions and refuses loudly when they don't hold.

### 5d. Patch the metadata and self-verify

The injector writes the finalized `sopk_decinfo` (deltas, key, nonce, sizes, flags) at
its **known blob offset** (`seg_file_off + decinfo_off`) — after asserting the placeholder
magic is there — then **whitens** it in place (§9b). It then runs `_self_verify()`, which
re-parses the output and asserts **every invariant the runtime depends on** before the tool
emits a file:

- round-trip: decrypting the output `.text` reproduces the original plaintext;
- whitening round-trip: de-whitening the shipped 128 bytes reproduces the packed record,
  and the `SOPK` magic needle appears **nowhere** in the output;
- `.text` vaddr is unchanged (so `delta_text` is valid);
- every `PT_LOAD` is 16 KB congruent, and the injected segment is `R+X`;
- no `DT_TEXTREL`;
- **loader-aware hook check:** the strategy is a `DT_INIT-*` one and `DT_INIT` actually
  points at the stub entry — i.e. what the loader will call *first*, not a file-slot
  value a relocation would overwrite.

That last check is the one that would have caught the libflutter crash at pack time
instead of on the device; it is deliberately loader-aware now.

---

## 6. Component 3 — APK repackage and self-sign

Source: `sopack/apk.py`, driven by `sopack/cli.py`.

1. Unzip the APK; for each `lib/<abi>/<name>.so` matching the requested list (by full
   path or bare basename → all ABIs), run Component 2.
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
> new cert and may refuse to run — independent of whether the encryption itself
> succeeded.

---

## 7. How it was built and validated

The build followed the staged plan from the original design brief — prove the riskiest
runtime assumption first, then build outward — so that a failure at any stage was
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
`apksigner.jar` for signing) — no NDK and no root required, because the stub is
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
against the C stub) — confirm those ABIs on device or under qemu-user.

---

## 8. Boundaries and limitations

- **Obfuscation only.** The key ships in the binary (whitened — §9); plaintext is readable
  at runtime.
- **New signing identity.** No update-install over the original; signature-pinned apps
  will notice.
- **Decrypt happens at `DT_INIT`**, i.e. after relocation but before `DT_INIT_ARRAY`.
  Code invoked *before* `DT_INIT` (IFUNC resolvers, `DT_PREINIT_ARRAY`) cannot be
  protected by this approach — not usually a problem, but it's the boundary.
- **Per-library fragility.** Section-stripped libraries or exotic init code are refused
  loudly rather than silently corrupted. LIEF-rebuilt ELFs occasionally trip strict
  loaders, so a real `dlopen`/on-device check is always warranted.
- **Encrypting stock engine libraries is usually not worth it.** `libflutter.so`, for
  example, is the public, byte-identical Flutter engine — encrypting it protects
  nothing proprietary while adding load-time cost and fragility. Encrypt the library
  that holds *your* code (e.g. Flutter's `libapp.so`, the Dart AOT snapshot).

---

## 9. Anti-static-analysis hardening

The default posture is obfuscation (§1). Three measures raise the bar for a **static**
analyst — someone reading the APK without running it — while keeping the freestanding /
prebuilt-blob / 128-byte-contract architecture intact.

### 9a. Why the old layout was trivial to defeat

The v1 record was a fixed 128-byte `sopk_decinfo` beginning with the constant magic
`SOPK` (`0x4B504F53`). Extraction was: grep the file for the magic, read the struct at
that offset, lift `key[32]` / `nonce[16]` / `cipher_id`, and — from `delta_text` /
`text_size` — learn exactly where `.text` is and how big. A ~10-line offline script then
decrypts `.text` without ever running the app. The magic and the plaintext key were two
crown-jewel signposts.

### 9b. Whitening the metadata record (the primary measure)

The 128-byte contract is unchanged; only its **at-rest representation** changes. The whole
record is XOR-masked with a ChaCha20 keystream whose **key is a checksum the stub computes
over its own code bytes** at load. No new secret is stored anywhere — the derivation lives
in the (freestanding) stub.

- **Span.** `sopk_whiten_key` (FNV-1a-64 folded through splitmix64 to 32 bytes, so every key
  byte depends on every span byte) runs over the `SOPK_WHITEN_SPAN` (1024) bytes immediately
  **before** `g_decinfo` — real code/rodata the injector never rewrites. The span is
  anchored on `&g_decinfo` alone; anchoring on a function symbol (`&sopk_entry`) emits an
  unresolved arm64 relocation that the build guard rejects. Mirrored in `sopack/cipher.py` ⇄
  `stub/stub_cipher.h`; the fixed nonce is `SOPK_WHITEN_NONCE`.
- **Pack time** (`elf_inject.py`): patch decinfo at its **known** blob offset
  (`seg_file_off + decinfo_off`, the value `_self_verify` already trusts) — the magic scan
  is gone — then `whiten()` the 128 bytes in place. `_self_verify` de-whitens the shipped
  bytes back to the packed record and asserts the magic needle appears **nowhere** in the
  output.
- **Load time** (`stub.c`): copy the volatile record to a local, `sopk_whiten_key` over the
  span, `sopk_chacha20_apply` to de-whiten, then the existing `magic == SOPK && text_size != 0`
  gate runs on the de-whitened locals. **The magic/version are a post-de-whiten sentinel** —
  present only after a correct derivation, never in the file. A tampered stub checksums
  differently → garbage de-whiten → magic mismatch → **fail open** (chain the original init),
  the same safe degradation as an unpatched blob. (Anti-tamper is a free side effect, not the
  goal — a dynamic analyst never patches the stub, they dump decrypted `.text` from memory.)

What this buys: the grep-magic-read-key attack finds nothing; recovering the key now
requires reproducing the checksum-and-keystream derivation, i.e. reversing the stub.

### 9c. Section-header stripping — researched, rejected on Android 14+, removed

Whitening hides the key but **not** where `.text` is — the ELF **section header** still
gives its name, offset and size, so a pass to detach the section table was implemented and
tested. **Two on-device tests (Android 16 / target_sdk 36) killed it:** (1) zeroing
`e_shoff`/`e_shnum`/`e_shstrndx` → `linker: "...libapp.so" has invalid e_shstrndx`; (2) after
keeping `e_shstrndx` and zeroing only `e_shoff`/`e_shnum` → `linker: "...has no section
headers"` (bionic `ReadSectionHeaders` rejects `e_shnum == 0`). Both → lib never loads →
Flutter `SIGSEGV`. glibc `dlopen` on the host passed both, so host tests can't catch this.
**Conclusion:** bionic (Android 14+) requires a section header table to exist; detaching it
is not viable, so the feature was **removed**. It was also marginal: once whitening holds,
`.text`'s location (derivable from the un-strippable program headers + `PT_DYNAMIC`/`.dynsym`)
gives an analyst nothing. See [`static-analysis-hardening.md`](./static-analysis-hardening.md)
§Method 3.

### 9d. String hygiene

The logcat **tag** `"sopack"` is the one constant that would name the packer in a `strings`
dump (which scans raw bytes, section table or not). It is stored XOR-obfuscated in
`stub_log.h` and decoded on-stack, so the name never appears in a packed lib. The staged
`--log` debug labels (`A:entry`, …) remain in cleartext — they are generic markers, only
emitted under `--log`, and not a reliable packer fingerprint; fuller message obfuscation is
a straightforward extension of the same helper.

### 9e. The ceiling, and two ways to break it (not the default)

Everything above lives in the "prebuilt blob + clean architecture" envelope, which shares
one hard limit: the stub is identical across every packed app and holds the *complete*
recipe, so **reverse it once, unpack every app** at that version. Two options break that
ceiling but leave the clean envelope:

- **Polymorphic per-pack stub — implemented, opt-in via `--obfuscate`.** With `--obfuscate`,
  `sopack` recompiles the stub per pack through **O-MVLL** with a fresh random seed, so every
  app ships a structurally different, heavily-obfuscated stub (control-flow flattening +
  MBA + control-flow breaking on the decrypt/whiten logic) — reversing one app yields no
  unpacker for the next. Only the **reloc-free** O-MVLL pass set is enabled, so every build
  still passes the no-reloc / no-undef / no-`adrp` guards; passes that need writable globals
  or libc (opaque-constants, indirect-branch, basic-block-duplicate → `lrand48`) are excluded
  because the freestanding R+X blob can't host them. Obfuscation is scoped to **arm64-v8a**
  (AArch32 exhausts registers; x86_64 is unsupported by O-MVLL). **Cost:** needs the NDK +
  O-MVLL toolchain **at pack time** (x86_64-only, so typically run under emulation — see
  `assets/Dockerfile`), and packs are slower. Default (no `--obfuscate`) is unchanged: the
  shipped prebuilt blob, no toolchain. See [`static-analysis-hardening.md`](./static-analysis-hardening.md)
  §"Per-pack polymorphism". **Honest ceiling:** this breaks *reuse*, not per-app
  reversibility — a determined analyst + LLM still reverses any single app's stub; the win is
  that the cost is now per-app, not amortized to ~0. (Per-pack *data*-only randomization — a
  random whitening salt, junk in `reserved` — is cheap but does **not** break the ceiling; the
  logic stays identical across apps.)
- **External / server-derived key.** Keep the key out of the `.so`: store a `key_id` + salt,
  have the app derive the key (PBKDF2 from a **server** secret or user credential) and write
  it to `/data/user/<userId>/<pkg>/files/.sopk_<key_id>` before `System.loadLibrary`; the
  stub reads it via raw `openat`/`read` and fails open if absent. **Static resistance is real
  only if the secret is out-of-band** (server/user) — an embedded secret is still in the
  APK's dex, so no gain. **Cost:** a whole app-integration surface (new CLI flags, a keyfile
  reader, a `.keys.json` manifest, reference integration code); not "clean". Composes with
  whitening. (This is the "external-key mode" that earlier docs described but the repo never
  shipped.)

## 10. File map

```
sopack/               the tool (Python)
  cli.py              argument parsing → repackage()
  apk.py              unzip → inject → 16 KB align → apksigner; keystore mgmt
  elf_inject.py       encrypt .text, add segment, hijack/add init, patch decinfo, self-verify
  cipher.py           ChaCha20 / XOR  — mirror of stub/stub_cipher.h
  metadata.py         sopk_decinfo pack/parse — mirror of stub/decinfo.h
  stubs.py            load prebuilt per-ABI blobs + offsets
  stubs/              stub_<abi>.bin + .json (built artifacts, shipped as package data)
stub/                 the injected runtime stub (C)
  stub.c              sopk_entry: mmap/decrypt/mremap-onto-base/mprotect/flush/chain
  syscalls.h          per-ABI raw syscalls, page-size probe, memcpy, I-cache flush
  stub_cipher.h       ChaCha20 / XOR — mirror of cipher.py
  stub_log.h          freestanding logd writer (the --log confirmation line)
  decinfo.h           the 128-byte injector↔stub contract
  stub.ld             link at vaddr 0 → flat R+X image
  build_stubs.sh      NDK/LLVM build → flat blobs + offsets; fails on any relocation
tests/                cipher KAT (RFC 8439), metadata layout, dlopen integration
docs/                 this documentation
```
