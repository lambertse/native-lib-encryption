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

- **Polymorphic per-pack stub.** Compile a *different* stub per pack (randomized whitening
  constants / checksum seed, instruction scheduling, junk / opaque predicates) so reversing
  one app does not crack the others. This is the only in-binary way to break the ceiling.
  **Cost:** needs the `build_stubs.sh` toolchain (clang+lld+llvm) **at pack time**, not just
  the shipped blob — it breaks the prebuilt-blob model, slows packs, and must re-run the
  no-reloc/no-`adrp` guards per pack. (Per-pack *data* randomization — a random whitening
  salt, junk in `reserved` — is cheap but does **not** break the ceiling; the logic is still
  identical across apps.)
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
                      (+ adds the wbaes helper .so — the only add-file path)
  elf_inject.py       encrypt .text, add segment, hijack/add init, patch decinfo, self-verify
                      (+ _inject_wbaes: DT_NEEDED surgery + helper emission)
  cipher.py           ChaCha20 / XOR — mirror of stub/stub_cipher.h; plus AES-128-CTR,
                      which is the wbaes KEY-WRAP primitive (see §11)
  metadata.py         sopk_decinfo pack/parse — mirror of stub/decinfo.h
  provision.py        wbaes host provisioning: seal a kek via wb_keygen, wrap a session key
  rt_meta.py          sopk_rt_region pack/parse — mirror of stub/sopk_rt.h
  stubs.py            load prebuilt per-ABI blobs + offsets; locate the wbaes skeleton
  stubs/              stub_<abi>.bin + .json (built artifacts, shipped as package data)
                      sopk_rt_<abi>.so — the wbaes helper skeleton (USER-built, see §11)
stub/                 the injected runtime stub (C)
  stub.c              sopk_entry: mmap/decrypt/mremap-onto-base/mprotect/flush/chain
  syscalls.h          per-ABI raw syscalls, page-size probe, memcpy, I-cache flush
  stub_cipher.h       ChaCha20 / XOR — mirror of cipher.py
  stub_log.h          freestanding logd writer (the --log confirmation line)
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

## 11. `--cipher wbaes` — the white-box key-wrap mode

*For the boundary with the whitebox-cryptography SDK itself — the API surface consumed vs refused,
the artifact flow, the version contract and the upgrade checklist — see
[`wbc-integration.md`](./wbc-integration.md). This section is the reasoning behind it.*

An alternative to §4's freestanding stub, selected with `--cipher wbaes`. Everything in
§§1–2 still applies (`execmem` not `execmod`, no W+X, I-cache flush, 16 KB pages); what
changes is *where the decryptor lives* and *where the key lives*.

### 11a. The problem it solves, and the one it does not

The stub ships its ChaCha20 key inside the `.so` (whitened, §9b). Whitening raises the cost
of lifting it but the key is still, in principle, recoverable from the shipped bytes. A
white-box cipher removes that: the AES-128 key is diffused offline into a table network
inside an obfuscated VM, and **never reconstructed at runtime**. Nothing in the shipped
artifacts is a key you can copy out.

The white-box runtime is C++ and needs libc, libsodium and the dynamic linker, so it cannot
live in a freestanding blob. It therefore ships as a normal Android `.so` — a **helper** —
injected as a `DT_NEEDED` of the target. bionic runs a dependency's constructors before the
dependent's init, which gives us the same "before the target's own code" guarantee that
§5c's `DT_INIT` hijack gives, *without any init surgery at all*. As a side effect this mode
handles `INIT_ARRAY`-only libraries (the `libflutter.so` case) for free.

### 11b. Why the white-box does not decrypt `.text` (the redesign that mattered)

The obvious design — encrypt `.text` with the white-box, decrypt it with the white-box —
does not work at scale, and the reason is intrinsic rather than a bug. Each 16-byte block is
thousands of obfuscated VM instructions, and the VM deep-copies a ~400 KB data image per
block. Measured throughput was ~0.02–0.06 MB/s: a 5.5 MB Flutter `libapp.so` needed
**minutes** inside an ELF constructor. The first on-device test crashed at "uptime 2s" in
libflutter, far too early for the decrypt to have finished — the target read still-encrypted
code.

The slowness *is* the obfuscation, so it cannot be optimised away. Upstream drew the same
conclusion and in 2.0.0 **deleted** the bulk entry points (`wbc_crypt_ctr`,
`wbc_encrypt_ecb`), leaving key wrapping as the only shape the SDK offers. sopack follows:

```
white-box  ──wraps──▶  32-byte session key    (2 blocks, ~1.4 ms, FIXED cost)
session key ─drives──▶  ChaCha20 over .text    (~360 MB/s)
```

The white-box charge does not grow with the payload, so only the ChaCha20 term scales.
Measured on an aarch64 host for a 5.5 MiB `.text`:

| step | cost | scales with `.text`? |
|---|---|---|
| `wbc_open` (Argon2id KDF + Unseal) | ~230 ms | no — but once **per library** |
| `wbc_unwrap_key` (2 white-box blocks) | ~1.4 ms | no |
| ChaCha20 over `.text` | ~15 ms | yes |
| **total** | **~245 ms** | |

Note that the KDF, not the crypto, is now the dominant term — and it is the one that
multiplies by library count, since each target gets its own helper and blob. Collapsing that
to one shared helper is a known, deliberately deferred optimisation.

### 11c. Why the bulk cipher is sopack's own ChaCha20, not the SDK's AEAD

2.0.0 also ships `wbc_bulk_seal`/`wbc_bulk_open` (XChaCha20-Poly1305) as its data mover. We
do not use them, for three reasons in priority order:

1. **`.text` encryption must be length-preserving.** The ciphertext occupies the target's own
   `.text` bytes. An AEAD adds 40 bytes (24-byte nonce + 16-byte tag) with nowhere to live,
   forcing a split frame; and its in/out-must-not-overlap contract forces a second
   full-size buffer — a transient +5.5 MB inside a constructor at app startup.
2. **No new cross-language contract.** `cipher.py` ⇄ `stub_cipher.h` ChaCha20 is already
   mirrored, KAT-locked and exercised by the aarch64 `dlopen` test. Using the AEAD would mean
   a bit-exact XChaCha20-Poly1305 on the pack side (new Python crypto, or a PyNaCl dependency).
3. **It is faster** here anyway: 14.5 ms vs 17.0 ms per 5.5 MiB. The Poly1305 tag buys
   integrity we have no use for — the threat model is obfuscation, and a tampered `.text`
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

Verified byte-exact against the real 2.0.0 `wbc_unwrap_key` and pinned by a KAT in
`tests/test_cipher.py`. So provisioning stays "pure Python + the unchanged `wb_keygen` CLI",
and `assets/wbc/wb_keygen`'s interface did not have to change.

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
library. The helper has no such fallback — decryption is its only job — so a fail-open return
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
target is one extra `DT_NEEDED`. LIEF's `add_library` cannot be used for it — on tight libraries
it grows `.dynamic`/`.dynstr` and spills 4 KB-aligned segments that break 16 KB loading (§2d).
So the packer appends a 16 KB-aligned **copy** of `.dynstr` with the helper soname on the end,
repoints `DT_STRTAB`/`DT_STRSZ` at the copy, and overwrites the `.dynamic` `DT_NULL` terminator
with the new `DT_NEEDED` — all in raw file surgery, leaving `.dynamic` and `PT_DYNAMIC` in place.

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

The library still loaded — `DT_NEEDED` resolved, because the packer owned both sides of that one
offset — but `dlsym(h, "_kDartVmSnapshotData")` returned `NULL`. Flutter stored the nulls and
dereferenced one in `performNativeAttach`, SIGSEGV'ing ~1 s after launch, in *unmodified*
`libflutter.so` code with nothing pointing at the packer. A clean null dereference in a library
you did not touch is the signature of a **load-time lookup failure**, not of executing encrypted
bytes — that distinction is what located this.

Two lessons are now enforced in code. The string table must be read back **from the written
file** via `DT_STRTAB` (`_effective_strtab`), never from the pre-write section. And
`_self_verify_wbaes` compares every dynamic symbol name before and after and refuses to pack on
any change, resolving them the way bionic does (`_LoaderView`: program headers + `.dynamic`, never
section headers, since in this mode the `.dynstr` section header and `DT_STRTAB` legitimately
point at different bytes).

See [`wbaes-verification.md`](./wbaes-verification.md) for the six-phase verification
procedure, including a host round-trip that exercises every one of these contracts without a
device.

---

## 12. Key lifecycle — pack time and runtime, in both modes

Where the key comes from, how it is embedded, and how it is recovered at load. Everything below
is drawn from the code; §§4–5 and §11 argue *why* each step exists.

**There are two key paths, not three.** `--cipher xor` and `--cipher chacha20` share one path
completely — same `sopk_decinfo`, same whitening, same stub, same delivery; only the bulk
primitive differs. Call that **stub mode**. `--cipher wbaes` is the other. Both use the same
16-byte nonce block convention (12-byte ChaCha20 nonce ‖ 4-byte little-endian counter), so the
nonce is never a point of difference.

### 12a. Stub mode — pack time (how the key is embedded)

```
HOST — sopack pack --cipher chacha20|xor
─────────────────────────────────────────────────────────────────────────────────
  cipher.gen_key_nonce()
    ├── key32   = urandom(32)
    └── nonce16 = urandom(12) ‖ 00 00 00 00
           │
           ├──▶ apply_cipher(.text, key32, nonce16) ──▶ ciphertext, IN PLACE
           │                                            (stream cipher: same length)
           └──▶ sopk_decinfo, 128 B   (metadata.py ⇄ stub/decinfo.h)
                  magic 'SOPK' │ version │ cipher_id │ flags
                  delta_text │ text_size │ delta_init   ← signed, vs &g_decinfo
                  key32 │ nonce16 │ reserved[40]
                           │
           stub blob (with the record at decinfo_off) appended as one R+X PT_LOAD
                           │
           WHITEN AT REST — the record is masked in the shipped file:
             span = blob[decinfo_off-1024 : decinfo_off]      ← the stub's OWN
             wkey = cipher.whiten_key(span)                      code/rodata
             shipped128 = ChaCha20(record, wkey, WHITEN_NONCE)
                           │
           DT_INIT ──▶ stub entry     (hijack the existing one, or add in place)
```

The whitening key is **derived from the stub's own bytes**, so nothing key-shaped is stored to
carry it. Consequences the code enforces: the literal `SOPK` magic never appears in a packed
output (`_self_verify`), the injector patches at the known offset `seg_file_off + decinfo_off`
rather than scanning for magic, and it refuses to pack if `decinfo_off < WHITEN_SPAN` or the span
has fewer than 16 distinct bytes (a low-entropy span would mean a near-fixed whitening key).
`_self_verify` steps 5a/5b then re-read the output file and check the span is byte-identical to
what was whitened with, and that the shipped 128 bytes de-whiten back to the record.

**This is obfuscation, not secrecy.** The de-whitening key is computable from the shipped file
alone — an analyst who reverses the stub once recovers every key. Whitening raises that one-time
cost; it does not remove the ceiling (§9e).

### 12b. Stub mode — runtime (how the key is retrieved)

```
DEVICE — bionic runs DT_INIT before DT_INIT_ARRAY
─────────────────────────────────────────────────────────────────────────────────
  DT_INIT ──▶ sopk_entry
    │
    │  &g_decinfo reached PC-relatively (adr; -mcmodel=tiny) — no load bias needed
    │
    ├─ copy the shipped 128 bytes byte-by-byte into a STACK local raw[128]
    │     (the segment is R+X: de-whitening in place is not possible)
    ├─ wkey = sopk_whiten_key(&g_decinfo - 1024, 1024)   ← recomputed from own code
    └─ sopk_chacha20_apply(raw, 128, wkey, SOPK_WHITEN_NONCE)   ← self-inverse
           │
           ├─ parse raw[] into locals: key32, nonce16, cipher_id, flags,     [A:entry]
           │     delta_text, text_size, delta_init   ← plaintext key material
           │                                           lives HERE, one stack frame
           ├─ GATE: raw.magic == 'SOPK' && text_size != 0 ?
           │     no ──▶ [A:not-patched] ──▶ chain original init — FAIL OPEN
           │            (a tampered stub checksums differently → garbage → here)
           │
           └─ text = &g_decinfo + delta_text                                  [B]
                     │
                     └──▶ shared .text placement tail, §12e      [C][D][E][F]
                                │
                          chain original init via delta_init            [H:… OK]
```

### 12c. `wbaes` mode — pack time (how the key is embedded)

```
HOST — sopack pack --cipher wbaes            (provision.py:provision_text)
─────────────────────────────────────────────────────────────────────────────────
  gen_wbaes_params() ──▶ kek16, sk32, wrap_iv16, nonce16
  passphrase = token_hex(16)        seed = randbits(64)
           │
  kek16 ──▶ host wb_keygen --key <hex> --pass <p> --seed <n> --out blob
           │        │
           │        └──▶ sealed blob   (kek diffused into the table network;
           │                            NOT recoverable from the blob)
           │
  sk32 ──(AES-128-CTR under kek16)──▶ wrapped = wrap_iv ‖ aes128_ctr(sk, kek, iv)
           │                          48 B — byte-identical to wbc_wrap_key (§11d)
           │
  sk32 ──▶ apply_cipher(.text, sk32, nonce16) ──▶ ciphertext, IN PLACE
           │
  wpass = whiten_pass(passphrase, blob)     ← keyed off blob[:1024], the blob's own bytes
           │
  ✗ kek16 and sk32 are DISCARDED — never written to any output
           │
  sopk_rt_region v2 (96-B header + soname ‖ wpass ‖ blob)  ← rt_meta.py ⇄ sopk_rt.h
           │
  helper skeleton clone ── region appended as RO 16 KB-aligned PT_LOAD
           │              ── DT_SONAME := libsopk_rt_<target>.so
           │
  target: + DT_NEEDED libsopk_rt_<target>.so   (raw surgery; no DT_INIT touched)
  APK:    + lib/<abi>/libsopk_rt_<target>.so   (STORED, 16 KB)
```

What ships is the sealed blob, the wrapped session key, the nonce and the whitened passphrase.
**No shipped byte is a key that can be copied out and used** — the long-term key exists only as a
table network, and the session key only as ciphertext under it.

### 12d. `wbaes` mode — runtime (how the key is retrieved)

```
DEVICE — bionic runs a dependency's constructors BEFORE the dependent's init
─────────────────────────────────────────────────────────────────────────────────
  dlopen(target) ──▶ load libsopk_rt_<target>.so ──▶ sopk_rt_ctor
    │
    ├─ magic-scan own program headers for 'SRTR' + EXACT version  (§11e)
    │     no match ──▶ return — FAIL OPEN, SILENTLY
    │     (that silence is why _emit_helper demands the build marker at pack time)
    ├─ dl_iterate_phdr ──▶ target load base, matched by soname basename
    │
    ├─ wkey = sopk_whiten_key(region.blob, 1024) ─▶ ChaCha20(wpass) ──▶ pass
    │     (self-inverse; the same whiten_key/WHITEN_NONCE pair as stub mode uses)
    ├─ wbc_open(blob, pass) ──▶ ctx        Argon2id: ~230 ms, +64 MiB transient
    ├─ wbc_unwrap_key(ctx, wrapped) ──▶ sk32              2 white-box blocks, ~1.4 ms
    └─ wbc_close(ctx)                                     frees the ~400 KB VM image
           │
           │  sk32 is now an ORDINARY key in ORDINARY memory ── the one window a
           │  process dump can exploit without attacking the white-box (§11a)
           │
           ├─ text = target_base + region.text_rva
           ├─ mmap anon RW ‖ copy window ‖ ChaCha20(text…, sk32, nonce16)   ─┐
           ├─ wbc_wipe(sk32, 32)   ← window closed as soon as the decrypt is  │ §12e
           │                         done, BEFORE the pages are placed        │
           └─ mremap onto the original VA ‖ mprotect R-X ‖ icache flush     ─┘
```

The long-term key `kek` is **never reconstructed on device**, at any point. That is the entire
security difference between the two modes.

### 12e. The shared `.text` placement tail (identical in both modes)

Both decryptors end the same way, and the shape is forced by §2a — executing bytes the process
modified in a *file-backed* mapping is `execmod` (denied to apps); executing from *anonymous*
memory is `execmem` (allowed). Hence: never decrypt in place. The bracketed letters are stub
mode's logcat stages — the ones [`troubleshooting.md`](./troubleshooting.md) has you read.

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
| where the metadata lives | `sopk_decinfo`, 128 B, inside the R+X stub segment | `sopk_rt_region` v2, 96 B + tail, in the helper's RO segment |
| found at runtime by | known offset from `&g_decinfo` (PC-relative) | magic-scan of the helper's own phdrs |
| decryptor | freestanding stub, raw syscalls, no libc | normal `.so`, libc + C++ + libsodium |
| delivery | `DT_INIT` hijack or in-place add | `DT_NEEDED` on the target |
| works on `INIT_ARRAY`-only libs | yes, via the added `DT_INIT` | yes, for free |
| gate on bad metadata | `magic` / `text_size` check → chain original (fail open, logs `A:not-patched`) | exact region version → `abort()` (**fails closed**, reason in `sopk_fail_code`) |
| symbols / debug info shipped | n/a (flat blob, no symbol table) | none: the packer strips every non-ALLOC section |
| plaintext key in memory | the de-whitened stack copy, for one frame; **not** explicitly zeroed on exit | `sk32`, only between the unwrap and the explicit `wbc_wipe` |
| startup cost | ~15 ms per 5.5 MiB | ~245 ms per library (Argon2id dominates) |
| **long-term key recoverable from the shipped files?** | **yes** — reverse the stub once | **no** — never reconstructed on device |

For the SDK-boundary view of the `wbaes` column — which WBC calls and artifacts each step uses —
see [`wbc-integration.md`](./wbc-integration.md).
