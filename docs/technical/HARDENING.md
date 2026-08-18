# Static-analysis hardening

This document lists **every technique sopack uses to make static analysis of a packed
`.so` harder**, with the code that implements each. It is the focused companion to
[`architecture.md`](./architecture.md) §9; read that for the surrounding design.

## At a glance

The v2 enhancement moves the decryption key from a plaintext, magic-tagged record to a form
an analyst can only recover by reverse-engineering the stub. Confirmed end-to-end on-device
(Android 16, arm64, a real Flutter app): the packed lib decrypts and the app runs, with no
SELinux `avc` denial, and neither `SOPK` nor `sopack` appears in the shipped lib.

| # | Technique | Status | Effect on a static analyst |
| - | --------- | ------ | -------------------------- |
| 1 | [Whiten the metadata record](#method-1--whiten-the-metadata-record-with-a-self-derived-key) with a key derived from the stub's own code | ✅ shipped (device-confirmed) | No key/magic in the file; recovery now requires reversing the stub |
| 2 | [No magic at rest](#method-2--no-magic-at-rest-patch-by-known-offset-not-by-scanning) - patch by known offset, verify the signpost is gone | ✅ shipped | Nothing to `grep` for; a pack-time guard proves it |
| 3 | [Section-header stripping](#method-3--section-header-stripping--researched-rejected-removed) | ❌ removed | Incompatible with Android 14+ bionic; also low value once (1) holds |
| 4 | [String hygiene](#method-4--string-hygiene-drop-the-packers-name) - obfuscate the `sopack` tag | ✅ shipped | Packer name absent from a `strings` dump |
| 5 | [Strip the wbaes helper](#method-5--strip-the-wbaes-helper-symbols-dwarf-host-paths) - symbols, DWARF, host paths | ✅ shipped (host-verified) | Removes the single largest shortcut: named functions and the SDK's whole API |

The contract version was bumped `SOPK_VERSION` 1 → 2 (`stub/decinfo.h` ⇄ `sopack/metadata.py`);
the 128-byte layout is unchanged - only its at-rest *representation* is whitened.

## Threat model, and the honest ceiling

- **In scope (what these techniques raise the cost of):** a *static* analyst reading the
  APK without running it - pulling the key out of the file, locating `.text`, fingerprinting
  the packer, and writing an offline decryptor.
- **Out of scope (always wins, by design):** a *dynamic* analyst. After load, plaintext
  `.text` lives in a readable `R-X` mapping; Frida or a `/proc/self/maps` dump recovers
  everything. This is obfuscation, not cryptographic protection.
- **The ceiling:** the decryption stub ships **byte-identical in every packed app** and
  contains the *complete* de-obfuscation recipe. So an analyst reverses the stub **once**
  and has a universal offline unpacker for every app at that sopack version. The measures
  below raise the one-time reversing cost (grep-and-decrypt → a real RE session); they do
  **not** remove the ceiling. Two ways to break it (polymorphic per-pack stub; external /
  server-derived key) are described in [`architecture.md`](./architecture.md) §9e - both
  leave the "clean, prebuilt-blob" architecture and are not the default.

### What the old (v1) layout gave away

The v1 record was a fixed 128-byte `sopk_decinfo` starting with the constant magic `SOPK`
(`0x4B504F53`). Extraction was a ~10-line offline script:

```
grep the file for "SOPK"  ->  offset of the struct
read key[32], nonce[16], cipher_id at fixed field offsets
read delta_text / text_size  ->  exactly where .text is and how big
decrypt .text with (key, nonce)   # never runs the app
```

The magic and the plaintext key were two crown-jewel signposts. Everything below removes
or obscures them.

---

## Method 1 - Whiten the metadata record with a self-derived key

**File(s):** `sopack/cipher.py`, `stub/stub_cipher.h`, `stub/stub.c`, `sopack/elf_inject.py`,
`stub/decinfo.h`.

The 128-byte contract is unchanged; only its **at-rest representation** changes. The whole
record is XOR-masked with a ChaCha20 keystream whose **key is a checksum the stub computes
over its own code bytes** at load. No new secret is stored anywhere - the derivation lives
in the freestanding stub.

- The checksum runs over `SOPK_WHITEN_SPAN` (1024) bytes **immediately before** `g_decinfo`
  - real stub code/rodata the injector never rewrites.
- The span is anchored on `&g_decinfo` **only**. Anchoring on a function symbol
  (`&sopk_entry`) emits an unresolved arm64 relocation that the build guard rejects.
- `sopk_whiten_key` = FNV-1a-64 folded through splitmix64 to 32 bytes, so **every key byte
  depends on every span byte** (tamper anywhere → wrong key → garbage de-whiten).

**Derivation (must stay byte-identical on both sides).** Python - `sopack/cipher.py`:

```python
def whiten_key(span: bytes) -> bytes:
    h = 0xcbf29ce484222325                        # FNV-1a-64 offset basis
    for b in span:
        h = ((h ^ b) * 0x00000100000001b3) & _MASK64   # FNV prime
    out = bytearray(); s = h
    for _ in range(4):                            # splitmix64 -> 32 bytes
        s = (s + 0x9e3779b97f4a7c15) & _MASK64
        z = s
        z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & _MASK64
        z = z ^ (z >> 31)
        out += struct.pack("<Q", z & _MASK64)
    return bytes(out)

def whiten(record: bytes, span: bytes) -> bytes:  # XOR keystream - its own inverse
    return apply_cipher(CIPHER_CHACHA20, record, whiten_key(span), WHITEN_NONCE)
```

C mirror - `stub/stub_cipher.h` (`sopk_whiten_key`, same constants; `SOPK_WHITEN_NONCE`).

**Pack time** - `sopack/elf_inject.py`, `inject_so()` / `_patch_decinfo()`:

```python
whiten_span = stub.blob[stub.decinfo_off - WHITEN_SPAN:stub.decinfo_off]
...
# write the finalized record at its KNOWN offset, then whiten in place:
f.seek(decinfo_off); f.write(whiten(info.pack(), span))
```

**Load time** - `stub/stub.c`, `sopk_entry()`:

```c
uint8_t raw[sizeof(sopk_decinfo)];
const volatile uint8_t *rp = (const volatile uint8_t *)src;
for (size_t i = 0; i < sizeof(raw); i++) raw[i] = rp[i];

const uint8_t *span = (const uint8_t *)src - SOPK_WHITEN_SPAN;   /* window before g_decinfo */
uint8_t wkey[32];
sopk_whiten_key(span, SOPK_WHITEN_SPAN, wkey);
sopk_chacha20_apply(raw, sizeof(raw), wkey, SOPK_WHITEN_NONCE);  /* de-whiten */

const sopk_decinfo *di = (const sopk_decinfo *)raw;
uint32_t magic = di->magic;   /* reappears ONLY after a correct de-whiten */
...
if (magic != SOPK_MAGIC || text_size == 0) goto chain;   /* fail open */
```

**What it buys**

- The constant `SOPK` magic **never appears in a packed output** - the grep-magic-read-key
  attack finds nothing.
- Recovering the key now requires reproducing the checksum+keystream derivation, i.e.
  reversing the stub.
- `magic`/`version` double as a **post-de-whiten integrity sentinel**: a tampered stub
  checksums differently → garbage de-whiten → magic mismatch → the stub **fails open**
  (chains the original init) rather than running still-encrypted code. (This anti-tamper
  property is a free side effect, not the goal - a dynamic analyst never patches the stub.)

---

## Method 2 - No magic at rest: patch by known offset, not by scanning

**File:** `sopack/elf_inject.py` (`_patch_decinfo`, `_self_verify`).

A corollary of Method 1, but a distinct decision. The v1 injector *located* the record by
scanning the output for the `SOPK` magic - which required the magic to survive into the
shipped file. The injector already knows the record's offset (`seg_file_off + decinfo_off`,
the value `_self_verify` always trusted), so it now patches there directly and asserts the
placeholder magic is present **first**, then whitens over it:

```python
f.seek(decinfo_off); placeholder = f.read(DECINFO_SIZE)
if placeholder[:len(_MAGIC_NEEDLE)] != _MAGIC_NEEDLE:
    raise InjectError("placeholder decinfo not at expected offset ...")
f.seek(decinfo_off); f.write(whiten(info.pack(), span))
```

`_self_verify` then asserts the signpost is gone - the `magic+version` needle appears
**nowhere** in the output - and that the shipped bytes de-whiten back to the packed record:

```python
if _MAGIC_NEEDLE in file_bytes:
    raise InjectError("decinfo magic still present in output - whitening did not take")
if whiten(stored, file_span) != info.pack():
    raise InjectError("whitened decinfo does not de-whiten to the packed record")
```

It also checks **span immutability** against the output file (the exact bytes the stub will
re-checksum at runtime), turning a would-be silent on-device key mismatch into a pack-time
error, and rejects a degenerate/low-entropy span that would weaken the key.

---

## Method 3 - Section-header stripping - RESEARCHED, REJECTED, REMOVED

Whitening hides the key but **not where `.text` is** - the ELF section header still gives
its name, offset and size. Detaching the section header table was implemented and tested,
then **removed** because it is incompatible with modern Android. The finding is kept here so
nobody re-attempts it.

> **⚠️ Confirmed incompatible with modern Android (bionic, Android 14+).** Two on-device
> tests (a Flutter app, Android 16 / target_sdk 36) killed it:
> 1. Zeroing `e_shoff`/`e_shnum`/`e_shstrndx` → linker: `"...libapp.so" has invalid
>    e_shstrndx` (bionic `VerifyElfHeader` requires `e_shstrndx != 0` and
>    `e_shentsize == sizeof(Shdr)`).
> 2. After fixing that (zero only `e_shoff`/`e_shnum`, keep `e_shstrndx`) → linker:
>    `"...libapp.so" has no section headers` - bionic `ReadSectionHeaders` rejects
>    `e_shnum == 0` outright. **bionic requires the section header table to exist.**
>
> In both cases `libapp.so` never loaded → Flutter `SIGSEGV` (missing Dart snapshot). glibc
> `dlopen` on the build host passed both files, so **host `dlopen` tests could not catch
> this** - the failure only appears on-device.

Beyond load-incompatibility it was also **low value**: once Method 1 holds and the key is
unrecoverable, knowing where `.text` lives buys an analyst nothing, and `.text`'s location is
derivable from the **un-strippable** program headers + `PT_DYNAMIC`/`.dynsym` anyway (bionic
needs those to load). So there is no clean, load-safe way to hide the code layout on Android,
and little to gain by doing so. The related "keep the table but blank the section names"
variant was also rejected: it still requires threading bionic's `.note.*`/MTE section lookups
without bricking, for the same near-zero benefit. Whitening is the load-safe hardening.

**Do not read this section as a rejection of stripping in general.** What failed was removing the
section *header table* (`e_shoff`/`e_shnum`). Removing individual non-`SHF_ALLOC` **sections** -
`.symtab`, `.strtab`, `.comment`, `.debug_*` - is a different operation: the table survives with a
valid `e_shstrndx` and `.shstrtab`, which is exactly what bionic checks. That is Method 5, and it
is shipped.

---

## Method 4 - String hygiene (drop the packer's name)

**File:** `stub/stub_log.h`, `stub/stub.c`.

`strings` scans raw bytes, so it finds a packer's name whether or not the section table is
present. The one constant that named this packer was the logcat **tag** `"sopack"`. It is
stored XOR-obfuscated and decoded on-stack, so the name never appears in a packed lib:

```c
#define SOPK_TAG_XOR 0x5a
static const unsigned char SOPK_TAG_OBF[] = { 0x29,0x35,0x2a,0x3b,0x39,0x31 }; /* "sopack" */

static inline void sopk_logcat(const char *msg) {
    char tag[sizeof(SOPK_TAG_OBF) + 1];
    for (unsigned i = 0; i < sizeof(SOPK_TAG_OBF); i++)
        tag[i] = (char)(SOPK_TAG_OBF[i] ^ SOPK_TAG_XOR);
    tag[sizeof(SOPK_TAG_OBF)] = 0;
    ...
}
```

The staged debug labels (`A:entry`, …) remain in cleartext: they are generic
markers, emitted only under `logging.stub-log`, and not a reliable packer fingerprint. Extending the
same helper to obfuscate them is straightforward if wanted.

---

## Method 5 - Strip the wbaes helper (symbols, DWARF, host paths)

Applies to `cipher: wbaes` only: the injected helper `libsopk_rt_<target>.so` is a normal,
dynamically-linked `.so`, so unlike the freestanding stub blob it *has* a symbol table to leak.

A static-analysis report on a shipped APK reconstructed the entire design - key hierarchy, load
flow, region layout - in about an hour, and said plainly what made that possible: the helper
shipped unstripped. It carried a 4,145-entry `.symtab` naming `sopk_rt_ctor`, `sopk_chacha20_apply`,
`self_cb`, `tgt_cb`, `SOPK_WHITEN_NONCE`, `sopk_rt_build_marker`, the entire `wbc_*` API and all 21
VM handlers, plus `STT_FILE` entries naming the translation units (`sopk_rt.c`, `wbcrypto.cpp`,
`vm.cpp`, `softaes.c`, `trusted_storage.cpp`) - and ~2.3 MB of DWARF, in which the absolute host
build paths disclosed a developer username and pinned the vendored libsodium version for CVE
matching. Naming is most of reversing; this handed it over.

**What ships now.** Every non-`SHF_ALLOC` section is removed, keeping only `.shstrtab`:

| Removed | Why it mattered |
| --- | --- |
| `.symtab`, `.strtab` | every internal function and variable name |
| `.debug_*` (six sections) | source-level structure, and the host build paths |
| `.comment` | exact compiler build string |

On the reference arm64 helper that is 2,785,024 of 3,250,832 bytes - 3.2 MB → ~470 KB, and about
11 MB across a four-library APK. The dropped section *names* go too, so `.debug_info` does not
linger in `.shstrtab` advertising what was taken out.

**Two layers, because the skeleton is hand-built outside the repo.** `scripts/build_wbaes.sh`
passes `-g0 -ffile-prefix-map=… ` and runs `llvm-strip --strip-all` (Phase 4); and
`elf_inject.py:_emit_helper` strips whatever still arrives, warning that it had to.
`_self_verify_wbaes` then asserts the result. The build flag alone was not enough - a correct
`--release` path already existed when the unstripped helper shipped. Nothing refused one.

**Why raw ELF surgery rather than LIEF here.** Two measured reasons: LIEF re-creates
`.symtab`/`.strtab` from its own symbol model on `write()`, so removing them through LIEF does not
remove them from the output; and LIEF keeps retained sections at their original file offsets, so
deleting 2.7 MB from the middle of the file leaves a 2.7 MB hole of zero padding rather than a
smaller file - which a STORED APK entry still carries in full. `_strip_nonalloc` therefore zeroes
the dropped ranges, rebuilds `.shstrtab` from the surviving names, remaps every `sh_link`/`sh_info`
index, and moves `.shstrtab` plus the section header table down past the last mapped byte before
truncating. Nothing the loader maps is moved, so the 16 KB segment congruence LIEF established is
undisturbed.

**This is not Method 3.** The section header table survives with a valid `e_shstrndx` and a real
`.shstrtab`; only its non-ALLOC entries are gone. See the note at the end of Method 3.

**Not hidden by this.** The 8 build-marker bytes stay (they live in `.rodata`, and being a stable
recognisable constant is the marker's whole job as the stale-skeleton guard), and so do the `SRTR`
magic and the section-less RO `PT_LOAD` that carries it. Those remain reliable detection
signatures, per "What is deliberately NOT hidden" below.

---

## How the hardening is verified

| Concern | Locked by |
| --- | --- |
| Python↔C whitening agree byte-for-byte | `tests/test_integration.py` aarch64 `dlopen` - only decrypts if both sides match (arm64 only; armv7/x86_64 are Python-KAT-only) |
| Python whitening doesn't silently change | `tests/test_metadata.py::test_whiten_key_kat` (pinned value) + self-inverse + tamper-sensitivity |
| Magic signpost gone; record round-trips | `_self_verify` (magic-needle absent, de-whiten == packed) + `b"SOPK" not in output` in integration tests |
| Span is real code the injector never rewrites | `_self_verify` span-immutability check + low-entropy guard in `inject_so` |
| End-to-end on real hardware | Confirmed on-device (Android 16, arm64): stub logs `native .text decrypted OK`, no SELinux `avc` denial, app runs |
| Stripping keeps the helper loadable | `tests/test_wbaes.py::test_a_stripped_library_still_loads` - strips a host `.so` and `dlopen`s it in a fresh process. Host glibc is **not** bionic (see Method 3), so this proves the surgery is sane, not that it is Android-safe; Phase 6 on device is still required |
| Nothing strippable survives a pack | `test_strip_removes_debug_and_symbols_but_keeps_the_loader_view`, `test_emitted_helper_is_stripped_and_keeps_its_dynamic_symbols`, and `_self_verify_wbaes` |
| A tracing or symbol-leaking helper cannot be packed | `test_emit_helper_refuses_a_tracing_skeleton`, `test_emit_helper_refuses_a_skeleton_that_reexports_the_white_box` |

Run: `python -m pytest tests/`. After **any** change to `stub/*.c`/`*.h`, rebuild the blobs
first: `bash stub/build_stubs.sh` (hard-fails on any relocation / undefined symbol / arm64
`adrp`).

## What is deliberately NOT hidden

- The appended **R+X `PT_LOAD` with `DT_INIT` pointing into it** is the packer's structural
  fingerprint and cannot be removed without breaking the mechanism. "Make key extraction
  hard" is achievable; "make sopack unfingerprintable" is not.
- **Where `.text` is.** Section-header stripping was removed (Method 3), and the location is
  derivable from program headers regardless. Harmless once the key is unrecoverable.
- Runtime plaintext (dynamic analysis) - see the threat model above.
- **The wbaes helper's `SRTR` magic in a section-less read-only `PT_LOAD`**, and the
  `libsopk_rt_<target>.so` name in the target's `DT_NEEDED`. Both are one-line detection
  signatures, and neither can be removed while the helper still has to find its own region and be
  loaded by name. Renaming buys an analyst-minute, not security.
- **That only `arm64-v8a` is protected.** `armeabi-v7a`/`x86`/`x86_64` ship cleartext `.text`, so
  an analyst who wants the *algorithm* reads another ABI's build and never touches the encryption.
  This is a deliberate scope decision: the protection raises device-level attack cost on arm64, it
  does not keep algorithms secret.
