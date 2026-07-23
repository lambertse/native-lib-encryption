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
| 2 | [No magic at rest](#method-2--no-magic-at-rest-patch-by-known-offset-not-by-scanning) — patch by known offset, verify the signpost is gone | ✅ shipped | Nothing to `grep` for; a pack-time guard proves it |
| 3 | [Section-header stripping](#method-3--section-header-stripping--researched-rejected-removed) | ❌ removed | Incompatible with Android 14+ bionic; also low value once (1) holds |
| 4 | [String hygiene](#method-4--string-hygiene-drop-the-packers-name) — obfuscate the `sopack` tag | ✅ shipped | Packer name absent from a `strings` dump |
| 5 | [Per-pack polymorphism](#method-5--per-pack-polymorphic-stub-obfuscate) — recompile a unique, obfuscated stub per pack | ✅ shipped (opt-in `--obfuscate`) | No universal unpacker; each app is a fresh, heavily-obfuscated reverse |

The contract version was bumped `SOPK_VERSION` 1 → 2 (`stub/decinfo.h` ⇄ `sopack/metadata.py`);
the 128-byte layout is unchanged — only its at-rest *representation* is whitened.

## Threat model, and the honest ceiling

- **In scope (what these techniques raise the cost of):** a *static* analyst reading the
  APK without running it — pulling the key out of the file, locating `.text`, fingerprinting
  the packer, and writing an offline decryptor.
- **Out of scope (always wins, by design):** a *dynamic* analyst. After load, plaintext
  `.text` lives in a readable `R-X` mapping; Frida or a `/proc/self/maps` dump recovers
  everything. This is obfuscation, not cryptographic protection.
- **The ceiling:** by default the decryption stub ships **byte-identical in every packed
  app** and contains the *complete* de-obfuscation recipe. So an analyst reverses the stub
  **once** and has a universal offline unpacker for every app at that sopack version. Methods
  1–4 raise the one-time reversing cost (grep-and-decrypt → a real RE session) but do **not**
  remove the ceiling. **Method 5 (`--obfuscate`) does** — it makes the stub per-pack unique,
  converting that one-time cost into a per-app cost — at the price of leaving the
  "clean, prebuilt-blob" envelope (it needs a compiler toolchain at pack time). It is opt-in
  and not the default. (The other ceiling-breaker, an external / server-derived key, is
  described in [`architecture.md`](./architecture.md) §9e.)

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

## Method 1 — Whiten the metadata record with a self-derived key

**File(s):** `sopack/cipher.py`, `stub/stub_cipher.h`, `stub/stub.c`, `sopack/elf_inject.py`,
`stub/decinfo.h`.

The 128-byte contract is unchanged; only its **at-rest representation** changes. The whole
record is XOR-masked with a ChaCha20 keystream whose **key is a checksum the stub computes
over its own code bytes** at load. No new secret is stored anywhere — the derivation lives
in the freestanding stub.

- The checksum runs over `SOPK_WHITEN_SPAN` (1024) bytes **immediately before** `g_decinfo`
  — real stub code/rodata the injector never rewrites.
- The span is anchored on `&g_decinfo` **only**. Anchoring on a function symbol
  (`&sopk_entry`) emits an unresolved arm64 relocation that the build guard rejects.
- `sopk_whiten_key` = FNV-1a-64 folded through splitmix64 to 32 bytes, so **every key byte
  depends on every span byte** (tamper anywhere → wrong key → garbage de-whiten).

**Derivation (must stay byte-identical on both sides).** Python — `sopack/cipher.py`:

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

def whiten(record: bytes, span: bytes) -> bytes:  # XOR keystream — its own inverse
    return apply_cipher(CIPHER_CHACHA20, record, whiten_key(span), WHITEN_NONCE)
```

C mirror — `stub/stub_cipher.h` (`sopk_whiten_key`, same constants; `SOPK_WHITEN_NONCE`).

**Pack time** — `sopack/elf_inject.py`, `inject_so()` / `_patch_decinfo()`:

```python
whiten_span = stub.blob[stub.decinfo_off - WHITEN_SPAN:stub.decinfo_off]
...
# write the finalized record at its KNOWN offset, then whiten in place:
f.seek(decinfo_off); f.write(whiten(info.pack(), span))
```

**Load time** — `stub/stub.c`, `sopk_entry()`:

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

- The constant `SOPK` magic **never appears in a packed output** — the grep-magic-read-key
  attack finds nothing.
- Recovering the key now requires reproducing the checksum+keystream derivation, i.e.
  reversing the stub.
- `magic`/`version` double as a **post-de-whiten integrity sentinel**: a tampered stub
  checksums differently → garbage de-whiten → magic mismatch → the stub **fails open**
  (chains the original init) rather than running still-encrypted code. (This anti-tamper
  property is a free side effect, not the goal — a dynamic analyst never patches the stub.)

---

## Method 2 — No magic at rest: patch by known offset, not by scanning

**File:** `sopack/elf_inject.py` (`_patch_decinfo`, `_self_verify`).

A corollary of Method 1, but a distinct decision. The v1 injector *located* the record by
scanning the output for the `SOPK` magic — which required the magic to survive into the
shipped file. The injector already knows the record's offset (`seg_file_off + decinfo_off`,
the value `_self_verify` always trusted), so it now patches there directly and asserts the
placeholder magic is present **first**, then whitens over it:

```python
f.seek(decinfo_off); placeholder = f.read(DECINFO_SIZE)
if placeholder[:len(_MAGIC_NEEDLE)] != _MAGIC_NEEDLE:
    raise InjectError("placeholder decinfo not at expected offset ...")
f.seek(decinfo_off); f.write(whiten(info.pack(), span))
```

`_self_verify` then asserts the signpost is gone — the `magic+version` needle appears
**nowhere** in the output — and that the shipped bytes de-whiten back to the packed record:

```python
if _MAGIC_NEEDLE in file_bytes:
    raise InjectError("decinfo magic still present in output — whitening did not take")
if whiten(stored, file_span) != info.pack():
    raise InjectError("whitened decinfo does not de-whiten to the packed record")
```

It also checks **span immutability** against the output file (the exact bytes the stub will
re-checksum at runtime), turning a would-be silent on-device key mismatch into a pack-time
error, and rejects a degenerate/low-entropy span that would weaken the key.

---

## Method 3 — Section-header stripping — RESEARCHED, REJECTED, REMOVED

Whitening hides the key but **not where `.text` is** — the ELF section header still gives
its name, offset and size. Detaching the section header table was implemented and tested,
then **removed** because it is incompatible with modern Android. The finding is kept here so
nobody re-attempts it.

> **⚠️ Confirmed incompatible with modern Android (bionic, Android 14+).** Two on-device
> tests (a Flutter app, Android 16 / target_sdk 36) killed it:
> 1. Zeroing `e_shoff`/`e_shnum`/`e_shstrndx` → linker: `"...libapp.so" has invalid
>    e_shstrndx` (bionic `VerifyElfHeader` requires `e_shstrndx != 0` and
>    `e_shentsize == sizeof(Shdr)`).
> 2. After fixing that (zero only `e_shoff`/`e_shnum`, keep `e_shstrndx`) → linker:
>    `"...libapp.so" has no section headers` — bionic `ReadSectionHeaders` rejects
>    `e_shnum == 0` outright. **bionic requires the section header table to exist.**
>
> In both cases `libapp.so` never loaded → Flutter `SIGSEGV` (missing Dart snapshot). glibc
> `dlopen` on the build host passed both files, so **host `dlopen` tests could not catch
> this** — the failure only appears on-device.

Beyond load-incompatibility it was also **low value**: once Method 1 holds and the key is
unrecoverable, knowing where `.text` lives buys an analyst nothing, and `.text`'s location is
derivable from the **un-strippable** program headers + `PT_DYNAMIC`/`.dynsym` anyway (bionic
needs those to load). So there is no clean, load-safe way to hide the code layout on Android,
and little to gain by doing so. The related "keep the table but blank the section names"
variant was also rejected: it still requires threading bionic's `.note.*`/MTE section lookups
without bricking, for the same near-zero benefit. Whitening is the load-safe hardening.

---

## Method 4 — String hygiene (drop the packer's name)

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

The staged `--log` debug labels (`A:entry`, …) remain in cleartext: they are generic
markers, emitted only under `--log`, and not a reliable packer fingerprint. Extending the
same helper to obfuscate them is straightforward if wanted.

---

## Method 5 — Per-pack polymorphic stub (`--obfuscate`)

**Files:** `sopack/cli.py` (`--obfuscate`), `sopack/obfuscate.py`, `sopack/apk.py`,
`stub/build_stubs.sh`, `stub/omvll_config.py`. **Opt-in, off by default.**

Methods 1–4 harden a stub that is still **identical across every app**, so one reverse
unpacks all. `--obfuscate` attacks that directly: it recompiles the stub **per pack** through
[O-MVLL](https://github.com/open-obfuscator/o-mvll) with a fresh random seed, so every packed
app ships a structurally unique, heavily-obfuscated stub. Reversing one app's stub yields no
reusable unpacker for the next — the one-time cost becomes a per-app cost.

Two levers combine:

- **Obfuscation** — control-flow flattening + mixed-boolean-arithmetic + control-flow
  breaking are applied to the decrypt/whiten crown-jewels (`sopk_entry`, which inlines
  `sopk_decrypt` and the whitening-key derivation, and `sopk_chacha20_apply`). This roughly
  doubles the instruction count and destroys the clean control-flow an analyst (or LLM) leans
  on. Measured elsewhere: CFF+MBA raises LLM analysis cost/time ~4–5×.
- **Polymorphism** — O-MVLL's RNG is seeded from `SOPK_SEED` (a fresh random value per pack),
  plus `shuffle_functions`. Two packs of the same library differ in ~85–90% of stub bytes,
  yet each is reproducible from its seed and still decrypts correctly.

**Only the reloc-free pass set is enabled**, because the stub is a flat **R+X** blob that
nothing links at load (the `execmem` design): no relocations, no runtime-mutable globals, no
`adrp`. `build_stubs.sh`'s existing guards remain the acceptance gate, and the excluded passes
were determined empirically against them:

| O-MVLL pass | usable in the freestanding stub? |
| ----------- | -------------------------------- |
| arithmetic (MBA), control-flow-flattening, control-flow-breaking, function-outline | ✅ reloc-free, no `adrp` |
| basic-block-duplicate | ❌ emits a call to libc `lrand48` (undefined in a `nostdlib` blob) |
| opaque-constants, indirect-branch/call | ❌ need writable globals / GOT the R+X blob can't host |

Scope and cost:

- Obfuscation is applied to **arm64-v8a only** — AArch32 exhausts its register file under the
  full pass set ("ran out of registers"), and O-MVLL does not target x86_64. Those ABIs get
  the normal (unobfuscated) stub.
- The O-MVLL plugin + a matching NDK are **x86_64-only and not bundled**; `--obfuscate`
  requires `ANDROID_NDK_HOME`, `OMVLL_PLUGIN`, `OMVLL_PYTHONPATH` in the environment and fails
  fast with an actionable message otherwise. The reproducible way to get them (incl. Rosetta
  emulation on Apple Silicon) is the image in [`assets/Dockerfile`](../assets/Dockerfile).
- Packing is slower (a full stub recompile per pack). The default path is untouched: no flag →
  the shipped prebuilt blob, no toolchain.

**Honest ceiling (unchanged framing):** this breaks *reuse*, not per-app reversibility. A
determined analyst with an LLM still reverses any single app's stub; the value is that the
cost no longer amortizes to ~0 across a version. Dynamic analysis still wins outright.

---

## How the hardening is verified

| Concern | Locked by |
| --- | --- |
| Python↔C whitening agree byte-for-byte | `tests/test_integration.py` aarch64 `dlopen` — only decrypts if both sides match (arm64 only; armv7/x86_64 are Python-KAT-only) |
| Python whitening doesn't silently change | `tests/test_metadata.py::test_whiten_key_kat` (pinned value) + self-inverse + tamper-sensitivity |
| Magic signpost gone; record round-trips | `_self_verify` (magic-needle absent, de-whiten == packed) + `b"SOPK" not in output` in integration tests |
| Span is real code the injector never rewrites | `_self_verify` span-immutability check + low-entropy guard in `inject_so` |
| End-to-end on real hardware | Confirmed on-device (Android 16, arm64): stub logs `native .text decrypted OK`, no SELinux `avc` denial, app runs |

Run: `python -m pytest tests/`. After **any** change to `stub/*.c`/`*.h`, rebuild the blobs
first: `bash stub/build_stubs.sh` (hard-fails on any relocation / undefined symbol / arm64
`adrp`).

## What is deliberately NOT hidden

- The appended **R+X `PT_LOAD` with `DT_INIT` pointing into it** is the packer's structural
  fingerprint and cannot be removed without breaking the mechanism. "Make key extraction
  hard" is achievable; "make sopack unfingerprintable" is not.
- **Where `.text` is.** Section-header stripping was removed (Method 3), and the location is
  derivable from program headers regardless. Harmless once the key is unrecoverable.
- Runtime plaintext (dynamic analysis) — see the threat model above.
