# Potential improvements

Changes that are **understood and deliberately not done**, with the measurement that would
justify each. This is not a wishlist: an entry earns its place by naming the trade-off it loses
on today and the number that would flip it.

An entry that *has* since been done stays here, marked **SHIPPED**, carrying its measured result
and the options it closed off - deleting it would invite the next reader to re-derive the same
dead ends.

---

## 1. One KEK / one blob / one shared white-box provider (`--cipher wbaes`) - **SHIPPED**

Landed as the **v3 provider split** (commit `ed4aa23`). This entry is kept for the measurement and
for the shapes it rules out; there is nothing left to do here.

**What ships now.** One long-term key (KEK) per **(pack, ABI)**, sealed once into one blob, carried
by **one `libsopk_wb.so` per ABI** - the shared provider, which has no constructor and exports the
single entry point `sopk_wb_k`. Each protected library still gets its own few-KB
`libsopk_rt_<target>.so`, which remains the 1:1 `DT_NEEDED` trigger and now carries only its own
`'SRTT'` region (wrapped session key, `.text` RVA/size, nonce, target soname). See
`docs/technical/ARCHITECTURE.md` §11b and `stub/sopk_wb.h`.

**Measured**, from a real 4-library arm64-v8a pack (`libapp`, `libZeroCore`, `libloadTA`,
`libvtap`):

| added entry | count | bytes each | total |
|---|---|---|---|
| `libsopk_wb.so` - provider skeleton 451,400 B + ~455 KB sealed blob | 1 | 936,072 | 936 KB |
| `libsopk_rt_<target>.so` - thin skeleton 8,848 B + region + 16 KB segment alignment | 4 | ~13,750 | ~55 KB |
| **added to the APK** | **5 entries** | | **~991 KB** |

Quote that against the right span. The pre-split APK shipped 4 × 3,710,000 B = **14.84 MB** of
helpers, but those were also **unstripped** (~2.7 MB of non-ALLOC sections each - see
`HARDENING.md` §Method 5), so 14.84 MB → 991 KB is **the split and the strip together**. The split
alone accounts for roughly **3.7 MB → 991 KB**.

**The N = 1 caveat is still live.** The win is per *additional* library; the first one still costs
~950 KB. Protecting a single library per ABI is the case where this mode's footprint is hardest to
justify, and `--cipher chacha20` (which adds no files at all, at the cost of shipping the key
whitened in the binary) remains the honest alternative there.

**The shape to avoid.** Earlier drafts of `CLAUDE.md` named the fix as "one helper carrying N
regions". That **cannot work**, and the reason still governs the design: bionic runs a shared
object's constructors exactly once, so a helper shared by N targets only decrypts the libraries
mapped when the *first* target loads. A `libapp.so` that Flutter `dlopen`s later would never be
decrypted, and the helper fails closed - an abort at best, a `SIGILL` inside the target at worst.
Keeping the trigger 1:1 with the target is the only thing that makes "is my target mapped when my
ctor runs?" answerable. Only the *provider* is shared, and it is not a trigger. The multi-library
PASS check in [`WBAES.md`](./WBAES.md) Phase 6 - exercise each library that loads at a *different*
time and confirm one `- OK` line each - exists to catch exactly this.

**What the split cost, for the record.** A second hand-built artifact per ABI (Phase 4 is two
ordered links - the thin helper links *against* the provider, so its `DT_NEEDED` comes from the
provider's `DT_SONAME` and `-Wl,-soname` is load-bearing); a `REGION_VERSION` bump to 3 and a
second build marker; the first *exported* symbol in this mode's history, i.e. a new static-analysis
fingerprint; a relaxed-but-also-strengthened `DT_NEEDED` guard; and a pack-level closure invariant
(`apk.py`) that no per-target verifier can check. One KEK per ABI also means every library in that
ABI shares one long-term key, where before the split each had its own.

### Where the floor is now, and why the last file cannot go

For N protected libraries in one ABI the APK gains **N + 1** entries. The only removable one is the
thin helper, worth ~13.7 KB each - **5.5%** of what the mode adds at N = 4. The remaining headroom
is file *count*, not bytes. Three ways to claim it, all rejected:

- **Fuse the helper and provider back into one artifact** (the pre-v3 shape). Costs N × 936 KB;
  at N = 4 that is a **+2.7 MB regression**. Only breaks even at N = 1.
- **Fuse only when a pack has one target per ABI.** Needs a third hand-built skeleton, a third
  build marker, a pre-pass over the APK to count targets before injection starts (`apk.py`
  currently streams the zip and discovers targets as it goes), and two runtime shapes to verify on
  device - for one file, in the one case where this mode is least worth using anyway.
- **Drop the thin helpers entirely**: inject the freestanding stub into each target and have it
  resolve `sopk_wb_k` in the provider at load. This is the only design that removes a whole
  artifact class, so it got a real look, and it is **blocked by the targets themselves**. It needs
  the target to gain both a `DT_NEEDED` (the provider) *and* an init hook, i.e. two `.dynamic`
  slots. Measured on the four libraries above: none has a `DT_INIT` (`libZeroCore` and
  `libflutter` have `INIT_ARRAY` only, which must never be hijacked - see `ARCHITECTURE.md` §5c),
  and each has exactly **one** trailing `DT_NULL` slot - already spent by `_add_needed_inplace`.
  The only way out is growing `.dynamic`, which is what spills 4 KB-aligned segments on tight libs
  (`libapp.so` by name) and breaks 16 KB loading. On top of that it would need a freestanding
  dynamic-symbol resolver in the stub (relocation-free, no `adrp`) and would flip the stub from
  fail-open to fail-closed. Large new risk in the component that crashes shipped apps, for 55 KB.

**Measurement that would reopen any of this.** A pack whose `.dynamic` slack and `DT_INIT`
availability differ from the above across every target, *plus* a case where the ~55 KB or the extra
entries actually matter - e.g. an APK-size budget the provider alone already fits inside.

---

## 2. Cache the shared provider's `wbc_ctx` instead of re-opening per call

Live option, still declined. The provider is **stateless** as designed: each call does `wbc_open`
→ `wbc_unwrap_key` → `wbc_close`. Caching the context instead would save `(N-1) × ~1 ms`.

**Why not.** It keeps the ~400 KB white-box table image resident - and dumpable - for the whole
process lifetime instead of a few milliseconds, widening the dynamic-analysis window that is
already this design's ceiling. It makes the provider stateful, and it needs explicit
serialisation, because upstream documents `wbc_ctx` as **not thread-safe** ("use one context per
thread, or serialize access"); the stateless version is correct under concurrent `dlopen` by
construction.

Worth recording honestly: caching violates **no** documented invariant. `sopk_wb.c`'s "close the
context immediately" comment is a footprint rationale, and `CLAUDE.md`'s bounded-exposure claim is
about the *session* key, not the context. It is a legitimate ~5-line change later - just not one
to make speculatively, and not for 1 ms per library.

A refcounted "close after the last expected target" variant does **not** survive its own
motivating case: a late-`dlopen`ed `libapp.so` keeps the context resident until then anyway.

**Measurement that would justify it.** N × per-library `open=` from Phase 6 tracing, weighed
against peak RSS on a 1–2 GB device.

---

## 3. Protect ABIs other than `arm64-v8a`

Only `arm64-v8a` is protected in practice, by deliberate scope choice. The other ABIs ship
cleartext `.text`, so an analyst after the *algorithm* reads the x86_64 build and never touches
the encryption. This is the single largest gap between what the tool does and what "the code is
encrypted" sounds like, and it is worth stating in any threat-model conversation.

Note `--cipher wbaes` on x86_64 also needs a provider built for that ABI. Since improvement 1
shipped there is one KEK per **(pack, ABI)**, so that provider must be sealed with its own key and
must **not** share arm64's long-term key.

**Measurement that would justify it.** Not a measurement: a decision about whether the emulator
and x86_64-device install base matters for the app being packed.
