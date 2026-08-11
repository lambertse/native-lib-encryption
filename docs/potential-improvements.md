# Potential improvements

Changes that are **understood and deliberately not done**, with the measurement that would
justify each. This is not a wishlist: an entry earns its place by naming the trade-off it loses
on today and the number that would flip it.

---

## 1. One KEK / one blob / one shared white-box provider (`--cipher wbaes`)

**Today.** Each protected library gets its own `libsopk_rt_<target>.so`, carrying its own sealed
blob. Each ships ~465 KB of white-box code plus a ~455 KB blob — **≈920 KB per library, STORED**
— and each runs its own `wbc_open`.

**What it would become.** One KEK per (pack, ABI), sealed once. **N thin per-target helpers**
(a few KB each, keeping today's `DT_NEEDED` trigger untouched) plus **one shared
`libsopk_wb.so`** per ABI that carries the blob and the whitened passphrase and exports a single
entry point the thin helpers call to unwrap their session key.

| protected libs per ABI | today | shared provider | delta |
|---|---|---|---|
| 1 | ~920 KB | ~920 KB + ~40 KB | **+40 KB (a regression)** |
| 2 | ~1.84 MB | ~1.0 MB | −840 KB |
| 5 | ~4.6 MB | ~1.12 MB | −3.5 MB |

**Why it is deferred.** The original motivation was startup: `wbc_open` cost 266 ms per library
on device. Sealing at the `light` KDF tier (wbcrypto 3.0.0) took that to ~1 ms, so the startup
argument is gone and what remains is **APK size** — which pays only at N ≥ 2 and is a small net
loss at N = 1. It is worth doing when a real app protects two or more libraries per ABI, and not
before.

**The shape to avoid.** Earlier drafts of `CLAUDE.md` named the fix as "one helper carrying N
regions". That **cannot work**: bionic runs a shared object's constructors exactly once, so a
helper shared by N targets only decrypts the libraries mapped when the *first* target loads. A
`libapp.so` that Flutter `dlopen`s later would never be decrypted, and the helper fails closed —
so it is an abort at best and a `SIGILL` inside the target at worst. Keeping the trigger 1:1 with
the target is the only thing that makes "is my target mapped when my ctor runs?" answerable. The
multi-library PASS check in `wbaes-verification.md` Phase 6 exists to catch exactly this.

**Cost to weigh against the size win.** A second hand-built artifact per ABI (Phase 4 becomes two
ordered links — the thin helper links *against* the provider, so its `DT_NEEDED` comes from the
provider's `DT_SONAME` and `-Wl,-soname` becomes load-bearing); a `REGION_VERSION` bump and a
second build marker; the first *exported* symbol in this mode's history, i.e. a new
static-analysis fingerprint; a relaxed (but also strengthened) `DT_NEEDED` guard; and a
pack-level closure invariant that no per-target verifier can check. One KEK per ABI also means
every library in that ABI shares one long-term key, where today each has its own.

**Measurement that would justify it.** Phase 6's `am start -W` TotalTime and
`dumpsys meminfo` peak RSS with N > 1 packed libraries, plus the resulting APK size.

---

## 2. Cache the shared provider's `wbc_ctx` instead of re-opening per call

Only relevant once improvement 1 exists. The provider would be **stateless** as designed: each
call does `wbc_open` → `wbc_unwrap_key` → `wbc_close`. Caching the context instead would save
`(N-1) × ~1 ms`.

**Why not.** It keeps the ~400 KB white-box table image resident — and dumpable — for the whole
process lifetime instead of a few milliseconds, widening the dynamic-analysis window that is
already this design's ceiling. It makes the provider stateful, and it needs explicit
serialisation, because upstream documents `wbc_ctx` as **not thread-safe** ("use one context per
thread, or serialize access"); the stateless version is correct under concurrent `dlopen` by
construction.

Worth recording honestly: caching violates **no** documented invariant. `sopk_rt.c`'s "close the
context immediately" comment is a footprint rationale, and `CLAUDE.md`'s bounded-exposure claim is
about the *session* key, not the context. It is a legitimate ~5-line change later — just not one
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

Note `--cipher wbaes` on x86_64 would also need a provider built for that ABI, which — if
improvement 1 lands with one KEK per ABI — must **not** share arm64's long-term key.

**Measurement that would justify it.** Not a measurement: a decision about whether the emulator
and x86_64-device install base matters for the app being packed.
