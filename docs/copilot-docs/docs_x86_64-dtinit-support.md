# Why x86_64 didn't work, and how `feature/dtinit-repurpose-hash` fixes it

> Scope: this analyzes the branch
> [`feature/dtinit-repurpose-hash`](https://github.com/lambertse/native-lib-encryption/tree/feature/dtinit-repurpose-hash)
> vs `master`. It explains the **root-cause limitation** that blocked x86_64
> libraries with no usable `DT_INIT`, the **new fallback design**, and the
> **verification gaps that still remain**.

---

## 1. TL;DR

`master` could only add a `DT_INIT` to a no-init library **one way**: overwrite
the `.dynamic` `DT_NULL` terminator in place and reuse the *following word* as the
new terminator. That trick silently assumes the word after the terminator is
**zero at runtime** — which is true on ARM but **architecturally false on
x86_64**. So any x86_64 `.so` with no usable `DT_INIT` (the shape of most
NDK C++ libs and Flutter's `libapp.so`) hit a hard `InjectError` on `master`.

The branch fixes this by turning the single in-place trick into a **three-tier
decision chain** — `inplace` → `repurpose-hash` → `grow-dynamic` — plus a new
`_self_verify` check that catches the one way the fallback could produce a
silently-unloadable library.

---

## 2. The root-cause limitation (why x86_64 specifically failed)

### 2.1 Recap: the in-place `DT_INIT` add

To run the stub first, sopack needs the library to have a `DT_INIT`. When there
isn't one, it must **add** one without growing `.dynamic` (growing it risks a
misaligned spilled segment / a relocated `PT_DYNAMIC` that loaders reject). The
`master` technique: overwrite the existing `DT_NULL` terminator with a `DT_INIT`
entry, and rely on **the next word being a `DT_NULL` at runtime** to act as the
new terminator.

### 2.2 The hidden assumption: "the next word is zero"

That only works if the word immediately after the terminator reads as `0`. On
PIC Android libraries the linker packs `.got`/`.got.plt` right after `.dynamic`,
so that word is the **reserved first GOT slot** — and whether it's zero is decided
by the **per-architecture psABI**, not by sopack:

- **AArch64 (`arm64-v8a`) and ARM32 (`armeabi-v7a`)** — the psABI leaves reserved
  `GOT[0]` **zero in the file** (the loader fills it at runtime). → slot reads `0`
  → valid new `DT_NULL` → **in-place works.**
- **x86-64 (and i386)** — the System V x86 psABI **mandates `GOT[0] = &_DYNAMIC`**.
  The static linker writes this **non-zero, non-relocated** value at link time; the
  loader never clears it. → slot is reliably non-zero → **can't be a `DT_NULL`** →
  **in-place is impossible.**

The branch's docs make this concrete: the same `libloadTA.so` packs fine on both
ARM targets but the slot after its terminator is `0x0` on ARM and `&_DYNAMIC`
(`0x4d18`) on x86_64.

> **This is inherent to the x86 GOT ABI**, not a quirk of one library. On
> `master`, `_add_dtinit_inplace()` raised
> `"slot after .dynamic terminator is file-backed with a non-DT_NULL tag; cannot
> add DT_INIT in place"` — a hard failure for essentially every no-`DT_INIT`
> x86_64 library.

---

## 3. What the branch changes

### 3.1 `_add_dtinit_inplace()` → `_add_dtinit()`: a 3-tier chain

The renamed function now **returns the strategy it used** and no longer treats an
unusable slot as fatal — it steps down the chain (`sopack/elf_inject.py`):

1. **`DT_INIT-inplace`** *(unchanged behavior)* — terminator slot is a runtime
   `DT_NULL` (ARM libs, and x86_64 libs that happen to have a zero slot): overwrite
   the terminator, use the following zero word as the new terminator, extend
   `PT_DYNAMIC`/`.dynamic`/`SHT_DYNAMIC`.

2. **`DT_INIT-repurpose-hash`** *(new)* — slot unusable, **but** the library has
   **both** `DT_HASH` and `DT_GNU_HASH`: overwrite the **redundant `DT_HASH`**
   entry's tag/value with `DT_INIT`. The terminator and entry count are untouched,
   so **no `PT_DYNAMIC`/section resize** is needed. Crucially **guarded on
   `DT_GNU_HASH` being present** — a *SysV-hash-only* lib would be bricked, so that
   case is refused and falls through.

   ```python name=sopack/elf_inject.py url=https://github.com/lambertse/native-lib-encryption/blob/feature/dtinit-repurpose-hash/sopack/elf_inject.py
   if has_gnu_hash and hash_slot is not None:
       struct.pack_into(DPACK, buf, hash_slot, _DT_INIT, entry_rva)
       return "DT_INIT-repurpose-hash"
   raise _NeedGrow(...)   # neither inplace nor repurpose applies
   ```

3. **`DT_INIT-grow-dynamic`** *(new, last resort)* — slot unusable *and* no
   redundant `DT_HASH` (a gnu-hash-only or sysv-hash-only lib): `_add_dtinit()`
   raises the internal `_NeedGrow` signal; `inject_so` catches it and **re-injects
   from scratch with `grow=True`**, adding a **real `DT_INIT` via LIEF**.

### 3.2 The retry wrapper

`inject_so` was split so the grow path is a clean second attempt:

```python name=sopack/elf_inject.py url=https://github.com/lambertse/native-lib-encryption/blob/feature/dtinit-repurpose-hash/sopack/elf_inject.py
def inject_so(...):
    try:
        return _inject_once(..., grow=False)
    except _NeedGrow:
        return _inject_once(..., grow=True)
```

In `grow=True`, LIEF adds the `DT_INIT` entry **before** the stub segment is
appended, so `entry_rva` is computed against the already-grown `.dynamic`, then the
entry's value is fixed up layout-neutrally.

### 3.3 New self-verify guard: `PT_DYNAMIC` must stay in a writable `PT_LOAD`

The grow fallback can make LIEF **relocate `.dynamic`** (when it has no trailing
slack). bionic rejects a `.dynamic` that isn't inside a loaded, **writable** range,
and the existing round-trip / `DT_INIT==entry` checks are blind to it. So the
branch adds an explicit containment assertion (`_self_verify`, now taking `abi`):

```python name=sopack/elf_inject.py url=https://github.com/lambertse/native-lib-encryption/blob/feature/dtinit-repurpose-hash/sopack/elf_inject.py
if host is None:
    raise InjectError(
        f"PT_DYNAMIC (0x{dv:x}+0x{dsz:x}) is not contained in a writable PT_LOAD "
        f"after {strategy} — the loader would reject this library")
```

This makes a future "no-slack lib that LIEF mis-lays" fail **loudly at pack time**
instead of silently on-device. `inplace`/`repurpose-hash` leave `.dynamic` in
place and pass trivially.

### 3.4 16 KB congruence now asserted for arm64 only

Related cleanup: the per-segment 16 KB congruence check in `_self_verify` is now
gated to `abi == "arm64-v8a"`. Rationale in the branch: 16 KB-page hardware is
arm64-exclusive; those devices can't run `armeabi-v7a` at all and no shipping
x86_64 device uses 16 KB pages — so enforcing congruence against an x86_64/armv7
input's pre-existing 4 KB-aligned LOAD segments would abort a pack over a device
class that can't exist. The injected segment itself is still `SEGMENT_ALIGN`-aligned
on every ABI.

### 3.5 New tests

`tests/test_integration.py` adds three fixtures using `--hash-style={both,sysv,gnu}`
and a `_stage_with_unusable_slot()` helper that forces the x86_64 condition (writes a
non-zero sentinel after the terminator) even on an aarch64 host:

- `test_repurpose_hash_when_slot_unusable` — both hashes present → strategy is
  `DT_INIT-repurpose-hash`, `DT_INIT` points at the stub, `DT_GNU_HASH` survives.
- `test_repurpose_guard_refuses_without_gnu_hash` — sysv-hash-only → raises
  `_NeedGrow` (must **not** repurpose the only hash).
- `test_grow_dynamic_fallback_runs` — gnu-hash-only → `DT_INIT-grow-dynamic`,
  then `dlopen` + call proves the stub decrypted `.text`.

---

## 4. Decision chain, at a glance

```
no usable DT_INIT?
   │
   ├─ slot after DT_NULL == 0 at runtime? ─ yes ─► DT_INIT-inplace      (ARM; lucky x86_64)
   │                                         no
   ├─ has BOTH DT_HASH and DT_GNU_HASH?   ─ yes ─► DT_INIT-repurpose-hash (typical x86_64)
   │                                         no  (sysv-only would brick → skip)
   └─ else (gnu-only / sysv-only) ───────────────► DT_INIT-grow-dynamic  (LIEF adds real DT_INIT)
                                                       └─ guarded by PT_DYNAMIC-containment self-verify
```

---

## 5. Enhancements delivered

| Area | `master` | branch |
|------|----------|--------|
| No-init x86_64 lib | **Hard `InjectError`** | Handled via `repurpose-hash` / `grow-dynamic` |
| Add-`DT_INIT` strategies | 1 (`inplace`) | 3 (`inplace`, `repurpose-hash`, `grow-dynamic`) |
| Grow safety | n/a | New `PT_DYNAMIC`-in-writable-`PT_LOAD` self-verify check |
| Hash safety | n/a | Repurpose **guarded on `DT_GNU_HASH`**; sysv-only never bricked |
| 16 KB check | all ABIs | arm64-only (correct scoping) |
| Tests | ARM shapes only | + hash-style fixtures forcing the x86_64 condition |

---

## 6. Remaining limitations (be honest before shipping x86_64)

Straight from the branch's own updated `docs/architecture.md §8` and `§5c`:

1. **No real Android x86_64 bionic run.** All new coverage is under **host glibc**
   (`dlopen`) or **static** assertions:
   - `grow-dynamic` is *run* under host glibc (dlopen + call, incl. a forced
     `PT_DYNAMIC`-spill case).
   - `repurpose-hash` is verified **statically** (strategy + self-verify) and by
     **analogy** to the grow dlopen — its own test *can't* `dlopen`, because the
     forced unusable-slot sentinel corrupts the image.
   - **Neither is exercised on an Android x86_64 bionic emulator.** Do that before
     shipping x86_64 output.
2. **bionic is stricter than glibc.** The same class of assumption gap caused the
   original `libflutter.so` `DT_INIT_ARRAY` SIGILL and the section-strip rejection;
   glibc passing is necessary but not sufficient.
3. **The unusable-slot condition is *forced*, not natural, in tests.** The aarch64
   fixtures inject a sentinel to simulate x86_64's `GOT[0]=&_DYNAMIC`; a genuine
   x86_64 build is still the real proof.
4. **armv7 unchanged and still unproven on-device** — this branch is about x86_64;
   the 32-bit ARM `mmap2`/`cacheflush` paths remain validated only under qemu smoke
   tests.

**Recommended gate before enabling x86_64 in production:** run the three new tests'
assertions (especially `repurpose-hash` and `grow-dynamic`) against a **real
Android x86_64 emulator/device**, watching `adb logcat` for `avc` denials and the
`--log` decrypt confirmation, and confirm bionic accepts both the repurposed-hash
`.dynamic` and any LIEF-grown `.dynamic`.