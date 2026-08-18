# 16 KB pages: why a 4 KB-aligned library cannot be packed

Reference for the pack-time error

```
warning: skipping lib/arm64-v8a/libvostestapp.so: in.so is not 16 KB-page compatible to
begin with: its own LOAD segments already violate the rule (...) before any injection, so
the packed output cannot either.
```

and for the general question *"how much of the 16 KB rule is sopack's own limitation?"*

---

## 0. The short answer: two different facts, only one of them ours

| | Whose |
|---|---|
| `libvostestapp.so` cannot be loaded on a 16 KB-page kernel, packed or unpacked | **the library's** - it was linked without `-Wl,-z,max-page-size=16384` |
| sopack **refuses to pack it at all**, even for a 4 KB-only shipment | **ours** - the guard has no escape hatch (§7) |

The refusal is the part worth arguing about, and it is a real gap. The incompatibility is not:
the same APK's sibling library is already correct.

```
$ readelf -lW lib/arm64-v8a/libvosWrapperEx.so | awk '/LOAD/{print $1,$2,$3,$NF}'
LOAD 0x000000 0x0000000000000000 0x4000      ← 16 KB aligned, congruent
LOAD 0x189fa0 0x000000000018dfa0 0x4000

$ readelf -lW lib/arm64-v8a/libvostestapp.so | awk '/LOAD/{print $1,$2,$3,$NF}'
LOAD 0x000000 0x0000000000000000 0x1000      ← 4 KB
LOAD 0x07d1b0 0x000000000007e1b0 0x1000
LOAD 0x0816e0 0x00000000000836e0 0x1000
```

One module in the build has the flag and the other does not. Since 1 Nov 2025 Play requires
64-bit apps to support 16 KB pages, so this APK is already non-compliant before sopack touches
it - the packer is the messenger, not the cause. The fix is one link flag in the module that
builds `libvostestapp.so`, and it also fixes the app's Play compliance.

> Which mode fired: the wording *"is not 16 KB-page compatible to begin with"* exists only in
> `_assert_16k_and_no_textrel` (`elf_inject.py:1066`), which is reached only from the **wbaes**
> verifiers. The default `chacha20` path refuses the same library for the same reason, but with
> a bare `LOAD seg align 4096 not multiple of 16384` and no mention of the input (§7).

---

## 1. What a page-size mismatch actually is

An ELF `PT_LOAD` is an instruction to the loader: *map `p_filesz` bytes from file offset
`p_offset` at virtual address `p_vaddr`, with permissions `p_flags`*. `mmap` can only do that at
**kernel page granularity** - the offset must be a multiple of the page size, and the mapping
covers whole pages. So a segment is mappable only if

```
p_vaddr ≡ p_offset  (mod PAGE_SIZE)
```

`p_align` is the linker's promise about which page sizes that congruence holds for. `-z
max-page-size=16384` makes the linker pad file offsets and space virtual addresses so the
promise holds at 16 KB; the default on many toolchains is still 4 KB.

Here are the failing library's three segments with the two skews computed:

| phdr | perms | `p_offset` | `p_vaddr` | end vaddr | `vaddr−offset` | mod 4 KB | mod 16 KB |
|---|---|---|---|---|---|---|---|
| LOAD[1] | `R E` | `0x0` | `0x0` | `0x7d1b0` | `0` | 0 ✓ | 0 ✓ |
| LOAD[2] | `RW` | `0x7d1b0` | `0x7e1b0` | `0x826e0` | `0x1000` | 0 ✓ | **`0x1000` ✗** |
| LOAD[3] | `RW` | `0x816e0` | `0x836e0` | `0x84680` | `0x2000` | 0 ✓ | **`0x2000` ✗** |

On a 4 KB kernel every skew is a whole number of pages and all three map. On a 16 KB kernel
LOAD[2] and LOAD[3] cannot be `mmap`ed at their required addresses at all.

There is a second, independent failure in the same table - draw the 16 KB page grid over it:

```
 vaddr   0x7c000        0x7d1b0   0x7e1b0        0x80000    0x826e0   0x836e0   0x84000
         |─────────────────┴─────────┴──────────────|────────────┴────────┴────────|
 page    [   16 KB page 0x7c000 …                   ][   16 KB page 0x80000 …      ]
 wants     R E  (LOAD1 .text/.plt)   RW (LOAD2 RELRO)   RW (LOAD2)      RW (LOAD3)
                                                        @off 0x7d1b0    @off 0x816e0
```

- Page `[0x7c000,0x80000)` must be **`R E` and `RW` simultaneously**. A page has one protection.
- Page `[0x80000,0x84000)` must carry file bytes at **two different offset skews** at once.

That is why this is not fixable after the fact - see §6.

**What a device does with it** is loader-dependent, and sopack has not measured it: a 16 KB
kernel either rejects the library outright (`dlopen` fails → `UnsatisfiedLinkError` at
`System.loadLibrary`, typically killing the app at startup), or loads it through a
compatibility path that abandons file-backed mapping and reads segments into private anonymous
memory. Do not design around the compat path - it is a device property, not a guarantee, and
Play's requirement exists precisely because it is not universal.

---

## 2. Step by step: every place sopack maps memory

Five mapping steps, three at pack time and two at load time. Page alignment matters at each one
for a different reason.

### Step 0 (pack time) - the library's offset inside the APK

`extractNativeLibs="false"` is the norm, so bionic `mmap`s the `.so` **straight out of the ZIP**.
The effective file offset is `zip_entry_data_offset + p_offset`, so the congruence in §1 only
survives if the entry itself starts on a page boundary. Hence `apk.py`: every `.so` is written
`ZIP_STORED` (uncompressed, or there is nothing to map) and `_align_apk` / `python_zipalign`
pads the local header so the entry's data begins at a multiple of **16384**.

*If violated:* every segment's skew is off by the entry misalignment; the whole library fails to
load. This step is entirely sopack's responsibility and it is enforced unconditionally.

### Step 1 (pack time) - `.text` is encrypted in place, section-exact

`elf_inject.py` encrypts the bytes of the **`.text` section**, not the segment, with a
length-preserving stream cipher. No offsets move, no segment geometry changes. For our library
that is `[0x296e0, 0x7c5a0)`, 339,648 bytes.

*Alignment relevance:* none directly - but it is why step 4 has to reason about a *page window*
around a *sub-page-aligned* range.

### Step 2 (pack time) - a new `PT_LOAD` is appended

Stub mode appends the R+X stub blob; wbaes mode appends a 16 KB-aligned copy of `.dynstr`. Both
set `seg.alignment = SEGMENT_ALIGN` (16384, `elf_inject.py:50`) and rely on LIEF to place the
segment congruently. `_self_verify*` then re-reads the written file and checks **every** LOAD -
ours and the library's - which is where a 4 KB input gets caught.

*If violated:* the appended segment itself becomes the unloadable one. This is the
LIEF-version-dependent failure documented in `TROUBLESHOOTING.md` §16 KB, a different cause with
the same symptom.

### Step 3 (load time) - bionic maps the library

Ordinary loader work: map each `PT_LOAD`, apply relocations, `mprotect` the `GNU_RELRO` range
read-only, then run `DT_INIT` (stub mode's entry point) / the `DT_NEEDED` helper's constructor
(wbaes mode). Page alignment is consumed here, by the kernel, exactly as in §1.

### Step 4 (load time) - the decryptor's page-window dance

Identical in both modes - `stub.c:136-202` and `sopk_rt.c:332-390` - and this is the step where
a 4 KB-aligned library would misbehave *even if the loader had accepted it*:

```
pg      = AT_PAGESZ                                  ← read at runtime, never hardcoded
win_lo  = align_down(text, pg)
win_hi  = align_up(text + text_size, pg)
 [C] scratch = mmap(anon, RW, win_hi - win_lo)       ← no file behind it
     memcpy(scratch, win_lo, win_len)                ← READS the whole window
 [D] decrypt exactly [text, text+text_size) inside scratch
 [E] mremap(scratch → win_lo, MREMAP_FIXED)          ← the window becomes anonymous
       └ fallback [E2]: mmap(MAP_FIXED) + copy
 [F] mprotect(win_lo, win_len, R-X)                  ← the whole window loses W
     icache flush over [text, text+text_size)
```

The **window**, not `.text`, is what gets remapped and re-protected - `mremap` and `mprotect`
take page-granular arguments, so `.text`'s sub-page ends are rounded outward. That rounding is
harmless when segments are spaced at the runtime page size, and is the whole problem when they
are not. `execmem`-vs-`execmod` (§2a of ARCHITECTURE) forces this shape; it is not
negotiable.

---

## 3. The window overreach, measured on this library

`.text` = `[0x296e0, 0x7c5a0)`. The window depends on the runtime page size:

| `AT_PAGESZ` | window | overshoot past LOAD[1]'s end `0x7d1b0` | bytes of LOAD[2] swallowed |
|---|---|---|---|
| 4096 | `[0x29000, 0x7d000)` | none (ends *below* it) | 0 |
| 16384 | `[0x28000, 0x80000)` | 11,856 bytes | **7,760 bytes of `.data.rel.ro`** |

At 4 KB the window is strictly inside the executable segment: correct by construction. It ends
at `0x7d000`, 432 bytes *below* LOAD[1]'s end - that tail is the end of `.plt`, which is neither
encrypted nor part of the window, so it simply stays file-backed and untouched. At 16 KB
it swallows the inter-segment gap plus the first 7,760 bytes of the **writable** segment.

Note this is not sopack computing something wrong. The window is minimal - it is the smallest
page-aligned range containing `.text`. It overreaches because the library packed a writable
segment into the same 16 KB page as executable code, which is exactly the condition §1 rejects.

---

## 4. Which step crashes, and how

Ordered by when they would fire. All are hypothetical for this library today - the guard stops
the pack first - and all assume a 16 KB kernel that somehow loaded the library.

| # | Step | Failure mode | Symptom |
|---|---|---|---|
| 1 | `[C] memcpy(scratch, win_lo, win_len)` | the window's rounded ends reach an **unmapped** address - a hole between LOADs, or past the last segment's rounded end | SIGSEGV **inside the constructor**, before any decryption; stub mode logs nothing past `B:mmap`, wbaes mode never reaches `sopk_fail` (it is a fault, not a checked error) |
| 2 | `[E] mremap(MREMAP_FIXED)` | the destination window spans two VMAs; the neighbour's pages are replaced by **anonymous** copies | no immediate crash - contents were copied in - but the neighbour silently loses its file backing and the page sharing that comes with it |
| 3 | `[F] mprotect(win, R-X)` | **the headline.** Every writable byte in the window loses `W` | SIGSEGV on the **first write to a global**, arbitrarily later, in the target library's own code, with a stack that points nowhere near the packer |
| 4 | `[F]` again | if a page holding `.got.plt` is in the window on a lazy-binding library, the resolver's first write to it faults | SIGSEGV inside `__dl__ZL...` on the first call through the PLT |

**For this specific library, #3 would probably not fire** - and the reason is luck, not design.
The 7,760 swallowed bytes are `.data.rel.ro`, which `GNU_RELRO` has already made read-only by
the time any constructor runs, so removing `W` removes nothing. `.data`/`.bss` start at
`0x836e0`, outside the window, and `DT_FLAGS: BIND_NOW` means `.got.plt` is written during
relocation and never again. Move `.data` eight kilobytes earlier - a routine consequence of
adding a global - and the same pack becomes an instant, unattributable SIGSEGV in production.

That margin is the real argument against a `--force`-style override: the failure it buys is not
a clean "does not load", it is a delayed segfault whose distance from the cause is measured in
seconds and stack frames.

---

## 5. Why the 4 KB path is nevertheless fine

Nothing above is a 4 KB problem. On a 4 KB kernel the window is `[0x29000, 0x7d000)`, entirely
inside the `R E` segment, and this library packs, loads and decrypts correctly - which is what
makes the current blanket refusal (§7) worth revisiting. `AT_PAGESZ` is read at runtime in both
decryptors, so a single packed artifact adapts to either page size; the geometry is what does
not.

---

## 6. Why sopack cannot repair the library

The obvious repair - insert `0x1000` of padding before LOAD[2] and `0x2000` before LOAD[3], so
each `p_offset` regains congruence with its `p_vaddr` mod 16 KB, then rewrite `p_align` - is
arithmetically correct and **still does not produce a loadable library**. It fixes only the
first of the two failures in §1. Page `[0x7c000,0x80000)` would still need to be `R E` for
`.plt` and `RW` for `.data.rel.ro` at the same time, and no amount of file padding changes that:
the collision is between **virtual addresses**, and `-z max-page-size=16384` fixes it by
*spacing the vaddrs*, not the offsets.

Respacing vaddrs after the fact means moving every symbol, every relocation target, every
`DT_*` address, every `.eh_frame` FDE and every PC-relative reference inside the code we cannot
read (this is a black-box packer - see ARCHITECTURE §1). That is a re-link, and the linker is
better placed to do it:

```
# in the module that builds libvostestapp.so
-Wl,-z,max-page-size=16384       # ndk-build / plain link
# or, Gradle + CMake / ndk-build:
android { defaultConfig { externalNativeBuild {
    cmake     { arguments "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON" }
    ndkBuild  { arguments "APP_SUPPORT_FLEXIBLE_PAGE_SIZES=true" }
} } }
```

Verify with `readelf -lW libvostestapp.so | awk '/LOAD/{print $3,$NF}'` - every alignment
`0x4000`, and every `vaddr − offset` a multiple of `0x4000`. Then re-pack; nothing in sopack
needs to change. Recent NDKs (r27 and later, per Google's 16 KB guidance) link 16 KB-aligned by
default, so a toolchain bump often suffices - confirm with the `readelf` line above rather than
assuming your NDK does it.

---

## 7. The part that *is* sopack's limitation

Three gaps, in the order they hurt:

1. **No way to pack for a 4 KB-only shipment.** The error says *"or pack it only for 4 KB device
   classes"* and the CLI offers no flag that does that - there is no `--allow-4k` /
   `--no-16k-check`. §5 says such a build would be correct on 4 KB hardware. Under auto-select
   the library is instead demoted to a skip and **ships in cleartext** (the run summary says so,
   which is the one thing that works as intended here).
2. **The stub path's check is unconditional and unattributed.** `_assert_16k_and_no_textrel`
   (wbaes) gates on `abi == "arm64-v8a"` and re-reads the input to say *who* is at fault;
   `_self_verify` (chacha20/xor, `elf_inject.py:1556-1564`) does neither - it checks every LOAD
   on every ABI and raises a bare `LOAD seg align 4096 not multiple of 16384`. Same library,
   same cause, an error that sends the reader hunting for a packer bug. It also means that
   **under `abis: all`** an `armeabi-v7a` or `x86_64` input can be rejected over a device class
   that cannot run it - 16 KB page hardware is arm64-only. (The `abis:` default of `arm64-v8a`
   alone keeps that out of the way in normal use, which shrinks the blast radius without fixing
   it.) A known gap, recorded in `CLAUDE.md` as *"an intent the stub path does not yet
   implement"*.
3. **`abis:` cannot express "4 KB devices only".** The device-class distinction the error message
   invokes has no representation anywhere in the tool.

None of that is a reason to weaken the check. §4 is: the guard is refusing to emit an artifact
whose failure mode is a delayed segfault in someone else's code.

---

## See also

- `docs/technical/ARCHITECTURE.md` §2a (`execmod` vs `execmem` - why the window dance exists),
  §2d (16 KB pages), §12e (the shared placement tail, both modes)
- `docs/TROUBLESHOOTING.md` §*is not 16 KB-page compatible to begin with* (this failure) and
  §*has a LOAD segment that breaks 16 KB loading* (the other one - sopack's own output, usually
  a LIEF version)
