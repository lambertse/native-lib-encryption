# Troubleshooting

Concrete failure modes seen with sopack, what causes each, and how to confirm/fix.
Background for all of these is in [`technical/ARCHITECTURE.md`](./technical/ARCHITECTURE.md).

The single most useful diagnostic is packing with **`--log`** and reading logcat:

```bash
adb logcat -s sopack:I
```

The stub emits staged lines (`A:entry`, `B:…`, `C:mmap…`, `D:decrypt…`, `E:mremap…`,
`H:native .text decrypted OK`). The **last** line you see tells you how far it got.

---

## App crashes with SIGILL inside the dynamic linker at launch

```
Fatal signal 4 (SIGILL), code 1 (ILL_ILLOPC) ... in ...libX.so
  #00 ...libX.so (offset ...)
  #01 linker64 __dl__ZL10call_array...      <-- DT_INIT_ARRAY iteration
  #02 linker64 __dl__ZN6soinfo17call_constructorsEv
  #03 linker64 __dl__Z9do_dlopen...
```

**Cause:** a constructor in `DT_INIT_ARRAY` ran on **still-encrypted** `.text`. The
stub never decrypted, because the injector hijacked an `INIT_ARRAY` slot - and on
position-independent libraries those slots are overwritten by `R_*_RELATIVE`
relocations at load, which revert the stub pointer to the original constructor.

**Status:** fixed. sopack now **never hijacks `DT_INIT_ARRAY`**; for a library with an
`INIT_ARRAY` but no `DT_INIT` (libflutter.so and most NDK C++ libs) it **adds a
`DT_INIT`**, which the loader runs *before* `INIT_ARRAY`. Confirm your build uses the
fix:

```bash
llvm-readelf -dW lib/arm64-v8a/libX.so | grep -E 'INIT'
# expect DT_INIT present; strategy in the pack output should read "DT_INIT-inplace"
```

If you're on an old build, re-pack with current sopack. (`_self_verify` now asserts
`DT_INIT` points at the stub, so this can no longer ship silently.)

---

## The exact same code crashes on my build but not on a build you gave me (arm64)

**Cause:** the arm64 stub reached its metadata via `adrp`+`add` (page-relative), which
is only correct when the injected segment loads at a **page-aligned** vaddr. Different
LIEF versions place the segment at different alignments; a non-page-aligned placement
made `adrp` mis-address the key/flags → garbage decrypt (and, because the flags were
misread, no `--log` line, so it looked like the stub never ran).

**Status:** fixed. The arm64 stub is built with **`-mcmodel=tiny`** (emits `adr`,
byte-relative, alignment-independent), and `build_stubs.sh` fails if any `adrp` remains.
Confirm your rebuilt blob:

```bash
llvm-objdump -d sopack/stubs/stub_arm64-v8a.bin | grep -c adrp   # must be 0
```

Rebuild the stubs (`bash stub/build_stubs.sh`) and re-pack.

---

## `error: bytes after .dynamic terminator ...` / `cannot add DT_INIT in place`

**Cause:** adding a `DT_INIT` works by overwriting `.dynamic`'s `DT_NULL` terminator
and using the following word as the new terminator - which requires that following slot
to read as `DT_NULL` at runtime. For some library layouts (and some LIEF versions) it
doesn't.

**What sopack already handles:** the runtime zero-ness is decided by the containing
`PT_LOAD`'s `filesz`/`memsz` (bytes beyond `filesz` are kernel zero-filled), and only
the `d_tag` **word** of the follow-slot needs to be zero (bionic ignores `d_val` on a
`DT_NULL`). Both are accounted for.

**If it still fires,** the slot after `.dynamic` is genuinely file-backed, mapped, and
has a non-zero tag - the tool refuses rather than corrupt the library. This is a
per-library limitation of the in-place method; report the library.

---

## `has a LOAD segment that breaks 16 KB loading` (arm64)

**First: upgrade LIEF.** `pip install -U 'lief>=1.0'`, then re-pack. This is almost always the
whole fix, and the packer now prints the LIEF version in the error for exactly that reason.

**Cause:** sopack's own output, not your library. The check re-reads the input first and would
have said *"is not 16 KB-page compatible to begin with"* if the input were at fault.

**Which artifact?** The message names it, and it can be any of three - they are emitted at
different points and only the first has an input to compare against:

| Artifact | Emitted by | Note |
|---|---|---|
| `the packed target <soname>` | `_inject_wbaes` steps 2-3 | the only one with an `orig_path`, hence *"its input … is clean"* |
| `the emitted thin helper libsopk_rt_<t>.so` | `_emit_helper`, per target | *"emitted from a skeleton, so there is no input to blame"* |
| `the emitted shared provider libsopk_wb.so` | `emit_provider`, once per ABI **after** the per-target loop | a target failure aborts before this one is even reached |

Older builds printed *"the input was clean, so this one is ours"* for all three, including the
two that have no input - so a log from those cannot be attributed. Upgrade sopack, re-run, and
read which artifact it names.

**Known trigger: the LIEF version.** sopack asks for 16 KB (`seg.alignment = SEGMENT_ALIGN`), but
some LIEF builds relocate the program headers or invent an extra 4 KB-aligned LOAD when the
append does not fit the existing layout. It is layout- and size-dependent, so it shows up on
larger libraries while smaller ones pack cleanly. This is the same hazard that makes
`_inject_wbaes` avoid LIEF's `add_library` entirely (see `docs/technical/ARCHITECTURE.md` §11f);
`add(seg)` is normally safe, but not on every LIEF version.

Observed on a macOS host with LIEF **`0.17.0`** packing a 1.66 MB arm64 library
(`libvosWrapperEx.so`, `--cipher wbaes`). On LIEF **`1.0.0`**, same file and same sopack commit,
all three artifacts come out clean - target (2 LOADs in, 3 out, all `0x4000`), thin helper
(6 LOADs), and provider (4 LOADs), every one `0x4000`-aligned and congruent. The provider was
checked with a *synthetic* region of representative size (~455 KB blob) rather than a real seal,
since the layout question does not need a host `wb_keygen`; the alignment result is what stands,
not the exact byte count. Hence the `lief>=1.0` floor in `pyproject.toml` (1.0.0 is on PyPI with
macOS arm64 wheels, so the upgrade resolves on an Apple Silicon host). When reporting a
recurrence, include:

```bash
python3 -c "import lief; print(lief.__version__)"
readelf -lW <input.so>  | awk '/LOAD/{print $2, $3, $NF}'   # the input's offsets/vaddrs/alignments
readelf -lW <packed.so> | awk '/LOAD/{print $2, $3, $NF}'   # and the output's
```

Note `awk '/LOAD/{print $NF}'` on two files is easy to misread: this library has **2** LOAD
segments, so four printed lines means you ran it on the same file twice, not that you saw the
output.

**Workarounds if `>=1.0` still fails:** report it with the table row it named, exclude that library
(`--exclude-lib libfoo`, or leave it out of `--lib`), or pack it only for a device class that does
not require 16 KB pages. Under auto-select this failure is already demoted to a per-library skip -
the library then ships in cleartext, which the run summary calls out.

**Do not disable the check.** It is refusing to emit an APK that would fail to load on 16 KB-page
hardware, which Play requires 64-bit apps to support - the failure is the guard working.

---

## No `sopack` line in logcat at all

Not necessarily a failure. Check, in order:

1. **Did you pass `--log`?** Without it the stub is silent by design.
2. **Which ABI loaded?** The device loads one ABI. If you only encrypted `arm64-v8a`
   but the device pulled `armeabi-v7a`, it loaded the *unencrypted* copy - nothing to
   report. Encrypt the ABI your device uses (or all of them).
3. **Filter correctly:** `adb logcat -s sopack:I` (tag `sopack`, level info).
4. If you see `A:entry` but not `H:…`, the stub ran but a syscall failed - the last
   staged line names the stage (e.g. `E:mremap FAILED`). See the mremap note below.

---

## `avc: denied { execmod }` (should not happen)

sopack decrypts into **anonymous** memory (`execmem`, allowed), never re-executes a
modified file mapping (`execmod`, denied). If you see `execmod`, something is loading a
library that decrypts in place - not sopack's path. `execmem` denials, by contrast,
only appear on unusually hardened ROMs (GrapheneOS-style) that restrict even JIT-style
mappings.

To confirm it is the device and not the packer, run
[`stub/execmem-probe/`](../stub/execmem-probe/) on it - a standalone `.so` that exercises
the same decrypt-and-execute path with no decryption and no packing involved. If the probe
is denied there, packed libraries cannot run on that device.

## `E:mremap FAILED` in the log, app still runs or crashes later

Some devices reject `MREMAP_FIXED` over a file-backed mapping. The stub has a fallback
(`munmap` the `.text` window, `mmap(MAP_FIXED)` fresh anon pages, copy decrypted bytes
in) and logs `E2:mmap-fixed fallback ok`. If both `E` and `E2` fail, the library is
left encrypted and will crash on first call - report the device/ABI, and include the
result of [`stub/execmem-probe/`](../stub/execmem-probe/) on that device, which isolates
the `mremap` step from everything else.

---

## App installs and launches but then reports tampering / exits / behaves oddly

**Cause:** re-signing gives the APK a **new signing certificate**. Apps with
integrity/anti-tamper or signature-pinning checks (very common in banking/security
apps - look for libraries like `libpki.so`, `libZeroCore.so`, V-Key/`libvos*`) detect
the new identity and refuse to run. This is the **app's own protection**, not a sopack
bug, and sopack can't defeat it.

Confirm the encryption itself is fine (static checks in `BUILDING.md` §5, and the
`sopack` decrypt line appears) to separate "encryption broke it" from "the app rejected
the re-sign."

---

## `error: no .so entries matched the requested list; nothing to encrypt`

The names you passed to `--lib`/`--libs` didn't match any `lib/<abi>/<name>.so` in the APK.

- If your `requested=[...]` shows a single element containing commas, you passed a
  comma list to a build without comma support - either update sopack (current `--lib`
  splits on commas) or repeat the flag: `--lib a.so --lib b.so`.
- Confirm the exact names/ABIs present:

  ```bash
  python3 -c "import zipfile;[print(n) for n in zipfile.ZipFile('in.apk').namelist() if n.startswith('lib/') and n.endswith('.so')]"
  ```
- A bare basename matches every selected ABI; make sure the library actually ships for
  the ABI you passed to `--abi`. **`--abi` defaults to `arm64-v8a` alone** - if the library
  is only present for another ABI, pass `--abi all` or name that ABI.
- Dropping `--lib`/`--libs` entirely encrypts every `lib/<abi>/*.so` and sidesteps the
  question.

---

## `error: none of the N lib/<abi>/*.so entries in this APK were packed`

Auto-select found libraries but every one was excluded or failed to inject. The per-library
reasons are printed above the error.

- `excluded by 'libsopk_*'` on **every** entry means you are re-packing an already-packed
  APK. Pack the original.
- `abi not selected` on every entry means the APK ships no `arm64-v8a` libraries; pass
  `--abi all` or the ABI it does ship.
- `excluded by '...'` from your own `--exclude-lib` - loosen the glob. Note it also
  overrides an explicit `--lib`.
- Everything failing to inject points at a shared cause; read the individual messages and
  see the per-library sections above.

---

## A library I expected to be encrypted shipped in cleartext

Under auto-select (no `--lib`/`--libs`) an injection failure is a **warning, not an error** -
the original library is written back unchanged so the pack still produces a working APK.
Check the run's summary:

```
Skipped (selected but could not be injected - these ship in CLEARTEXT):
  lib/arm64-v8a/libfoo.so: <reason>
```

Look the reason up in this document. To make that failure fatal instead, name the library
explicitly with `--lib libfoo.so` - explicit selection never degrades to a skip.

Also check the `Not selected:` block - `libflutter` and `libsopk_*` are excluded by default
(`--no-default-exclude` drops the former; the latter is unconditional), and anything outside
`--abi` is listed as `abi not selected`.

---

## `invalid linker name in argument '-fuse-ld=lld'` when building stubs

Your `ANDROID_NDK_HOME` points at something that isn't a real NDK (e.g. a version like
`4.8.0`). A valid NDK is r19+ and bundles `lld` (version like `27.0.12077973`). Install
a real NDK, or unset `ANDROID_NDK_HOME` to fall back to plain LLVM on `PATH`.

## `could not find apksigner` / `zipalign` / `keytool`

- `apksigner`: set `SOPACK_APKSIGNER_JAR=/path/to/apksigner.jar`, or put `apksigner` on
  `PATH`, or set `ANDROID_SDK_ROOT`.
- `zipalign`: not required - sopack falls back to its built-in Python 16 KB aligner.
- `keytool`: install a JDK or set `JAVA_HOME`.

---

## `incompatible pointer to integer conversion` building the stub (NDK r27)

NDK r27's clang treats `-Wint-conversion` as an error. The stub already casts pointers
to `long` in the fixed-`mmap` path; if you hit this after editing `syscalls.h`, add the
explicit `(long)` cast. Rebuild with `bash stub/build_stubs.sh`.

---

# `--cipher wbaes` failures

This mode **fails closed**: instead of degrading, every failure path calls `abort()`. That is
deliberate - the helper has no fallback, so returning would leave the target running encrypted
`.text` and crashing later somewhere unrelated. The trade-off is that a release build logs
nothing, so the *only* thing that names the cause is the numeric reason code.

## The app dies with `SIGABRT` at launch - reading `sopk_fail_code`

The reason is stored in a `volatile unsigned int sopk_fail_code` before the abort, so it
survives into the tombstone's memory dump even in a stripped, non-logging build:

```bash
adb logcat -s sopk_rt sopk_wb DEBUG
adb shell ls /data/tombstones/          # then pull and search for sopk_fail_code
```

**Codes are stable and are never renumbered.** Low codes are the thin helper's own; anything in
**10..19** is the shared provider's, folded in as `10 + reason` (`stub/sopk_rt.c`,
`stub/sopk_wb.h`):

| code | meaning | usual cause |
|---|---|---|
| 1 | no metadata region found in self | **stale skeleton** - the ctor's version gate matched nothing. Rebuild both skeletons (WBAES.md Phase 4). This is the most common one. |
| 2 | bad region fields | region header failed sanity checks; packer/skeleton mismatch |
| 3 | target not loaded | the target soname was not mapped when the helper's ctor ran |
| 4, 5 | **retired** | were `WBC_OPEN`/`WBC_UNWRAP` before the v3 provider split. A tombstone showing these is from an **old build** - do not read it as a current failure mode. |
| 6 | scratch `mmap` failed | out of memory / mapping pressure |
| 7 | fixed anon remap failed | see `E:mremap FAILED` above - same root cause |
| 8 | `mprotect R-X` failed | SELinux, or a W^X policy issue |
| 9 | region tail exceeds segment | truncated or corrupted region |
| 11 | provider: bad argument | NULL pointer or wrong buffer length |
| 12 | provider: **ABI mismatch** | a mismatched helper/provider **pair** - one was rebuilt without the other |
| 13 | provider: no region found | stale or region-less provider |
| 14 | provider: bad region fields | packer/provider mismatch |
| 15 | provider: region tail past segment | truncated provider region |
| 16 | provider: `wbc_blob_kdf_tier` failed | the runtime and the blob format disagree - usually a pre-3.0.0 `libwbcrypto.a` linked against a v4 blob |
| 17 | provider: `wbc_open` failed | wrong passphrase (the whitening mirror drifted) or a tampered blob |
| 18 | provider: `wbc_unwrap_key` failed | the wrap convention drifted, or a foreign blob |

A bare **10** cannot occur - it would mean provider reason 0, which is success.

## `cannot locate symbol "sopk_wb_k"` / the app dies inside `dlopen`

The shared provider `lib/<abi>/libsopk_wb.so` is missing, or its `DT_SONAME` is not exactly
`libsopk_wb.so`. Each thin helper records that `DT_NEEDED` string **at link time** (Phase 4b),
so the packer asserts the soname rather than fixing it - it cannot fix it retroactively.

Check the output APK:

```bash
unzip -l out.apk | grep libsopk          # expect ONE libsopk_wb.so per ABI, plus one helper per target
readelf -dW sopk_wb_arm64-v8a.so | grep SONAME    # must be exactly libsopk_wb.so
```

If the soname is a *path* (`.../sopack/stubs/sopk_wb_arm64-v8a.so`), you built the provider
without `-Wl,-soname,libsopk_wb.so`. Rebuild it and then rebuild the thin helper against it.

## Pack fails: `skeleton is missing the build marker` / `rebuild both`

The skeleton in `sopack/stubs/` predates a region or ctor-flow change. This is the guard doing
its job: on device a stale skeleton is undiagnosable (code 1, above), so the packer turns it
into a build-time error instead. Re-run `./scripts/build_wbaes.sh`, which rebuilds both
artifacts together - and note the two markers differ on purpose, so a *fresh helper + stale
provider* pair is caught too.

## Pack fails: the blob was refused (`assert_light_blob`)

`provision.py` refuses anything but a **v≥4, tier-0 (`light`)** sealed blob:

- *"blames a stale keygen"* - your host `wb_keygen` is pre-3.0.0 and emits a v3 blob.
  Rebuild it from the SDK (`scripts/gen_blob.sh`), with `--force` so a cached binary is not
  reused.
- *"blames sopack"* - the blob is v4 but sealed at `medium`/`heavy`. `wb_keygen` **defaults to
  `heavy`**, so this means the `--kdf light` flag was dropped; a heavy blob costs ~266 ms of
  Argon2id and a transient 64 MiB *per library* on device.

## Pack fails: `libsopk_wb.so already exists in this APK`

You are packing an already-packed APK. Reusing the existing provider would leave every thin
helper resolving against a **foreign** sealed blob, so no session key would unwrap and every
target would abort. Pack the original APK instead.

## A packed library never logs `- OK`, but the app runs

Not necessarily a failure: a library the app never loads never runs its helper. Establish which
it is before assuming. See [technical/WBAES.md](./technical/WBAES.md) Phase 6 - if the library
**is** mapped and there is no `- OK` line, its `.text` is running encrypted and it will `SIGILL`
when reached.
