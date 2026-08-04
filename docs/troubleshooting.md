# Troubleshooting

Concrete failure modes seen with sopack, what causes each, and how to confirm/fix.
Background for all of these is in [`architecture.md`](./architecture.md).

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
stub never decrypted, because the injector hijacked an `INIT_ARRAY` slot — and on
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
and using the following word as the new terminator — which requires that following slot
to read as `DT_NULL` at runtime. For some library layouts (and some LIEF versions) it
doesn't.

**What sopack already handles:** the runtime zero-ness is decided by the containing
`PT_LOAD`'s `filesz`/`memsz` (bytes beyond `filesz` are kernel zero-filled), and only
the `d_tag` **word** of the follow-slot needs to be zero (bionic ignores `d_val` on a
`DT_NULL`). Both are accounted for.

**If it still fires,** the slot after `.dynamic` is genuinely file-backed, mapped, and
has a non-zero tag — the tool refuses rather than corrupt the library. This is a
per-library limitation of the in-place method; report the library.

---

## `the injection produced a LOAD segment that breaks 16 KB loading` (arm64)

**Cause:** sopack's own output, not your library. The check re-reads the input first and would
have said *"is not 16 KB-page compatible to begin with"* if the input were at fault — so this
wording means the input was clean and the injection introduced the bad segment.

**Known trigger: the LIEF version.** Some LIEF builds relocate or add a 4 KB-aligned segment
when the appended segment does not fit the existing layout. It is layout- and size-dependent, so
it shows up on larger libraries while smaller ones pack cleanly. This is the same hazard that
makes `_inject_wbaes` avoid LIEF's `add_library` entirely (see `docs/architecture.md` §11f);
`add(seg)` is normally safe, but not on every LIEF version.

Observed once on a macOS host packing a 1.7 MB arm64 library that another host — same file, same
sopack commit, LIEF `1.0.0` — packed to clean 16 KB output. So when reporting it, include:

```bash
python3 -c "import lief; print(lief.__version__)"
readelf -lW <input.so>  | awk '/LOAD/{print $NF}'      # the input's alignments
readelf -lW <packed.so> | awk '/LOAD/{print $NF}'      # and the output's
```

**Workarounds, in order:** pin a LIEF version that produces clean output; leave that library out
of `--lib`; or pack it only for a device class that does not require 16 KB pages.

**Do not disable the check.** It is refusing to emit an APK that would fail to load on 16 KB-page
hardware, which Play requires 64-bit apps to support — the failure is the guard working.

---

## No `sopack` line in logcat at all

Not necessarily a failure. Check, in order:

1. **Did you pass `--log`?** Without it the stub is silent by design.
2. **Which ABI loaded?** The device loads one ABI. If you only encrypted `arm64-v8a`
   but the device pulled `armeabi-v7a`, it loaded the *unencrypted* copy — nothing to
   report. Encrypt the ABI your device uses (or all of them).
3. **Filter correctly:** `adb logcat -s sopack:I` (tag `sopack`, level info).
4. If you see `A:entry` but not `H:…`, the stub ran but a syscall failed — the last
   staged line names the stage (e.g. `E:mremap FAILED`). See the mremap note below.

---

## `avc: denied { execmod }` (should not happen)

sopack decrypts into **anonymous** memory (`execmem`, allowed), never re-executes a
modified file mapping (`execmod`, denied). If you see `execmod`, something is loading a
library that decrypts in place — not sopack's path. `execmem` denials, by contrast,
only appear on unusually hardened ROMs (GrapheneOS-style) that restrict even JIT-style
mappings.

## `E:mremap FAILED` in the log, app still runs or crashes later

Some devices reject `MREMAP_FIXED` over a file-backed mapping. The stub has a fallback
(`munmap` the `.text` window, `mmap(MAP_FIXED)` fresh anon pages, copy decrypted bytes
in) and logs `E2:mmap-fixed fallback ok`. If both `E` and `E2` fail, the library is
left encrypted and will crash on first call — report the device/ABI.

---

## App installs and launches but then reports tampering / exits / behaves oddly

**Cause:** re-signing gives the APK a **new signing certificate**. Apps with
integrity/anti-tamper or signature-pinning checks (very common in banking/security
apps — look for libraries like `libpki.so`, `libZeroCore.so`, V-Key/`libvos*`) detect
the new identity and refuse to run. This is the **app's own protection**, not a sopack
bug, and sopack can't defeat it.

Confirm the encryption itself is fine (static checks in `building.md` §5, and the
`sopack` decrypt line appears) to separate "encryption broke it" from "the app rejected
the re-sign."

---

## `error: no .so entries matched the requested list; nothing to encrypt`

The requested names didn't match any `lib/<abi>/<name>.so` in the APK.

- If your `requested=[...]` shows a single element containing commas, you passed a
  comma list to a build without comma support — either update sopack (current `--lib`
  splits on commas) or repeat the flag: `--lib a.so --lib b.so`.
- Confirm the exact names/ABIs present:

  ```bash
  python3 -c "import zipfile;[print(n) for n in zipfile.ZipFile('in.apk').namelist() if n.startswith('lib/') and n.endswith('.so')]"
  ```
- A bare basename matches every selected ABI; make sure the library actually ships for
  the ABI you passed to `--abi` (some libs are arm64-only).

---

## `invalid linker name in argument '-fuse-ld=lld'` when building stubs

Your `ANDROID_NDK_HOME` points at something that isn't a real NDK (e.g. a version like
`4.8.0`). A valid NDK is r19+ and bundles `lld` (version like `27.0.12077973`). Install
a real NDK, or unset `ANDROID_NDK_HOME` to fall back to plain LLVM on `PATH`.

## `could not find apksigner` / `zipalign` / `keytool`

- `apksigner`: set `SOPACK_APKSIGNER_JAR=/path/to/apksigner.jar`, or put `apksigner` on
  `PATH`, or set `ANDROID_SDK_ROOT`.
- `zipalign`: not required — sopack falls back to its built-in Python 16 KB aligner.
- `keytool`: install a JDK or set `JAVA_HOME`.

---

## `incompatible pointer to integer conversion` building the stub (NDK r27)

NDK r27's clang treats `-Wint-conversion` as an error. The stub already casts pointers
to `long` in the fixed-`mmap` path; if you hit this after editing `syscalls.h`, add the
explicit `(long)` cast. Rebuild with `bash stub/build_stubs.sh`.
