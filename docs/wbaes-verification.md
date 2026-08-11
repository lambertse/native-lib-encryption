# Verifying `--cipher wbaes` end to end

A layered checklist. Each phase has a **command** and a **PASS signal** you can check
yourself. Phases 1–5 run on the pack host (Linux/macOS); Phase 6 needs an Android device.

**Requires whitebox-cryptography >= 2.0.0.** 2.0.0 removed the bulk entry points
(`wbc_crypt_ctr`, `wbc_encrypt_ecb`) in favour of key wrapping, and bumped the sealed-blob
format to v3. Older artifacts are not usable: a v2 blob is *rejected* by `Unseal`, and a
1.x `libwbcrypto.a` will not link against the current `stub/sopk_rt.c`. If
`scripts/gen_blob.sh` fails with `'abort' is not a member of 'std'`, your checkout predates
the `#include <cstdlib>` fix in `src/vm/assembler.cpp` — update it.

**Phases 1-4 are automated** by `scripts/build_wbaes.sh`, which runs them in order and turns
every PASS signal below into a hard gate:

```bash
./scripts/build_wbaes.sh                      # prompts for WBC/NDK if unset; RELEASE skeleton
./scripts/build_wbaes.sh --host-only          # Phases 1-3 only; no NDK needed
./scripts/build_wbaes.sh --trace              # Phase-6 tracing skeleton (NOT shippable)
```

It stops before Phase 5 (that needs your APK and lib names) and prints the pack command to run
next. The phases below are the manual equivalent, and the reference for what each check means
when the script fails one. (`scripts/build_chacha20.sh` is the equivalent for the stub ciphers,
which need only the stub blobs.)

Set these once if you prefer to run the phases by hand:

```bash
export SOPACK=/path/to/sopack             # this repo
export WBC=/path/to/whitebox-cryptography # the SDK repo (master, >= 3.0.0)
export NDK=/path/to/android-ndk           # your NDK (for Phase 4)
```

---

## Phase 1 — Prove the white-box IS standard AES-128 (host `wb_keygen`)

Any `wb_keygen` delivered out of band is an **Android** binary and will not run on the pack
host. Build the host-native, un-obfuscated provisioning tool from source (this is exactly
what the SDK's `scripts/gen_blob.sh` is for) and let it self-check the FIPS-197 vector:

```bash
cd "$WBC"
bash scripts/gen_blob.sh --key 000102030405060708090a0b0c0d0e0f \
     --pass demo --seed 42 --out /tmp/sealed.blob
```

**PASS:** the output ends with `69c4e0d86a7b0430d8cdb78070b4c55a` and
`sealed white-box -> /tmp/sealed.blob (454848 bytes, hardened bytecode, 44604 B code)`.
That hex is the FIPS-197 AES-128 vector — proof the white-box is bit-exact AES-128, which is
what lets sopack compute the key wrap in Python (Phase 3). It also leaves a runnable host
tool at `$WBC/build-host/wb_keygen`.

```bash
export SOPACK_WBKEYGEN="$WBC/build-host/wb_keygen"
```

---

## Phase 2 — sopack unit tests (crypto + layout + injection)

```bash
cd "$SOPACK"
python3 -m pytest tests/ -q
```

**PASS:** all tests pass. Two SKIP by design rather than fail, and the reason says why: the
full-injection tests need a host `wb_keygen`, because they seal a real white-box blob and there
is nothing meaningful to fake. Everything else — including the guards and the `.dynstr` re-sort
behaviour the mode depends on — runs off the committed `tests/fixtures/mini_arm64.so` with no
setup at all. What this covers:

- `test_cipher.py` — AES core vs FIPS-197; **`aes128_ctr` vs a vector captured from the real
  2.0.0 `wbc_unwrap_key`, still exact at 3.0.0** (the key-wrap contract); openssl fast paths == pure Python for
  both AES-CTR and ChaCha20, **and that a wrong-IV-convention `openssl` is rejected rather
  than silently trusted** (macOS ships LibreSSL, Linux OpenSSL 3.x — a same-length wrong
  result would ship a corrupt `.text` that only crashes on device); passphrase whitening
  self-inverse.
- `test_rt_meta.py` — the 96-byte `sopk_rt_region` layout matches `stub/sopk_rt.h`, the
  build marker in Python matches the one in the C header, and a foreign region version is
  rejected loudly.
- `test_wbaes.py` — a REAL wbaes injection on an arm64 `.so`: `.text` encrypted, the raw
  `DT_NEEDED` added, both target and helper stay 16 KB-aligned, region round-trips; **that
  every one of the target's exported symbol names survives** (the defect that produced a
  loading-then-crashing APK) and that reintroducing it fails the pack; that a skeleton without
  the build marker is refused; **that a skeleton with unresolved `wbc_*` imports is refused**
  (the 1.x-archive trap below); and that the symbol count is right for `DT_GNU_HASH`-only
  libraries and for ones that export nothing.

---

## Phase 3 — Full round-trip through the REAL white-box (host, no device)

This is the strongest check available without a device, and the one that catches
Python↔C drift. It proves, in one run: the C struct in `sopk_rt.h` parses the region the
Python packer wrote; the passphrase whitening mirror is byte-exact (otherwise `wbc_open`
rejects the passphrase); the wrap computed in Python is what the real `wbc_unwrap_key`
inverts; and the ChaCha20 mirror is byte-exact (otherwise the plaintext compare fails).

The probe lives at [`scripts/rt_roundtrip.c`](../scripts/rt_roundtrip.c) (it is what
`build_wbaes.sh` compiles, so there is one copy, not two). Build it:

```bash
cd "$WBC"
SODIUM_INC="$(echo third_party/libsodium/libsodium-*/src/libsodium/include)"
SRCS=$(find src -name '*.cpp' -not -path 'src/tools/*' -not -path 'src/rt/*' | sort)
cc -O2 -Iinclude -I"$SOPACK/stub" -c "$SOPACK/scripts/rt_roundtrip.c" -o /tmp/rt_roundtrip.o
c++ -std=c++17 -O2 -w -Isrc -Iinclude -I"$SODIUM_INC" \
    /tmp/rt_roundtrip.o $SRCS build-host/libsodium.a -o /tmp/rt_roundtrip
```

Provision a realistically sized payload through the real packer code, then decrypt it:

```bash
cd "$SOPACK"
python3 - <<'PY'
import os
from sopack.provision import provision_text
from sopack.rt_meta import Region
plain = os.urandom(5_513_872)                 # libapp.so-sized .text
prov = provision_text(plain)                  # seals a kek, wraps a session key, encrypts
region = Region(text_rva=0x10000, text_size=len(plain), wrapped=prov.wrapped,
                nonce16=prov.nonce16, soname=b'libapp.so', wpass=prov.wpass,
                blob=prov.blob).pack()
open('/tmp/region.bin','wb').write(region)
open('/tmp/cipher.bin','wb').write(prov.ciphertext)
open('/tmp/plain.bin','wb').write(plain)
print(f'provisioned {len(plain)} bytes; region {len(region)}, blob {len(prov.blob)}')
PY

/tmp/rt_roundtrip /tmp/region.bin /tmp/cipher.bin /tmp/plain.bin
```

**PASS:** `ROUND-TRIP: PASS`. Reference run on an aarch64 Linux host:

```
region: 455061 bytes, hdr=96
  magic/version OK  target='libapp.so'  text_size=5513872  blob=454924  pass_len=32
  blob kdf tier = 0 (0 = light/HKDF)
  wbc_open OK (1.1 ms)
  wbc_unwrap_key OK (0.83 ms)
  ChaCha20 decrypt: 11.8 ms (467 MB/s)

ROUND-TRIP: PASS   (total 13.7 ms for 5513872 bytes)
```

Note where the time goes: **no term dominates any more**, and the only one that grows with
`.text` is the 11.8 ms ChaCha20 line. `wbc_blob_kdf_tier` asserting tier 0 is what makes that
true — it proves the blob was sealed at the `light` tier. Before wbcrypto 3.0.0 this run showed
`wbc_open OK (226.3 ms)` for a 243 ms total, because the seal's KDF was a fixed Argon2id
64 MiB / 2; sealing at `light` (HKDF-SHA256) replaces that with 1.1 ms and removes the transient
64 MiB. A `wbc_open` line in the hundreds of ms here means the tier assertion should have caught
it first — report that, it is a bug.

The white-box itself is 0.83 ms because it only ever touches the 32-byte session key. Both the
long-term key and the session key were generated, used and discarded inside `provision_text` —
only the sealed blob, the wrapped key, the nonce and the whitened passphrase exist afterwards.

If `wbc_open` fails here, the passphrase whitening mirror has drifted
(`sopack/cipher.py` ⇄ `stub/stub_cipher.h`). If it opens but the compare fails, the
ChaCha20 mirror or the wrap has drifted.

---

## Phase 4 — Build the per-ABI skeletons (NDK + O-MVLL)

**Since region v3 there are TWO artifacts per ABI**, and they must be built in this order,
because 4b links against 4a's output:

| # | source | output | role |
|---|---|---|---|
| 4a | `stub/sopk_wb.c` | `sopk_wb_<abi>.so` → `libsopk_wb.so` | ONE shared white-box provider per ABI. Links `libwbcrypto.a`, owns every `wbc_*` call and the sealed blob, exports exactly `sopk_wb_k`. |
| 4b | `stub/sopk_rt.c` | `sopk_rt_<abi>.so` | The THIN per-target helper. Links **no** white-box; the packer clones it once per protected library. |

Why the split, in one line: the trigger must stay 1:1 with the target (bionic runs a shared
object's constructors **once**, so one helper shared by N targets would only decrypt the libraries
already mapped when the first loads), but the ~465 KB of white-box code and the ~455 KB blob do
not need duplicating N times. See `stub/sopk_wb.h`.

`./scripts/build_wbaes.sh` does both in one step. The manual recipe follows.

First the Android runtime library — `libwbcrypto.a` **bundles libsodium** since 2.0.0, so the
separate Android `libsodium.a` the old recipe built by hand is no longer needed:

```bash
cd "$WBC"
./scripts/build_android.sh --abi arm64-v8a --api 24     # -> build-android/libwbcrypto.a
cp build-android/libwbcrypto.a include/wbcrypto.h "$SOPACK/assets/wbc/"
```

**4a — the shared provider.** Add YOUR O-MVLL plugin flags to this line:

```bash
CXX="$NDK/toolchains/llvm/prebuilt/$(uname | tr A-Z a-z)-x86_64/bin/clang++"
# (on Apple Silicon the prebuilt dir is still darwin-x86_64)

"$CXX" --target=aarch64-linux-android24 -fPIC -shared -O2 -g0 \
    -ffile-prefix-map="$WBC=." -ffile-prefix-map="$SOPACK=." \
    -fvisibility=hidden -Wl,--exclude-libs,ALL -Wl,--no-undefined \
    -Wl,-soname,libsopk_wb.so \
    -static-libstdc++ \
    -I"$WBC/include" -I"$SOPACK/stub" \
    -x c "$SOPACK/stub/sopk_wb.c" -x none \
    "$SOPACK/assets/wbc/libwbcrypto.a" \
    -o "$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so"

"$(dirname "$CXX")/llvm-strip" --strip-all "$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so"
```

> **`-Wl,-soname,libsopk_wb.so` is load-bearing, not tidiness.** The thin helper's `DT_NEEDED`
> string is whatever the linker recorded here. Without an explicit soname, lld records the file
> **path** it was given (`.../sopack/stubs/sopk_wb_arm64-v8a.so`) and the resulting APK cannot
> load. The packer *asserts* this rather than fixing it — it cannot fix it, because every thin
> helper already recorded the string at link time.

**4b — the thin helper.** Simpler than 4a: plain `clang`, no static libc++, no `-x c` dance, no
`libwbcrypto.a`. But it **must** take the provider as a link input, so `--no-undefined` still
holds and the `DT_NEEDED` comes from the provider's `DT_SONAME` rather than being invented:

```bash
CC="$(dirname "$CXX")/clang"

"$CC" --target=aarch64-linux-android24 -fPIC -shared -O2 -g0 \
    -ffile-prefix-map="$SOPACK=." \
    -fvisibility=hidden -Wl,--no-undefined \
    -I"$SOPACK/stub" \
    "$SOPACK/stub/sopk_rt.c" \
    "$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so" \
    -o "$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"

# -g0 stops OUR debug info; the static archive still contributes its own symbols.
"$(dirname "$CXX")/llvm-strip" --strip-all "$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"
```

**Keep the thin helper under the same O-MVLL flags as the provider.** Otherwise every packed app
ships an identical un-obfuscated copy of the decrypt-and-place dance — a hardening regression
versus the pre-v3 single artifact.

This is the RELEASE line, and it is the default for a reason. Built without `-g0` and the strip,
the helper carries ~2.7 MB of DWARF (85% of the file) naming `sopk_rt_ctor`, the whole `wbc_*`
API and the VM handler set, plus a 4,000-entry `.symtab` and the absolute host source paths. A
static-analysis report on a shipped APK named exactly that as the single largest shortcut it had.

`--strip-all` keeps `.dynsym`/`.dynstr` and the section header table, which is what bionic needs.
It is **not** the section-header stripping that `static-analysis-hardening.md` §Method 3 rejected;
that zeroed `e_shoff`, and Android 14+ refuses to load the result.

For the **Phase 6** tracing build, add `-DSOPK_RT_LOG -llog` (the `-D` may sit anywhere on the
line — the driver collects defines globally — but `-llog` must come after the source). Such a
helper must then be packed with `sopack pack --allow-helper-log`, because it logs the target
soname and the `.text` address and size to logcat; the packer refuses it otherwise, and the
result is not shippable.

If `-static-libstdc++` is not accepted, drop it and append the two archives explicitly after
`libwbcrypto.a` instead:

```bash
SYSROOT="$NDK/toolchains/llvm/prebuilt/$(uname | tr A-Z a-z)-x86_64/sysroot"
    "$SYSROOT/usr/lib/aarch64-linux-android/libc++_static.a" \
    "$SYSROOT/usr/lib/aarch64-linux-android/libc++abi.a" \
```

Six things about that link line, all load-bearing:

- **Use `clang++`, not `clang`, and link libc++ STATICALLY.** `libwbcrypto.a` is C++, so the
  C driver leaves the entire C++ runtime unresolved — `operator new`/`delete`, `__cxa_*`,
  `std::runtime_error`, `typeinfo`, vtables, `__gxx_personality_v0`, dozens of them. Static,
  because a `libc++_shared.so` dependency would be another `.so` to ship and sopack's
  dependency-closure guard rejects it (check 1 below is what catches that).

- **`-x c` on the source, `-x none` after it.** `sopk_rt.c` is C; the C++ driver would
  otherwise compile it as C++. `-x none` restores by-extension handling so the archive that
  follows is still treated as an archive. (Upstream hit this exact trap in its own examples
  build.)

- **`-Wl,--no-undefined` is not optional.** A `-shared` link permits unresolved symbols by
  default, so if `libwbcrypto.a` is a **1.x** archive — no `wbc_wrap_key`/`wbc_unwrap_key`/
  `wbc_wipe`/`wbc_random`/`wbc_bulk_*` — the link **succeeds silently** and leaves
  `wbc_unwrap_key` and `wbc_wipe` as `UND` imports. Nothing complains until the device, where
  bionic cannot resolve them, `dlopen` of the *helper* fails, and therefore `dlopen` of the
  **target** fails too — surfacing as a crash inside whatever was loading the target, nowhere
  near the real cause. `--no-undefined` turns it into `undefined reference to 'wbc_unwrap_key'`
  at build time. This is why step 1 above is a prerequisite and not a suggestion: nothing
  under `assets/` is tracked (it holds large third-party binaries), so the archive is
  whatever you last built there — check it before blaming the link.

- **Do not link `libwbvm.a` / `libwbprovision.a`.** Those carry the *provisioning* surface
  (`wbc_seal_key`, the white-box generator, the reference AES) which must never ship in an
  app. Only `libwbcrypto.a` (the runtime set) belongs here.
- **`-Wl,--exclude-libs,ALL` is what hides the `wbc_*` symbols.** `WBC_API` expands to
  `visibility("default")` inside the archive's own objects, baked in when the archive was
  built, so neither `-fvisibility=hidden` nor `-DWBC_STATIC` on this compile can remove
  them. Without it the helper advertises `wbc_open`/`wbc_unwrap_key` in its dynamic symbol
  table, which hands a reverser a labelled map of the scheme.

  If check 2 below still prints symbols, `--exclude-libs` did not take effect (its coverage
  has varied across lld versions). Use a version script instead — it works regardless of
  where the visibility came from, because it filters at link time:

  ```bash
  printf '{ local: *; };\n' > /tmp/hide-all.map
  # ...add to the clang line, alongside or instead of --exclude-libs:
  #   -Wl,--version-script=/tmp/hide-all.map
  ```

  The helper exports nothing by design — its only entry point is an ELF constructor, which
  the loader reaches through `DT_INIT_ARRAY`, not the symbol table.
- No `-llog` unless you also pass `-DSOPK_RT_LOG` (Phase 6).

**PASS checks — and they DIFFER per artifact.** The expectations invert: the provider must export
exactly one symbol and define every `wbc_*`; the thin helper must export nothing and reference no
`wbc_*` at all. `sopack pack` re-runs all of these (and refuses on failure), so this is the
early-warning copy, not the only line of defence:

```bash
P="$SOPACK/sopack/stubs/sopk_wb_arm64-v8a.so"      # provider
S="$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"      # thin helper
NM="$NDK"/toolchains/llvm/prebuilt/*/bin/llvm-readelf

# ---- the provider ----
# P1. only bionic dependencies. libc++_shared.so means the static libc++ did not take effect.
$NM -dW "$P" | grep NEEDED
# P2. DT_SONAME must be exactly libsopk_wb.so — see the -Wl,-soname note above.
$NM -dW "$P" | grep SONAME
# P3. exports EXACTLY sopk_wb_k. Nothing means --exclude-libs/a version script swallowed the
#     entry; extra names mean --exclude-libs did not take effect.
$NM --dyn-syms "$P" | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" {print $8}'
# expect exactly: sopk_wb_k
# P4. IMPORTS no wbc_* — anything here means a PRE-3.0.0 archive. wbc_blob_kdf_tier in
#     particular is the 3.0.0-only symbol.
$NM --dyn-syms "$P" | awk '$7=="UND" && $8 ~ /^(wbc_|sodium_)/ {print $8}'
# expect NO output

# ---- the thin helper ----
# S1. bionic + libsopk_wb.so, and libsopk_wb.so must be PRESENT (a helper that lost it fails on
#     device as "cannot locate symbol sopk_wb_k", taking the target's dlopen with it).
$NM -dW "$S" | grep NEEDED
# expect libc.so / libm.so / libdl.so / libsopk_wb.so (+ liblog.so if built with tracing)
# S2. exports nothing
$NM --dyn-syms "$S" | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" {print $8}'
# expect NO output
# S3. imports sopk_wb_k and NO wbc_*/sodium_* — since v3 only the provider touches the white-box
$NM --dyn-syms "$S" | awk '$7=="UND" {print $8}' | grep -E '^(sopk_wb_k|wbc_|sodium_)'
# expect exactly: sopk_wb_k

# ---- both ----
# B1. each carries ITS OWN build marker. The two values differ on purpose: with one shared
#     marker, a fresh thin helper + a stale provider would pass both checks.
python3 -c "
from sopack.rt_meta import HELPER_BUILD_MARKER as h, PROVIDER_BUILD_MARKER as p
print('helper  marker:', h in open('$S','rb').read())
print('provider marker:', p in open('$P','rb').read())"
# expect True, True

# B2. stripped: no symbol table, no DWARF, no host build paths — and still a section table
for f in "$P" "$S"; do
  $NM -SW "$f" | grep -cE '\.symtab|\.debug_'    # expect 0
  strings "$f" | grep -cE '^/(Users|home)/'       # expect 0
done

# B3. THE SIZE SPLIT — this is the point of the v3 design, so check it.
ls -l "$P" "$S"
# provider ~470 KB (ships ONCE per ABI); thin helper a few KB. A thin helper anywhere near
# 470 KB means it still statically links libwbcrypto.a, and nothing was saved.
```

Check B1 is what stops a **stale** skeleton shipping. The on-device ctor requires an exact
region-version match and otherwise aborts with no explanation, so a skeleton built from an older
`sopk_rt.c` would produce an APK that crashes with encrypted `.text` and no diagnostic.
sopack refuses such a skeleton at pack time instead.

---

## Phase 5 — Pack a real APK and inspect the output

```bash
cd "$SOPACK"
mkdir -p output                 # sopack does not create it, and apksigner will fail without it

APK=path/to/your.apk
OUT=output/vsa-encrypted.apk
TGT=libso1.so                   # the lib you check below

python3 -m sopack.cli pack "$APK" \
  --lib "libso1.so,libso2.so" \
  --cipher wbaes \
  --abi arm64-v8a \
  --wb-keygen "$SOPACK_WBKEYGEN" \
  -o "$OUT" \
  --verify
```

**Quote the `--lib` list.** It is comma-separated but must be ONE argv word: unquoted
`--lib libso1.so, libso2.so` shell-splits, and argparse rejects the second name with
`error: unrecognized arguments: libso2.so`.

Verify the output APK:

```bash
OUT="$OUT" TGT="$TGT" python3 - <<'PY'
import zipfile, subprocess, tempfile, os, math, collections
Z = zipfile.ZipFile(os.environ["OUT"]); TGT = os.environ["TGT"]
libs = [n for n in Z.namelist() if n.startswith("lib/arm64-v8a/")]
helper = f"lib/arm64-v8a/libsopk_rt_{TGT[:-3]}.so"
print("1) helper added         :", helper in libs)
print("2) helper is STORED     :", Z.getinfo(helper).compress_type == zipfile.ZIP_STORED)
print("2) target is STORED     :", Z.getinfo(f"lib/arm64-v8a/{TGT}").compress_type == zipfile.ZIP_STORED)
def extract(n):
    p = os.path.join(tempfile.gettempdir(), os.path.basename(n))
    open(p,"wb").write(Z.read(n)); return p
tp, hp = extract(f"lib/arm64-v8a/{TGT}"), extract(helper)
for label,p in (("target",tp),("helper",hp)):
    al = subprocess.run(f"readelf -lW {p} | awk '/LOAD/{{print $NF}}' | sort -u",
                        shell=True, capture_output=True, text=True).stdout.split()
    print(f"3) {label} 16K-aligned  :", all(int(a,16)%16384==0 for a in al), al)
need = subprocess.run(f"readelf -dW {tp} | grep NEEDED", shell=True, capture_output=True, text=True).stdout
print("4) target NEEDs helper  :", f"libsopk_rt_{TGT[:-3]}.so" in need)
# 5) .text is encrypted (high Shannon entropy)
o = subprocess.run(f"readelf -SW {tp}", shell=True, capture_output=True, text=True).stdout
for ln in o.splitlines():
    if " .text " in ln:
        parts = ln.replace("]"," ").split(); i = parts.index("PROGBITS")
        off, size = int(parts[i+2],16), int(parts[i+3],16)
data = open(tp,"rb").read()[off:off+size]
c = collections.Counter(data); H = -sum(v/len(data)*math.log2(v/len(data)) for v in c.values())
print(f"5) .text entropy        : {H:.2f} bits/byte (encrypted ≈ 8.0)")
# 6) the helper must not stand out from the libraries it ships beside
stamps = {n: Z.getinfo(n).date_time for n in libs}
print("6) helper timestamp OK  :", stamps[helper][0] != 1980,
      "| distinct stamps:", len(set(stamps.values())))
# 7) the helper carries no symbol table, no DWARF and no host build paths
sec = subprocess.run(f"readelf -SW {hp}", shell=True, capture_output=True, text=True).stdout
bad = [n for n in (".symtab", ".strtab", ".debug_") if n in sec]
paths = [l for l in subprocess.run(f"strings {hp}", shell=True, capture_output=True,
                                   text=True).stdout.splitlines()
         if l.startswith(("/Users/", "/home/"))]
print("7) helper stripped      :", not bad, "| leftover:", bad)
print("7) no host paths        :", not paths, "| e.g.:", paths[:1])
print("7) section table intact :", ".shstrtab" in sec, "| size:", len(Z.read(helper)))
PY
```

**PASS:** all of (1)–(4) `True`; (5) entropy ≈ 8.0 (encrypted); (6) the helper's ZIP
timestamp matches the Gradle-built libraries around it rather than 1980-01-01 — an outlier
there was the *first* thing a static-analysis report noticed about a shipped APK, before any
disassembly; (7) no `.symtab`/`.debug_*`/host paths, `.shstrtab` still present, and the helper
is ~470 KB rather than ~3.2 MB. `--verify` prints a signer
cert. No AES key appears anywhere: the long-term key is diffused into the white-box blob
(inside the helper), and the session key ships only in its wrapped form.

**(8) The target's exported symbol names must be unchanged.** `inject_so` already refuses to
pack otherwise, but check it here too — it is the failure that produced a loading-then-crashing
APK, and it is invisible to every other check in this list:

```bash
APK="$APK" OUT="$OUT" TGT="$TGT" python3 - <<'PY'
import zipfile, os, sys
sys.path.insert(0, ".")
from sopack.elf_inject import _dynsym_names
TGT = os.environ["TGT"]
for tag, apk in (("orig", os.environ["APK"]), ("packed", os.environ["OUT"])):
    z = zipfile.ZipFile(apk)
    open(f"/tmp/{tag}_{TGT}", "wb").write(z.read(f"lib/arm64-v8a/{TGT}"))
a, b = _dynsym_names(f"/tmp/orig_{TGT}"), _dynsym_names(f"/tmp/packed_{TGT}")
print(f"{len(a)} symbols; PRESERVED: {a == b}")
if a != b:
    print("  first diff:", next((x, y) for x, y in zip(a, b) if x != y))
PY
```

Expect `PRESERVED: True`. Note this must be resolved via `DT_STRTAB` (as `_dynsym_names` does),
not `readelf`'s section-header view — in this mode the two legitimately point at different
tables, so `readelf --dyn-syms` alone can mislead in either direction.

---

## Phase 6 — On-device (the last mile; needs a device/emulator, arm64)

**Strongly recommended for the FIRST device test: build the skeleton with tracing** so each
helper's decrypt is visible in logcat (a release helper does not log, so an abort names no
cause). Add
`-DSOPK_RT_LOG -llog` to the Phase-4 clang line, rebuild `sopk_rt_arm64-v8a.so`, re-pack, then:

```bash
adb install -r out.apk
adb logcat -c && adb shell am start -n <pkg>/<launcher-activity>
# TWO tags since the v3 split: sopk_rt = each thin helper, sopk_wb = the shared provider
# (which is where the KDF-tier line comes from). DEBUG = native crash tombstones.
adb logcat -s sopk_rt sopk_wb DEBUG
```

With tracing you should see one line PER packed library, e.g.:
`decrypted 'libapp.so' .text (5513872 bytes) at 0x… — OK`, plus `blob kdf tier = 0` from the
`sopk_wb` tag. A `SIGABRT` names the exact step that failed; `sopk_fail_code` in the tombstone
gives the code, and provider failures arrive in the **10..19** band (see `stub/sopk_wb.h`).

**PASS:**
- One `… — OK` line per packed library, and the app launches and behaves normally — meaning
  each helper's constructor ran **before** its target's init and decrypted `.text` in place.
- **No** `SIGILL`/`SIGSEGV` from a target (a crash there = its `.text` ran still-encrypted).
- **COUNT THE LINES.** `sopack pack` reports how many libraries it injected; you need that many
  `— OK` lines. A missing one does **not** necessarily mean failure — a library the app never
  loads never runs its helper — but you must establish which it is rather than assume. Check
  whether it was loaded at all:

  ```bash
  PID=$(adb shell pidof <pkg>)
  adb shell run-as <pkg> cat /proc/$PID/maps | grep -E 'libvtap|libsopk'
  ```

  If the library IS mapped and there is no `— OK` line for it, that is a real failure: its
  `.text` is running encrypted and it will `SIGILL` when reached.
- If your app loads more than one packed library at **different** times (separate
  `System.loadLibrary` / `dlopen` calls), exercise each and confirm all work / all log OK —
  this validates the one-thin-helper-per-target design. Note the log will show different TIDs
  for libraries loaded on different threads; that is the design working, not a problem. A single
  helper shared by N targets would only ever decrypt the first group.

**Confirm the `light` KDF tier is actually in effect.** This is now a *confirmation* step, not a
decision: since wbcrypto 3.0.0 the blob is sealed with `--kdf light`, so each helper's `wbc_open`
should be single-digit-to-low-teens ms and there should be **no ~64 MiB spike per helper**. With a
tracing skeleton the helper logs `blob kdf tier = 0` before opening. Things to read off logcat:

- `blob kdf tier = 0` — anything else means a pre-3.0.0 host `wb_keygen` sealed the blob, which
  the pack-time gate (`provision.assert_light_blob`) should have refused. If it packed anyway,
  that is a bug worth reporting.
- an `open=` in the hundreds of ms — same conclusion: an Argon2id-sized open means a `heavy` blob.
- `SIGABRT` with `sopk_fail_code == 10` (`SOPK_FAIL_WBC_TIER`) — `wbc_blob_kdf_tier` rejected the
  header, i.e. the runtime and the blob format disagree (a pre-3.0.0 `libwbcrypto.a` linked into
  the skeleton against a v4 blob).

**Then measure startup cost and memory.** Each helper still runs its own `wbc_open` — `Unseal`
AEAD-decrypts the ~455 KB blob and builds the VM image, ~1 ms on a host — so with N packed
libraries you pay that N times, just at a far smaller constant than the pre-3.0.0 ~230 ms:

```bash
adb shell am start -W -n <pkg>/<launcher-activity>   # TotalTime = startup wall clock
adb shell dumpsys meminfo <pkg> | head -20           # peak RSS around startup
```

Record both, and compare peak RSS against the pre-3.0.0 baseline (which carried N × 64 MiB of
transient Argon2id arena). What these numbers now decide is **not** whether startup forces a
redesign — the `light` tier took that pressure off — but whether the remaining per-library cost is
worth collapsing to one shared blob, which is now mostly an **APK-size** question: each per-target
helper ships ~465 KB of white-box code plus its own ~455 KB blob, ≈920 KB, duplicated N times.

Note the shape to *avoid*: "one shared helper carrying N regions" cannot work, for the same reason
the multi-library PASS check above exists — bionic runs a shared object's constructors once, so it
would only decrypt the libraries mapped when the first target loads. The workable shape is N thin
per-target helpers plus one shared white-box provider `.so`. See `docs/potential-improvements.md`.

For a **release** build, drop `-DSOPK_RT_LOG -llog` — the helper then logs nothing and does
not depend on liblog.

Optional runtime confirmation on a 16 KB device: `adb shell getconf PAGE_SIZE` → `16384`, and
the app still runs.

---

## Appendix — where the time goes

The per-phase cost breakdown (and why only the ChaCha20 term scales with `.text` size) lives
in [`architecture.md` §11b](./architecture.md#11b-why-the-white-box-does-not-decrypt-text-the-redesign-that-mattered).
Build the skeleton with `-DSOPK_RT_LOG` and the helper logs its own version of that table per
library at load, which is how you compare a device against those host figures.
