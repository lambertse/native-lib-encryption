# Verifying `--cipher wbaes` end to end

A layered checklist. Each phase has a **command** and a **PASS signal** you can check
yourself. Phases 1–5 run on the pack host (Linux/macOS); Phase 6 needs an Android device.

**Requires whitebox-cryptography >= 2.0.0.** 2.0.0 removed the bulk entry points
(`wbc_crypt_ctr`, `wbc_encrypt_ecb`) in favour of key wrapping, and bumped the sealed-blob
format to v3. Older artifacts are not usable: a v2 blob is *rejected* by `Unseal`, and a
1.x `libwbcrypto.a` will not link against the current `stub/sopk_rt.c`. If
`scripts/gen_blob.sh` fails with `'abort' is not a member of 'std'`, your checkout predates
the `#include <cstdlib>` fix in `src/vm/assembler.cpp` — update it.

Set these once:

```bash
export SOPACK=/path/to/sopack             # this repo
export WBC=/path/to/whitebox-cryptography # the SDK repo (master, >= 2.0.0)
export NDK=/path/to/android-ndk           # your NDK (for Phase 4)
```

---

## Phase 1 — Prove the white-box IS standard AES-128 (host `wb_keygen`)

The delivered `assets/wbc/wb_keygen` is an **Android** binary and will not run on the pack
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

**PASS:** all tests pass. Some SKIP by design rather than fail, and the reason names the
missing precondition: the two full-injection tests need a host `wb_keygen` (they seal a real
white-box blob), and the optional large-library variant needs a real `.so` in `assets/`.
Everything else — including the guards and the `.dynstr` re-sort behaviour the mode depends
on — runs off the committed `tests/fixtures/mini_arm64.so` with no setup. What this covers:

- `test_cipher.py` — AES core vs FIPS-197; **`aes128_ctr` vs a vector captured from the real
  2.0.0 `wbc_unwrap_key`** (the key-wrap contract); openssl fast paths == pure Python for
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

Build the probe once:

```bash
cat > /tmp/rt_roundtrip.c <<'EOF'
/* Host round-trip of the FULL --cipher wbaes contract. Parses the packer's region with the
 * real C struct, de-whitens the passphrase, opens the sealed blob with the real wbcrypto
 * 2.0.0, unwraps the session key, and ChaCha20-decrypts with the same code the helper uses. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "wbcrypto.h"
#include "sopk_rt.h"
#include "stub_cipher.h"

static double ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e3+t.tv_nsec/1e6;}
static unsigned char *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(1); }
    fseek(f, 0, SEEK_END); long l = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(l); if (fread(b, 1, l, f) != (size_t)l) exit(1);
    fclose(f); *n = l; return b;
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s region.bin cipher.bin plain.bin\n", argv[0]); return 2; }
    size_t rn, cn, pn;
    unsigned char *rb = slurp(argv[1], &rn), *ct = slurp(argv[2], &cn), *pt = slurp(argv[3], &pn);

    const sopk_rt_region *r = (const sopk_rt_region *)rb;
    printf("region: %zu bytes, hdr=%u\n", rn, SOPK_RT_REGION_HDR_SIZE);
    if (r->magic != SOPK_RT_REGION_MAGIC) { printf("FAIL: bad magic 0x%08x\n", r->magic); return 1; }
    if (r->version != SOPK_RT_REGION_VERSION) { printf("FAIL: version %u != %u\n", r->version, SOPK_RT_REGION_VERSION); return 1; }
    const uint8_t *tail = rb + SOPK_RT_REGION_HDR_SIZE;
    const char *soname = (const char *)tail;
    const uint8_t *wpass = tail + r->soname_len;
    const uint8_t *blob  = wpass + r->pass_len;
    printf("  magic/version OK  target='%.*s'  text_size=%llu  blob=%u  pass_len=%u\n",
           (int)r->soname_len, soname, (unsigned long long)r->text_size, r->blob_len, r->pass_len);
    if (r->text_size != cn || cn != pn) { printf("FAIL: size mismatch\n"); return 1; }

    /* de-whiten the passphrase exactly as the ctor does */
    uint8_t wkey[32]; sopk_whiten_key(blob, SOPK_WHITEN_SPAN, wkey);
    char pass[256]; memcpy(pass, wpass, r->pass_len);
    sopk_chacha20_apply((uint8_t *)pass, r->pass_len, wkey, SOPK_WHITEN_NONCE);
    pass[r->pass_len] = '\0';

    wbc_ctx *ctx = NULL; double t0 = ms();
    wbc_status s = wbc_open(blob, r->blob_len, pass, &ctx);
    double t_open = ms() - t0;
    if (s != WBC_OK) { printf("FAIL: wbc_open -> %s (wrong passphrase => whitening drift)\n", wbc_strerror(s)); return 1; }
    printf("  wbc_open OK (%.1f ms)\n", t_open);

    uint8_t sk[WBC_SESSION_KEY_BYTES];
    t0 = ms(); s = wbc_unwrap_key(ctx, r->wrapped, sk); double t_unwrap = ms() - t0;
    wbc_close(ctx);
    if (s != WBC_OK) { printf("FAIL: wbc_unwrap_key -> %s\n", wbc_strerror(s)); return 1; }
    printf("  wbc_unwrap_key OK (%.2f ms)\n", t_unwrap);

    t0 = ms(); sopk_chacha20_apply(ct, cn, sk, r->nonce16); double t_bulk = ms() - t0;
    wbc_wipe(sk, sizeof sk);
    printf("  ChaCha20 decrypt: %.1f ms (%.0f MB/s)\n", t_bulk, cn/1e6/(t_bulk/1e3));

    int ok = memcmp(ct, pt, pn) == 0;
    printf("\nROUND-TRIP: %s   (total %.1f ms for %zu bytes)\n",
           ok ? "PASS" : "FAIL", t_open + t_unwrap + t_bulk, pn);
    return ok ? 0 : 1;
}
EOF

cd "$WBC"
SODIUM_INC="third_party/libsodium/libsodium-1.0.20/src/libsodium/include"
SRCS=$(find src -name '*.cpp' -not -path 'src/tools/*' -not -path 'src/rt/*' | sort)
cc -O2 -Iinclude -I"$SOPACK/stub" -c /tmp/rt_roundtrip.c -o /tmp/rt_roundtrip.o
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
region: 455233 bytes, hdr=96
  magic/version OK  target='libapp.so'  text_size=5513872  blob=455096  pass_len=32
  wbc_open OK (226.3 ms)
  wbc_unwrap_key OK (1.43 ms)
  ChaCha20 decrypt: 15.4 ms (359 MB/s)

ROUND-TRIP: PASS   (total 243.1 ms for 5513872 bytes)
```

Note where the time goes: `wbc_open`'s Argon2id KDF is ~93% of it, and the white-box itself
is 1.4 ms because it only ever touches the 32-byte session key. Neither term grows with
`.text`; only the 15 ms ChaCha20 line does. Both the long-term key and the session key were
generated, used and discarded inside `provision_text` — only the sealed blob, the wrapped
key, the nonce and the whitened passphrase exist afterwards.

If `wbc_open` fails here, the passphrase whitening mirror has drifted
(`sopack/cipher.py` ⇄ `stub/stub_cipher.h`). If it opens but the compare fails, the
ChaCha20 mirror or the wrap has drifted.

---

## Phase 4 — Build the per-ABI helper skeleton (NDK + O-MVLL)

You build this; sopack only does ELF surgery on it. First the Android runtime library —
2.0.0 ships a wrapper for the cross-build, and `libwbcrypto.a` now **bundles libsodium**, so
the separate Android `libsodium.a` the old recipe built by hand is no longer needed:

```bash
cd "$WBC"
./scripts/build_android.sh --abi arm64-v8a --api 24     # -> build-android/libwbcrypto.a
cp build-android/libwbcrypto.a include/wbcrypto.h "$SOPACK/assets/wbc/"
```

Then the helper (add YOUR O-MVLL plugin flags to this clang++ line):

```bash
CXX="$NDK/toolchains/llvm/prebuilt/$(uname | tr A-Z a-z)-x86_64/bin/clang++"
# (on Apple Silicon the prebuilt dir is still darwin-x86_64)

"$CXX" --target=aarch64-linux-android24 -fPIC -shared -O2 \
    -fvisibility=hidden -Wl,--exclude-libs,ALL -Wl,--no-undefined \
    -static-libstdc++ \
    -I"$WBC/include" -I"$SOPACK/stub" \
    -x c "$SOPACK/stub/sopk_rt.c" -x none \
    "$SOPACK/assets/wbc/libwbcrypto.a" \
    -DSOPK_RT_LOG -llog \
    -o "$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"
```

(`-DSOPK_RT_LOG -llog` is the Phase-6 tracing build; drop both for release. The `-D` may sit
anywhere on the line — the driver collects defines globally — but `-llog` must come after the
source, as above.)

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

**PASS — three checks:**

```bash
S="$SOPACK/sopack/stubs/sopk_rt_arm64-v8a.so"
NM="$NDK"/toolchains/llvm/prebuilt/*/bin/llvm-readelf

# 1. only bionic dependencies (sopack rejects it otherwise)
$NM -dW "$S" | grep NEEDED
# expect only libc.so / libm.so / libdl.so (+ liblog.so if you built with tracing).
# libc++_shared.so here means the static libc++ did not take effect.

# 2. exports nothing — no wbc_* leak
$NM --dyn-syms "$S" | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" {print $8}'
# expect NO output

# 2b. IMPORTS no wbc_* either — anything here means it linked against a 1.x archive and
#     will fail to load on device (see --no-undefined above)
$NM --dyn-syms "$S" | awk '$7=="UND" && $8 ~ /^wbc_/ {print $8}'
# expect NO output

# 3. carries the build marker sopack greps for
python3 -c "
from sopack.rt_meta import HELPER_BUILD_MARKER as m
print('build marker present:', m in open('$S','rb').read())"
# expect True
```

Check 3 is what stops a **stale** skeleton shipping. The on-device ctor requires an exact
region-version match and otherwise fails open silently, so a skeleton built from an older
`sopk_rt.c` would produce an APK that crashes with encrypted `.text` and no diagnostic.
sopack refuses such a skeleton at pack time instead.

---

## Phase 5 — Pack a real APK and inspect the output

```bash
cd "$SOPACK"
python3 -m sopack.cli pack in.apk --lib libfoo.so --cipher wbaes \
    --abi arm64-v8a --wb-keygen "$SOPACK_WBKEYGEN" -o out.apk --verify
```

Verify the output APK (replace `libfoo.so` with your target):

```bash
python3 - <<'PY'
import zipfile, subprocess, tempfile, os, math, collections
Z = zipfile.ZipFile("out.apk"); TGT = "libfoo.so"
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
PY
```

**PASS:** all of (1)–(4) `True`; (5) entropy ≈ 8.0 (encrypted). `--verify` prints a signer
cert. No AES key appears anywhere: the long-term key is diffused into the white-box blob
(inside the helper), and the session key ships only in its wrapped form.

**(6) The target's exported symbol names must be unchanged.** `inject_so` already refuses to
pack otherwise, but check it here too — it is the failure that produced a loading-then-crashing
APK, and it is invisible to every other check in this list:

```bash
python3 - <<'PY'
import zipfile, sys
sys.path.insert(0, ".")
from sopack.elf_inject import _dynsym_names
TGT = "libfoo.so"
for tag, apk in (("orig", "in.apk"), ("packed", "out.apk")):
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
helper's decrypt is visible in logcat (otherwise a silent fail-open is hard to diagnose). Add
`-DSOPK_RT_LOG -llog` to the Phase-4 clang line, rebuild `sopk_rt_arm64-v8a.so`, re-pack, then:

```bash
adb install -r out.apk
adb logcat -c && adb shell am start -n <pkg>/<launcher-activity>
adb logcat -s sopk_rt DEBUG          # sopk_rt = our trace; DEBUG = native crash tombstones
```

With tracing you should see one line PER packed library, e.g.:
`decrypted 'libapp.so' .text (5513872 bytes) at 0x… — OK`. Any `(fail open)` line names the
exact step that failed (region / target-not-loaded / `wbc_open` / `wbc_unwrap_key`).

**PASS:**
- One `… — OK` line per packed library, and the app launches and behaves normally — meaning
  each helper's constructor ran **before** its target's init and decrypted `.text` in place.
- **No** `SIGILL`/`SIGSEGV` from a target (a crash there = its `.text` ran still-encrypted).
- If your app loads more than one packed library at **different** times (separate
  `System.loadLibrary` / `dlopen` calls), exercise each and confirm all work / all log OK —
  this validates the one-helper-per-target design (a shared helper would only decrypt the
  first group).

**Also measure startup cost and memory.** Each helper runs its own `wbc_open`, and that
Argon2id KDF is both the dominant time cost (~230 ms on a fast host, more on a phone) and a
transient **64 MiB** allocation (`crypto_pwhash_MEMLIMIT_INTERACTIVE`) — per helper, inside
an ELF constructor at startup. With N packed libraries you pay both N times:

```bash
adb shell am start -W -n <pkg>/<launcher-activity>   # TotalTime = startup wall clock
adb shell dumpsys meminfo <pkg> | head -20           # peak RSS around startup
```

Record both. If N is large or the device is a 1–2 GB model, this is the number that decides
whether to collapse the design to one shared helper carrying N regions (one KEK, one blob,
one `wbc_open`). Nothing else in the load path scales with library count.

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
