# The whitebox-cryptography integration

How sopack's `--cipher wbaes` mode is wired to the **whitebox-cryptography (WBC) SDK** — which
artifacts and API calls it consumes, which it deliberately refuses, which side owns what, and what
breaks when the SDK moves. This is the boundary view: the *shape* of the integration, not its
rationale or its build steps.

Where the neighbouring docs stop and this one starts:

| doc | covers | read it instead when |
|---|---|---|
| [`architecture.md`](./architecture.md) §11 | *why* each decision was forced — the perf redesign, the AEAD rejection, the `dlsym` post-mortem | you want the argument, not the summary |
| [`wbaes-verification.md`](./wbaes-verification.md) | the six-phase procedure, with commands | you are actually building or verifying |
| [`building.md` §4](./building.md) | the CLI flags | you just want to pack an APK |
| `CLAUDE.md` | the invariants, terse | you are changing the code |

Nothing here is a build command and nothing here argues a design choice; both live above.

*Citation rule:* references into the WBC repo name a **file and symbol, never a line number** — it
is an external repo and line numbers drift.

---

## 1. Version contract

| piece | pinned at | consequence of a mismatch |
|---|---|---|
| WBC SDK | **>= 2.0.0** | 1.x has no `wbc_wrap_key`/`wbc_unwrap_key`/`wbc_wipe` at all |
| sealed blob format | **v3** (`Unseal` rejects older) | every pre-2.0.0 blob and prebuilt archive is dead |
| sopack region | **v2** (`rt_meta.REGION_VERSION`) | the on-device gate is exact, and a mismatch **aborts** |

1.x is not merely unsupported, it is *silently* unsupported: a `-shared` link permits unresolved
symbols, so a skeleton built against a 1.x `libwbcrypto.a` links cleanly and leaves the missing
`wbc_*` as `UND` imports. See §5.

## 2. What sopack consumes

| from WBC | used by | notes |
|---|---|---|
| `wb_keygen` CLI: `--key <hex> --pass <str> --seed <n> --out <path>` | `provision.py:_seal` | must be a **host** build (WBC `scripts/gen_blob.sh`). The delivered `assets/wbc/wb_keygen` is an *Android* binary, ships out of band and is not in this repo — `provision.py:_host_incompatible_reason` recognises that exact mistake by file magic |
| `libwbcrypto.a` | the helper skeleton link | the **Android** archive, from WBC `scripts/build_android.sh` (distinct from `gen_blob.sh` above, which builds the host keygen). **Bundles libsodium** since 2.0.0, so no separate Android libsodium |
| `wbcrypto.h` | `stub/sopk_rt.c` | |
| `wbc_open`, `wbc_unwrap_key`, `wbc_close`, `wbc_wipe` | `stub/sopk_rt.c:sopk_rt_ctor` | **four calls — that is the entire device-side surface** |

## 3. What sopack refuses

| not used | why |
|---|---|
| `wbc_crypt_ctr`, `wbc_encrypt_ecb` | deleted upstream in 2.0.0. Bulk white-box runs well under 1 MB/s; a 5.5 MB `libapp.so` took *minutes* inside a constructor (→ §11b) |
| `wbc_bulk_seal`, `wbc_bulk_open` | `.text` encryption must be **length-preserving in place**; the AEAD's 40 bytes of framing have nowhere to live (→ §11c) |
| `libwbvm.a`, `libwbprovision.a` | the provisioning surface — **must never ship on device** |
| `wbc_wrap_key` on the host | not needed; the host computes the wrap itself (§4) |

## 4. The discovery that removed the need for a host tool

`wbc_wrap_key` is plain **AES-128-CTR under the sealed key** (`src/sdk/wbcrypto.cpp:CtrSessionKey`):
a random 16-byte IV, the full IV as the initial big-endian counter, the IV prepended to the output.
The white-box *is* bit-exact AES-128, and the pack host still holds the long-term key at the moment
it seals it — so it can compute the wrap in pure Python:

```python
wrapped = wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)   # == wbc_wrap_key(ctx, sk, …)
```

Consequences: **no host tool links the white-box runtime, and `wb_keygen`'s CLI never changed.**
The price is that the CTR convention is now a frozen cross-project contract — pinned by a KAT
captured from the real 2.0.0 `wbc_unwrap_key` in `tests/test_cipher.py`.

## 5. Artifact flow

This is the *ownership* view — who produces each artifact and whether it ships. For the
step-by-step **sequence** at pack time and at load, and the same picture for stub mode,
see [`architecture.md`](./architecture.md) §12c–d.

```
  ── host (pack time) ──────────────────────┐   ── device (load time) ────────────────
                                            │
  kek ──wb_keygen──▶ blob ──────────────────┼──▶ wbc_open(blob, pass) ──▶ ctx
   │                   └──▶ whiten(pass)  ──┼──▶ de-whiten ──────────────┘
   │                                        │
   └─(AES-128-CTR)─▶ wrapped ───────────────┼──▶ wbc_unwrap_key(ctx, wrapped) ──▶ sk
                                            │                          wbc_close(ctx)
  sk ──ChaCha20──▶ encrypted .text ─────────┼──▶ ChaCha20(sk, nonce16) ──▶ plain .text
   │                     + nonce16          │                            wbc_wipe(sk)
   └── discarded, never written ────────────┘
```

| artifact | produced by | ships in the APK? |
|---|---|---|
| `kek` (long-term AES-128 key) | `cipher.gen_wbaes_params` | **no** — discarded after sealing, never reconstructable |
| passphrase | `provision.provision_text` (`secrets.token_hex(16)`) | yes, **whitened** (`cipher.whiten_pass`, keyed off the blob's own first bytes) |
| sealed blob | host `wb_keygen` | yes, inside the helper |
| `sk` (32-byte session key) | `cipher.gen_wbaes_params` | **no** — discarded on the host, re-derived on device by the unwrap |
| `wrapped` (48 B) | `provision.py`, in Python (§4) | yes |
| `nonce16` | `cipher.gen_wbaes_params` | yes |
| encrypted `.text` | `apply_cipher(CIPHER_CHACHA20, …)` | yes, in the target's own section bytes |
| skeleton `sopack/stubs/sopk_rt_<abi>.so` | **you**, by hand (NDK + O-MVLL, → Phase 4) | no — it is a pack-time input |
| `libsopk_rt_<target>.so` | `elf_inject._emit_helper` | yes — added to `lib/<abi>/` by `apk.py`, the tool's **only** add-file path |

Delivery is a `DT_NEEDED` on the target, added by raw ELF surgery (`_inject_wbaes` /
`_add_needed_inplace`, never LIEF `add_library`). bionic runs a dependency's constructors before the
dependent's init, so there is no `DT_INIT` or decinfo surgery in this mode at all — which is why it
handles `INIT_ARRAY`-only and no-init libraries for free.

## 6. The interchange format: the 96-byte v2 region

The region is the **only** structured data crossing from packer to device. `sopack/rt_meta.py`
(`_FMT = "<IIQQ48s16sHHI"`, `HDR_SIZE == 96`) mirrors `struct sopk_rt_region` in `stub/sopk_rt.h`:

```
magic 'SRTR' | version | text_rva | text_size | wrapped[48] | nonce16[16] |
soname_len | pass_len | blob_len        ── then the variable tail: soname, wpass, blob
```

It is appended to the helper as one read-only 16 KB-aligned `PT_LOAD` and found at runtime by
**magic-scanning the helper's own program headers** — no patched symbol or file offset, because
LIEF re-bases the helper when the segment is appended (→ §11e). `tests/test_rt_meta.py` pins the
layout, the build marker, and that a foreign version is rejected.

## 7. What an upstream change breaks

| if this changes in WBC | sopack effect | what catches it |
|---|---|---|
| `CtrSessionKey`'s CTR convention | the host-computed wrap silently stops matching | the KAT in `tests/test_cipher.py` |
| blob format / `Unseal` | `wbc_open` fails → the ctor **aborts** (`sopk_fail_code` = 4) | nothing automatic; re-run Phase 3 |
| `wb_keygen` CLI | `provision.py:_seal` argv fails | loud, at pack time |
| `libwbcrypto.a` stops bundling libsodium | undefined `sodium_*` in the skeleton | `-Wl,--no-undefined`, then `_emit_helper` |
| a consumed `wbc_*` signature | skeleton compile error | the compiler — the only failure mode loud by default |

Note the pattern: **the device side cannot explain itself**. Since the fail-closed change it at
least stops rather than running encrypted code, but a release helper does not log, so an abort
names no cause. Almost every guard therefore has to sit on the host, where it can name the
remedy.

## 8. The guards that make a mismatch visible

Each of these exists because the corresponding silent failure actually shipped.

- **`_emit_helper`: build marker.** The skeleton is built by hand outside this repo, so a stale one
  is easy to leave behind — and on device it is undiagnosable (the ctor's version gate finds no
  region and aborts, with nothing pointing at the packer). `sopk_rt.c` embeds
  `SOPK_RT_BUILD_MARKER_BYTES`; `rt_meta.HELPER_BUILD_MARKER` mirrors it; the packer refuses a
  skeleton without it. **Bump both together** on any region-layout *or* ctor-flow change; bump
  `REGION_VERSION` as well only when the layout itself moves. The marker must stay in an
  `SHF_ALLOC` section, because the packer strips everything else.
- **`_emit_helper`: not a tracing build.** A `-DSOPK_RT_LOG` helper logs the target soname,
  `.text` RVA and size, and a final "OK" to logcat. Refused unless `--allow-helper-log`, which
  warns on every pack.
- **`_emit_helper`: strip + no re-exported `wbc_*`.** Every non-ALLOC section is removed from the
  emitted helper (2.7 MB of DWARF and the whole symbol table on a default build); an exported
  `wbc_*` is refused, since only `--exclude-libs,ALL` can hide what `WBC_API` marks visible.
- **`_emit_helper`: no undefined `wbc_*`/`sodium_*`.** The 1.x-archive trap of §1. `DT_NEEDED` and
  export checks do **not** catch it — the leftovers are undefined symbols, not dependencies.
- **`_emit_helper`: `DT_NEEDED` ⊆ `_BIONIC_ALLOWED`.** Catches a shared `libc++_shared.so` or any
  stray dependency, i.e. a white-box that was not statically linked.
- **`_self_verify_wbaes`: dynamic symbol names identical in vs out.** Repointing `DT_STRTAB` at an
  appended `.dynstr` copy desynced every `st_name` once and shipped a crashing APK (→ §11f). The
  table must be read back from the **written** file (`_effective_strtab`), and symbols resolved the
  way bionic does (`_LoaderView`), never via section headers.

Integration-driven toolchain requirements (these come from the SDK, not from Android): the archive
is C++, so link with **`clang++ -static-libstdc++`** and pass the C source as `-x c sopk_rt.c
-x none`; add `-Wl,--exclude-libs,ALL` so `wbc_*` are not re-exported (`-fvisibility=hidden` and
`-DWBC_STATIC` cannot do it — `WBC_API` visibility is baked into the archive's objects); add
`-Wl,--no-undefined`. Note the packer checks **dependencies and undefined imports**, not exports —
export hygiene is verified by hand in Phase 4 step 2. The exact command line lives in
`stub/sopk_rt.c`'s header comment and
[Phase 4](./wbaes-verification.md) — deliberately not copied here, since a third copy would drift.

## 9. Cost

`wbc_open`'s Argon2id dominates: ~230 ms plus a transient **64 MiB** allocation
(`crypto_pwhash_MEMLIMIT_INTERACTIVE`), and it scales with **library count**, not `.text` size —
the white-box term is a fixed two blocks (~1.4 ms) and only the ChaCha20 term grows. N libraries
means N helpers, N blobs and N `wbc_open`s serialised in the loader at startup. The fix — one KEK,
one blob, one helper carrying N regions — is deliberately deferred until device numbers exist
(→ [Phase 6](./wbaes-verification.md), and §11b for the full breakdown).

## 10. Security ceiling

The white-box is Chow-style AES, academically broken by BGE-class attacks: it protects against
**static** analysis, not dynamic, and plaintext `.text` still exists in an `R-X` mapping at runtime.
Key wrapping removes the "portable key ships in the binary" weakness and narrows the story in
exactly one documented way: the **session** key is an ordinary key in ordinary memory between the
unwrap and the `wbc_wipe`, so a process dump yields it without attacking the white-box at all. The
**long-term** key keeps its full protection. Detail in §11a — do not oversell either way.

## 11. Upgrading to a newer SDK

1. Diff `wbcrypto.h` for the four consumed symbols (§2) and for the blob version.
2. Re-run `python -m pytest tests/test_cipher.py` — the `aes128_ctr` KAT is the wrap tripwire.
3. Rebuild the per-ABI skeleton against the new `libwbcrypto.a` **with `-Wl,--no-undefined`**.
4. If the region layout changes, bump `REGION_VERSION` **and** the build marker on both sides.
5. Re-run [`wbaes-verification.md`](./wbaes-verification.md) Phases 1–4 (Phase 3 exercises every
   contract above through the real library, no device needed), then Phase 6 on hardware.

## 12. One request to send upstream: scrub build paths from `libwbcrypto.a`

Not a sopack change, and — since the strip landed — **not urgent**. Recording it so it is asked for
once rather than rediscovered.

A static-analysis report on a shipped APK reported a host path in the helper's `.rodata`:

```
/Users/<user>/src/opensource/<org>/whitebox-cryptography/third_party/libsodium/libsodium-1.0.20/src/libsodium/crypto_verify/verify.c
```

which leaks a developer username, the internal project name, and the exact libsodium version for
CVE matching. **Measurement corrected the location:** in the reference skeleton every such string
lives in `.debug_str`, `.debug_line` and `.strtab` — 40, 98 and a handful of hits — and **none** in
`.rodata` or `.data.rel.ro`. All three are non-`SHF_ALLOC`, so the pack-time strip (Method 5)
already removes every one. `_emit_helper` warns if any survives, which would mean a mapped section
and therefore an archive-side fix.

Still worth doing upstream as defence in depth, because it stops the strings existing at all:

```cmake
# top-level CMakeLists.txt, covering first-party sources and vendored libsodium alike
add_compile_options(
    -ffile-prefix-map=${CMAKE_SOURCE_DIR}=.
    -ffile-prefix-map=${CMAKE_BINARY_DIR}=.
)
```

Two things to pass on with it:

- `-ffile-prefix-map` is `-fdebug-prefix-map` **plus** `-fmacro-prefix-map`. Only the macro half
  rewrites the `__FILE__` strings that libsodium's assert/misuse macros bake into `.rodata`, so
  `-fdebug-prefix-map` alone would not have fixed the case the report described.
- `scripts/build_android.sh` should pass `-g0` for release archives, so no DWARF is produced to
  carry paths in the first place.

sopack's own side is already done: `scripts/build_wbaes.sh` passes both `-ffile-prefix-map` flags
and `-g0` for `sopk_rt.c`, but those cannot reach strings already compiled into the archive.
