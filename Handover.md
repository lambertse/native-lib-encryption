# handover.md — Self-Decrypting Native Shared Library (.so) on arm64 Android

## TL;DR
- **Do NOT decrypt the .text in place.** Modern Android (API 29+, hard-enforced on 14/15) blocks re-adding `PROT_EXEC` to a modified file-backed page via SELinux `execmod`, which was deliberately scoped out for apps targeting API ≥ 29. The only non-root, no-linker-modification design that survives W^X is: keep a small **plaintext decstub** (in `.init_array`/`JNI_OnLoad`), `mmap` a fresh **anonymous** RW region (covered by the `execmem` permission that IS granted to apps), decrypt into it, `mprotect` it to `R-X`, flush the i-cache, and redirect execution there.
- The hard blockers are: (1) SELinux `execmod` (no in-place file-backed re-exec), (2) W^X (never map W+X simultaneously), (3) the arm64 requirement to explicitly flush I/D caches after writing code, and (4) the 16 KB page-size transition — per Android's "Support 16 KB page sizes" guide, *"Starting November 1st, 2025, all new apps and updates to existing apps submitted to Google Play and targeting devices running Android 15 (API level 35) and higher must support 16 KB page sizes"* on 64-bit devices.
- This is a meaningful engineering effort with an inherent, unavoidable weakness (the key ships in the binary). It raises the bar against static analysis and casual RE but is defeated by any runtime memory dump. Scope it as an obfuscation/learning exercise, not real security.

## Key Findings

### The central constraint that dictates the whole architecture
On Android with `targetSdk ≥ 29`, an app runs in the `untrusted_app`/`untrusted_app_30` SELinux domain. AOSP `system/sepolicy` grants apps `allow appdomain self:process execmem` (in `public/app.te`, commented *"WebView and other application-specific JIT compilers"* — this is what lets WebView/ART JIT create anonymous executable memory), but it does **not** grant `execmod` on file-backed pages. `execmod` governs (per Stephen Smalley's kernel patch, LWN "Enhance SELinux control of executable mappings") *"the ability to make executable a previously written private file mapping, e.g. for text relocations."* That is exactly what happens if you `mprotect` the file-mapped `.text` to writable, decrypt (triggering copy-on-write), and then try to restore `PROT_EXEC`. That second `mprotect` fails with `EACCES` and logs `avc: denied { execmod } ... scontext=u:r:untrusted_app:s0 ... tclass=file`.

Historically AOSP `untrusted_app.te` contained `allow untrusted_app app_data_file:file { rx_file_perms execmod };` (comment: *"Some apps ship with shared libraries and binaries that they write out to their sandbox directory and then execute"*). That allowance was **removed for modern apps** in AOSP commit `b362474374afc402f65695252d30a008326c0eba` (*"Drop support for execmod (aka text relocations) for newer API versions. Retain it for older app APIs versions."*). It survives only for the legacy `untrusted_app_25`/`untrusted_app_27` domains (targetSdk ≤ 28). The current `private/untrusted_app_all.te` grants `execute` on `app_data_file`/`app_exec_data_file` but no `execmod`, and `private/app_neverallows.te` reinforces W^X: *"Shared libraries created by trusted components within an app home directory can be dlopen()ed. To maintain the W^X property, these files must never be writable to the app."*

**Conclusion: the classic UPX-style "decrypt the segment in place and jump back to the original VA" does not work for a modern app's own .so.** You must decrypt into anonymous memory and redirect.

### The four mechanisms that must all be handled
1. **Entry trigger without touching the linker**: `.init_array` constructor or `JNI_OnLoad`. The Android linker (`bionic/linker/linker.cpp`, `soinfo::call_constructors`) automatically calls `DT_INIT` then `DT_INIT_ARRAY` right after load/relocation, from `do_dlopen`. No linker modification needed — this is the intended extension point.
2. **The bootstrap paradox**: the decstub itself is code. If it lives in the encrypted `.text`, it cannot run. Keep the stub (and its constructor) in a separate, unencrypted section so the post-build tool encrypts everything *except* the stub.
3. **W^X-safe decryption**: anonymous `mmap` RW → decrypt → `mprotect` R-X → cache flush → redirect. Never RWX.
4. **arm64 cache coherency**: after writing decrypted code you MUST run the `DC CVAU / DSB ISH / IC IVAU / DSB ISH / ISB` sequence (or `__builtin___clear_cache`) or you will execute stale instructions and crash intermittently.

## Details

### 1. ELF64 / arm64 structure and the post-build rewriter

**Section vs. segment — which to encrypt.** An ELF has two parallel views:
- **Section headers** (`Elf64_Shdr`, `readelf -S`) describe `.text`, `.rodata`, `.data`, etc. Used at link time; not needed at runtime. `.text` has `sh_type=SHT_PROGBITS`, `sh_flags=SHF_ALLOC|SHF_EXECINSTR`. Its file bytes are `[sh_offset, sh_offset+sh_size)`.
- **Program headers** (`Elf64_Phdr`, `readelf -l`) describe `PT_LOAD` segments that the loader `mmap`s. The executable segment is the `PT_LOAD` with `p_flags = PF_R|PF_X` (`R E`).

For this project **encrypt at the .text SECTION granularity, not the whole executable PT_LOAD segment.** Rationale: the executable `PT_LOAD` on arm64 typically also contains `.plt`, `.init`, `.fini`, and code the linker touches during relocation. Encrypting the whole segment risks corrupting things the linker reads before your stub runs. Encrypting just `.text` (the bulk of the logic) is safer and sufficient. Keep your decstub OUT of `.text` (see §2).

Key ELF fact the tool must respect: **file offset ≠ virtual address.** `sh_offset`/`p_offset` are positions in the file; `sh_addr`/`p_vaddr` are load addresses. For a `PT_LOAD`, `p_offset` and `p_vaddr` must be congruent modulo `p_align` (the page size) so the kernel can `mmap` the file directly. The `load_bias` (chosen by ASLR) is added to `p_vaddr` at runtime; the runtime address of `.text` = `load_bias + sh_addr`.

**Post-build tool algorithm (runs on desktop, e.g. Python + LIEF or pyelftools, or C++ + LIEF):**
1. Parse `Elf64_Ehdr`, then `e_shoff`/`e_shnum`/`e_shentsize` to read section headers; find `.text` by name (via `.shstrtab`) or find the `SHF_EXECINSTR` PROGBITS section.
2. Record `sh_offset`, `sh_size`, `sh_addr`.
3. Read those bytes, encrypt (XOR / ChaCha20 / AES-CTR — CTR/stream avoids padding/length changes so file offsets are preserved), write them back at the same offset. **Do not change file size or any offsets** — this keeps all program headers valid.
4. Store metadata the stub needs (RVA of `.text` = `sh_addr`, length = `sh_size`, key/nonce) in a known place: a dedicated unencrypted data section you add, or a `__attribute__((section(".decinfo")))` struct that the tool locates and fills in.
5. Verify with `readelf -x .text libfoo.so` (bytes now look random) and `readelf -S`/`readelf -l` (unchanged layout).

Because arm64 never supported text relocations and NDK output is PIC, `.text` bytes are position-independent and can be relocated/copied to another address as long as you preserve GOT/PLT-based addressing (see §3 redirection).

### 2. Constructor / entry hooking without modifying the linker

**How the linker triggers you (no modification required).** `bionic/linker/linker.cpp`: `do_dlopen` → `find_library` → `soinfo::call_constructors()`, which runs `DT_NEEDED` children first, then `call_function("DT_INIT", init_func_)` (the `.init`/`DT_INIT`), then `call_array("DT_INIT_ARRAY", ...)`. So both `__attribute__((constructor))` functions (whose pointers the compiler places in `.init_array`) and a raw `DT_INIT` fire automatically at load. `JNI_OnLoad` fires later, when Java calls `System.loadLibrary`, via ART calling `dlsym(handle,"JNI_OnLoad")`.

**Choose the trigger:**
- **`.init_array` constructor** — earliest, fires on plain `dlopen`, works even if the lib is loaded natively. Use `__attribute__((constructor)) static void dec(void){...}`. Priority form `__attribute__((constructor(101)))` runs before higher numbers; 101–65535 are user-usable (0–100 reserved for the implementation). Constructors with the same priority run in `.init_array` order (file order).
- **`JNI_OnLoad`** — convenient if the lib is loaded from Java; you get a `JavaVM*`. Fires after all constructors.

Real Android packers overwhelmingly use `JNI_OnLoad`-triggered decryption. Tencent's **Legu** packer (analyzed by Romain Thomas, Quarkslab, versions 4.1.0.15/4.1.0.18; libs `libshell-super.2019.so` + `libshella-4.1.0.XY.so`) decrypts from `JNI_OnLoad`, using a modified XTEA with a hardcoded key plus NRV compression, and even *replaces the original `JNI_OnLoad` with a new one located in the first decrypted segment*. The **"WeddingCake"** anti-analysis library (Maddie Stone, Google — VB2018 "Unpacking the packed unpacker", found in *"more than 5,000 Android malware samples, including newer variants of the Chamois ad fraud malware"*) does in-place decryption of byte arrays from `JNI_OnLoad`: *"the JNI_OnLoad() function ends with many calls to the same function ... the subroutine at 0x2F30 (sub_2F30) is the in-place decryption function."*

Recommendation for this project: use an **`.init_array` constructor** for the decryption bootstrap so it works regardless of how the .so is loaded, and so it runs before any exported function can be called.

**Solving the bootstrap paradox — keep the stub unencrypted.** The decstub (constructor + decrypt routine + cache-flush + redirection logic) must not be encrypted. Options, in order of robustness:
- **Separate source file + section attribute.** Put all stub code in `decstub.c`, compile with `-ffunction-sections`, then place it via `__attribute__((section(".decstub")))` on each function, or a linker-script fragment mapping `decstub.o(.text)` into an output section named `.decstub`. The post-build tool encrypts `.text` but explicitly skips `.decstub`.
- **Verification:** `readelf -S` (confirm `.decstub` is `AX` and disjoint from `.text`), `objdump -d -j .decstub` (routines present and valid).
- The stub must be **self-contained**: it may call `libc`/`libdl` (already loaded, already relocated) but must not call any function that lives in the encrypted `.text`. Keep it minimal C.

**Relocation / RELRO ordering.** By the time your constructor runs, the linker has applied all relocations and applied `GNU_RELRO` (`soinfo::protect_relro()` → `mprotect(PT_GNU_RELRO range, PROT_READ)` before constructors). With `-Wl,-z,relro,-z,now` (BIND_NOW, the NDK default), the GOT is resolved and read-only. So you cannot patch the GOT after RELRO without re-`mprotect`ing it — the decrypted-copy-with-remap approach (§3) avoids depending on GOT patching.

### 3. Runtime memory mechanics (must survive W^X / SELinux / XOM)

**Do NOT do in-place (confirmed blocked).** In-place = `mprotect(text_page, len, PROT_READ|PROT_WRITE)`, decrypt, `mprotect(..., PROT_READ|PROT_EXEC)`. The final call triggers `execmod` on the file-backed, now-COW-dirtied page → `avc: denied { execmod }` → `EACCES`. Enforced for all apps targeting API ≥ 29. Drepper's canonical SELinux-memory reference and AOSP sepolicy both confirm this is the textbook `execmod` trigger.

**The working design — decrypt into anonymous memory (execmem path):**
```c
// 1. Allocate anonymous RW memory (NOT executable yet). execmem is allowed to appdomain.
size_t pg  = sysconf(_SC_PAGESIZE);          // 4096 or 16384 — never hardcode
size_t len = (text_size + pg - 1) & ~(pg-1);
void *copy = mmap(NULL, len, PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// 2. Copy the (still-encrypted) .text bytes, then decrypt in the copy.
memcpy(copy, (void*)(load_bias + text_sh_addr), text_size);
decrypt(copy, text_size, key, nonce);
// 3. Flip to R-X (W^X-safe: was never W+X simultaneously).
mprotect(copy, len, PROT_READ|PROT_EXEC);    // execmem check, allowed
// 4. Flush caches BEFORE executing (see cache section).
__builtin___clear_cache((char*)copy, (char*)copy + len);
```
`mmap(MAP_ANONYMOUS|MAP_PRIVATE)` then `mprotect(...PROT_EXEC)` is covered by `allow appdomain self:process execmem` — the same mechanism ART's JIT uses — so it is reliably permitted on stock devices without root.

**Redirection — how the rest of the library uses the decrypted copy.** The copy is at a different address than the original `.text`, and the rest of the loaded library still references the original VA. Options:
- **(A) Function-pointer / trampoline dispatch (simplest, recommended for a minor project).** Structure the protected code as functions reached only through a table of pointers that the stub rewrites to point into `copy` (offset = original function RVA − `.text` sh_addr). arm64 code is PIC and uses PC-relative branches, so a copied function that only branches within the copy (identical relative offsets, because you copy the whole `.text` blob) works. **Caveat:** PC-relative references (`ADRP`/`ADR`/`LDR` literal) from copied code to the *original* `.rodata`/GOT/PLT are off by `(copy_base − original_text_base)`, which is not a fixed page offset — this is the core limitation of leaving the copy at a fresh address.
- **(B) `mremap` + `MREMAP_FIXED` onto the original base (recommended for transparent correctness).** `mmap` anon RW elsewhere, decrypt, then `mremap(copy, len, len, MREMAP_MAYMOVE|MREMAP_FIXED, orig_text_base)` to move the pages onto the original `.text` virtual address, then `mprotect` R-X and flush caches. Moving to the original base makes every PC-relative reference valid again. Because the destination is an **anonymous** mapping (not the file), the exec `mprotect` is an `execmem` check, not `execmod` — so it is allowed. Round base and length to page size; the original file-backed `.text` mapping is replaced by the fixed mremap.

**XOM (execute-only memory) — a non-issue for you.** Per AOSP's "Execute-only memory (XOM) for AArch64 binaries": *"XOM support has been removed in the upstream Linux kernel. XOM is only supported in Android 10 and has been removed in Android 11 and kernel changes removing it have been backported to 4.9, so the common kernel no longer supports XOM."* (It was dropped because it broke PAN.) It only ever applied to *system* libraries, not app-loaded ones. Map your decrypted copy `PROT_READ|PROT_EXEC` (readable) — simplest and normal. Implication if you ever made pages exec-only: you could not read them back to re-encrypt or checksum, so decrypt-once and leave R-X.

**Cache coherency (mandatory on arm64).** arm64's I and D caches are not coherent for self-modifying code. After writing decrypted bytes and before executing, per the Arm ARM (DDI 0487) and Arm's "Caches and Self-Modifying Code" guidance, for each line: `DC CVAU` (clean D-cache to Point of Unification) → `DSB ISH` → `IC IVAU` (invalidate I-cache to PoU) → `DSB ISH` → `ISB` (flush pipeline). Line size comes from `CTR_EL0`. **Just call `__builtin___clear_cache(start, end)`** — the compiler-rt/libgcc implementation emits exactly this sequence and loops over cache lines. Run it on the thread that will execute the code (the final `ISB` is not broadcast to other cores). Do not rely on `mprotect` for i-cache coherency.

### 4. Key management (brief — minor project)
The unavoidable truth: **the key ships with the binary, so anyone who can run the app can recover the plaintext** by dumping the decrypted anonymous region from `/proc/self/maps` at runtime. Pragmatic choices:
- **Baseline:** hardcode a 256-bit key + nonce in `.decstub`, use ChaCha20 or AES-CTR (stream ciphers preserve length/offsets — important for the rewriter). XOR is fine for a pure learning exercise and is what the simplest ELF/PE `.text` packers use.
- **Slightly better:** derive the key at runtime from something not stored verbatim — e.g. a value computed from the APK signing certificate hash (`PackageManager.GET_SIGNING_CERTIFICATES` passed into JNI) or a string assembled at runtime. Defeats trivial `strings`/static key extraction, not a debugger.
- Don't over-invest: any of these is broken by a single Frida hook on `decrypt()` or a post-decryption memory dump. This is obfuscation, not cryptographic protection.

### 5. Build / packaging pipeline
1. **Build normally** with the NDK (arm64-v8a, `-fPIC` default; BIND_NOW/RELRO default). Protected logic in one or more `.c` files; decstub in `decstub.c`.
2. **Isolate the stub** into its own section: compile with `-ffunction-sections -fdata-sections`; assign via `__attribute__((section(".decstub")))` or a linker script. Ensure the constructor pointer lands in `.init_array` (from `__attribute__((constructor))`).
3. **16 KB page size (mandatory for Play, API 35, since Nov 1 2025):** build with **NDK r28+** (16 KB-aligned by default) or pass `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384` on r27 or lower; AGP 8.5.1+ aligns packaging. Verify with `llvm-objdump -p libfoo.so | grep LOAD` (align must be `2**14`, not `2**12`). In the stub, always use `getpagesize()`/`sysconf(_SC_PAGESIZE)` — never hardcode 4096.
4. **Run the post-build encryptor** on the release `.so`: encrypt `.text`, skip `.decstub`, fill the `.decinfo` metadata struct (text RVA, size, key, nonce). Keep file size/offsets identical.
5. **Verify:** `readelf -S` (layout unchanged), `readelf -x .text` (random bytes), `readelf -l` (LOAD align correct), `readelf -d | grep TEXTREL` (must be empty — text relocations refused since API 23), `objdump -d -j .decstub` (stub valid).
6. **Package** into the APK/AAB under `lib/arm64-v8a/`. Test on a 16 KB emulator image (Android Studio SDK Manager → API 35 "16 KB" system image) and a real device.

### 6. Prior art (brief pointers)
- **UPX** (John Reiser's ELF work): the canonical self-decompressing stub — a tiny stub in the first `PT_LOAD` decompresses the rest directly into address space then jumps to entry. It writes into W+X pages, which is exactly why the UPX mechanism does **not** port to modern Android apps under SELinux/W^X. Study it for the stub concept, not the memory mechanics.
- **Tencent Legu / SecNeo / Bangcle / Ijiami** (commercial Android packers): analyzed by Quarkslab (Romain Thomas). Decrypt from `JNI_OnLoad`, XTEA/ChaCha20 with hardcoded or derived keys, and replace `JNI_OnLoad` in the first decrypted segment. Confirms `JNI_OnLoad`-triggered decryption is the industry-standard pattern — but note that Quarkslab's `legu_unpacker_2019` statically recovers the original DEX (sample output: *"[+] Legu version: 4.1.0.15 [+] Password is 'IPk2Hw7AKTuIQBlc'"*), a reminder that shipped keys are recoverable.
- **"WeddingCake"** (VB2018, Maddie Stone): minimal in-place decrypt-from-`JNI_OnLoad` structure; good example of the trigger+decrypt pattern.
- **Open-source ELF/.text packers on GitHub**: `woody_woodpacker` (encrypts `.text`, injects a shellcode stub via PT_NOTE-to-PT_LOAD or segment-padding codecave — good reference for the rewriter's ELF surgery), `SamLarenN/PePacker` (PE, XOR `.text` + decryption stub). Both target desktop, not W^X-constrained Android.
- **Academic**: NORAX (IEEE S&P 2017) on XOM for COTS arm64 binaries; general self-modifying-code / packing literature.

### 7. Pitfalls / gotchas on modern arm64 Android
- **16 KB pages (biggest one).** Never assume 4096. All `mmap`/`mprotect`/`mremap` lengths and bases must round to `sysconf(_SC_PAGESIZE)`. A 4 KB assumption crashes on 16 KB devices; unaligned LOAD segments fail to load. Play requires 16 KB support for API 35 uploads since Nov 1 2025.
- **`execmod` vs `execmem`.** File-backed modified-then-exec = `execmod` = denied. Anonymous alloc-then-exec = `execmem` = allowed. The entire design hinges on staying on the `execmem` path.
- **W^X.** Never request `PROT_WRITE|PROT_EXEC` together (mmap or mprotect). Always RW → write → R-X.
- **PC-relative addressing after copy.** If you copy `.text` to a different base without moving it back to the original VA, references into `.rodata`/GOT/other segments break. Use `mremap`+`MREMAP_FIXED` onto the original `.text` base to keep every address valid.
- **RELRO.** With BIND_NOW+RELRO (NDK default) the GOT is read-only by the time your constructor runs. Don't plan on patching the GOT without re-`mprotect`ing it; prefer the mremap-onto-original-base approach.
- **No text relocations.** Since API 23 the linker refuses `.so`s with `DT_TEXTREL`/`TEXTREL` flag (*"on API 23 and above it refuses to load code with text relocations"*). Don't let your rewriter introduce them; keep code PIC.
- **Cache flush.** Omitting `__builtin___clear_cache` causes non-deterministic crashes (works in debug, fails under load) from stale i-cache lines.
- **file offset vs vaddr.** The rewriter edits file offsets; the stub works in virtual addresses (`load_bias + sh_addr`). Get `load_bias` from `dl_iterate_phdr` or the loaded base.
- **ptrace / anti-debug.** Frida/`ptrace` can still hook your `decrypt()` regardless of anti-debug; keep it out of scope unless learning it is a goal.
- **Threading.** Decrypt in the constructor (single-threaded, before any exported function is reachable) to avoid another thread executing half-decrypted or stale-cache code.
- **Self-inspection.** Find your own load base and `.text` at runtime via `dl_iterate_phdr` (match soname) or `/proc/self/maps`. Never hardcode addresses (ASLR).

## Recommendations (staged)
1. **Phase 0 — prove the memory path in isolation.** Before any ELF surgery: write a tiny .so whose constructor `mmap`s anon RW, memcpys a known function's bytes, `mprotect`s R-X, `__builtin___clear_cache`s, and calls it. Confirm it runs on a real Android 14/15 device *and* a 16 KB emulator. This validates the riskiest assumptions (`execmem` + W^X + cache) before investing in the packer. **Threshold to proceed:** no `avc: denied`, no SIGSEGV on either device.
2. **Phase 1 — mremap correctness.** Extend Phase 0 to `mremap`+`MREMAP_FIXED` the decrypted copy onto the original `.text` base; confirm functions that use `.rodata` strings and call helpers still work. **Threshold:** a function referencing a global string and calling a helper returns correct results.
3. **Phase 2 — build the desktop rewriter.** Use LIEF or pyelftools: locate `.text`, encrypt with AES-CTR/ChaCha20 (length-preserving), skip `.decstub`, populate `.decinfo`. **Threshold:** re-`readelf`/`objdump` shows unchanged layout, random `.text`, valid `.decstub`, no `TEXTREL`.
4. **Phase 3 — integrate + test matrix.** Test on Android 14 (4 KB), Android 15/16 (16 KB emulator + Pixel 8/9 in 16 KB developer mode), arm64 only. Watch `logcat | grep avc` for denials. **Threshold to ship:** clean load + correct behavior on all targets.
5. **Only if you need transparency for the whole library**, invest in the mremap-onto-original-base path; if you can restructure protected logic behind a pointer table, the trampoline path is far less error-prone.
6. **Do not spend effort on key hardening** beyond a runtime-derived key — the design is inherently defeatable by memory dump.

**What would change these recommendations:** if the target devices are rooted/engineering builds, in-place decryption with a custom SELinux policy becomes possible (drop the mremap complexity). If you only ever load the .so from Java, `JNI_OnLoad` becomes a simpler trigger than `.init_array`. If you must support 32-bit (armeabi-v7a), revisit text-relocation and cache-flush details (different from arm64).

## Caveats
- **Security value is limited by design.** The key ships in the binary; plaintext exists in a readable R-X anonymous mapping at runtime. Any attacker with Frida, a debugger, or a `/proc/self/maps` dump recovers everything. Treat this as anti-static-analysis obfuscation and a systems-programming exercise. Even hardened commercial packers (Legu) are statically unpacked by researchers.
- **Device variance.** SELinux policy, kernel W^X enforcement, and page size vary across OEMs/ROMs. The anonymous `execmem` path is broadly supported (it's how ART JIT works) but test on target hardware. Some hardened ROMs (GrapheneOS-style) may restrict even `execmem`.
- **XOM specifics** reflect AOSP docs: enforced only in Android 10 for system libs, removed in 11+. For your own app .so this does not apply.
- **The `mremap`/`MREMAP_FIXED` over the original file-backed mapping** is the least-tested corner and may interact with the linker's `soinfo` bookkeeping; validate carefully in Phase 1. The alternative is to leave the original mapping and use the pointer-table trampoline, accepting the PC-relative limitation.
- Some sources here are practitioner blogs (FunWithLinux, Medium) used for corroboration; the load-bearing facts (SELinux `execmod`/`execmem` rules, linker behavior, arm64 cache sequence, 16 KB policy, XOM history) rest on AOSP source/commits, the Arm architecture documentation, and official Android developer/AOSP documentation.
