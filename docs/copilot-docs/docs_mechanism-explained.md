# sopack, explained from zero

> Read this **before** any code. It assumes you know nothing about `.so` files,
> how Android loads a library, ARM64, `DT_INIT`, `mmap`, SELinux, or ELF. Every
> term is built up from scratch. By the end you'll understand *the whole idea* —
> what sopack does, and **why every part of it has to be exactly the way it is**.

---

## 1. What problem is this even solving?

An Android app is a `.apk` file (a ZIP). Inside it there are usually some
**native libraries** — files named like `libfoo.so`. These contain compiled
machine code (C/C++/Rust/Dart), not Java. When the app starts, Android loads
those `.so` files into memory and runs their code.

The problem sopack solves: **you want to hide the machine code inside a `.so`
so that someone who unzips your APK and opens the `.so` in a disassembler
can't just read your algorithms.**

The twist that shapes *everything*: **you do not have the source code of the
library.** You only have the finished, already-compiled `.so` file. So you
can't just "add a decrypt step at compile time." You have to take a **finished
binary** and surgically modify it. This is called a **packer** (the same
category as commercial tools like Tencent Legu).

The honest limit, stated once so you're never confused later:

> **This is obfuscation, not real security.** The key to decrypt the code has
> to ship *inside* the app (there's nobody else to ask for it), and once the
> app runs, the real code sits decrypted in memory where anyone with a debugger
> can copy it. sopack makes *static* analysis (reading the file without running
> it) much harder. It does **not** stop someone who runs the app and dumps
> memory. Don't oversell it.

---

## 2. The 30-second version of the whole idea

1. **Scramble (encrypt) the code** bytes inside the `.so` so the file on disk
   is gibberish.
2. **Glue on a tiny piece of your own code** (called the **stub**) that knows
   how to un-scramble it.
3. **Arrange for the stub to run first**, the instant the library loads,
   *before* any of the scrambled code is used.
4. The stub **decrypts the real code in memory**, puts it back exactly where
   the library expects it, and then lets the library run normally.
5. **Re-zip and re-sign** the APK.

Everything below is *why each of those five steps is surprisingly hard on modern
Android*, and how sopack handles it. The hard parts all come from **how Android
actually loads and protects code** — so we have to understand that first.

---

## 3. Background you need (built from zero)

### 3.1 What is a `.so` file? (ELF, sections, segments)

A `.so` ("shared object") is a file in the **ELF** format — the standard
container for executables and libraries on Linux/Android. Think of ELF as a box
with a **table of contents** describing chunks of bytes. Two different "views"
of those chunks matter:

- **Sections** — the *fine-grained, tool-oriented* view. Named regions like:
  - `.text` = the actual **executable machine code** (this is what we encrypt).
  - `.rodata` = read-only constants (strings, tables).
  - `.data`/`.bss` = writable variables.
  - `.dynamic` = a small control table the loader reads (very important below).
  - The list of sections lives in the **section header table**.
- **Segments** (a.k.a. **program headers**, `PT_LOAD`) — the *coarse, loader-oriented*
  view. When Android loads the library, it doesn't care about section names; it
  reads the program headers, which say *"map these byte ranges into memory with
  these permissions (read/write/execute)."*

So: **sections are for tools, segments are for the loader.** A single executable
segment typically *contains* `.text` plus a few other code-ish sections.

> **Why sopack encrypts the `.text` *section*, not the whole executable
> *segment*.** The executable segment also holds things like `.plt`/`.init`
> that the loader *touches while it's still setting the library up* — before our
> stub gets to run. If we encrypted those, they'd be gibberish exactly when the
> loader needs them, and the load would crash. Encrypting only `.text` is both
> safer and enough.

### 3.2 What "loading a `.so`" actually means

When the app calls `System.loadLibrary("foo")`, Android's **dynamic linker**
(on Android it's called **bionic**) does roughly:

1. **`mmap` the file** — map its `PT_LOAD` segments into the process's memory at
   some base address.
2. **Relocation** — patch up addresses inside the library (more on this in 3.4).
3. **Run initializers** — call the library's "startup" hooks (this is our entry
   point — see 3.5).
4. Hand control back; the app can now call functions in the library.

Our stub needs to sneak into step 3, **before** any real code runs.

### 3.3 ASLR and "we don't know our own address"

Modern systems use **ASLR** (Address Space Layout Randomization): every time the
library loads, it's placed at a *different, random* base address in memory. This
is a security feature. The consequence for us: **we can't hardcode any address.**
The stub, at runtime, doesn't magically know "the code is at address X."

sopack's clever answer to this is in section 5.3 — remember this problem exists.

### 3.4 Position-independent code and "relocations"

Because of ASLR, libraries are compiled as **PIC** (position-independent code):
the code works no matter where it's loaded. But some things (like "a pointer to
function Y") genuinely need a real address filled in once the load base is
known. Those spots are patched by the loader using a list of **relocations** —
little instructions that say *"at file offset N, write (load_base + addend)."*

Two takeaways you'll need later:

- A relocation runs **at load time** and **overwrites** whatever bytes were in
  the file at that spot. (This causes the single nastiest bug sopack had to
  solve — section 6.)
- `R_*_RELATIVE` is the common relocation type meaning "load_base + a fixed
  addend."

### 3.5 How a library runs code "on startup": `DT_INIT` and `DT_INIT_ARRAY`

This is the concept you specifically asked to have explained deeply, so here it
is from the ground up.

A library can ask the loader: *"run this function of mine automatically as soon
as I'm loaded."* These are **initializers** (think: C++ global constructors, or
`__attribute__((constructor))` functions). There are two mechanisms, and their
**difference is the heart of sopack's correctness**:

- **`DT_INIT`** — a *single* entry stored in the `.dynamic` control table. It's
  literally one field that says "the address of one init function." The loader
  calls it first.
- **`DT_INIT_ARRAY`** — a *list* (array) of init function pointers. The loader
  walks the array and calls each one. Modern C++/NDK libraries almost always use
  this (each global constructor gets a slot).

The exact order bionic uses is fixed and documented in its
`soinfo::call_constructors()`:

> **`DT_INIT` runs first, then every entry in `DT_INIT_ARRAY`.**

That ordering is *gold* for us: if we can make our stub the `DT_INIT`, we are
guaranteed to run **before** all of the library's own constructors — which is
exactly the window we need to decrypt the code before anything uses it.

**What `.dynamic` is:** a small table of `(tag, value)` pairs the loader reads.
Tags include `DT_INIT` (address of the init function), `DT_INIT_ARRAY` (address
of the array), `DT_HASH` (a symbol-lookup table), and `DT_NULL` (the tag value
`0`, which means **"end of table — stop reading here"**). Remember `DT_NULL` as
the terminator — sopack exploits it in section 6.

### 3.6 Memory permissions and "W^X"

Every page of memory has permissions: **R** (read), **W** (write), **X**
(execute). A core security rule on modern systems is **W^X** ("write XOR
execute"): a page should never be **writable and executable at the same time**,
because that's exactly what code-injection exploits need. So:

- To *change* code you need it Writable.
- To *run* code you need it eXecutable.
- You're not allowed to have both at once.

The normal dance is: write while it's `RW`, then flip it to `R-X` before running.
This W^X rule collides head-on with "decrypt code in place," and how Android
enforces it is the single biggest constraint on the whole design (section 4).

---

## 4. The four hard constraints of modern Android (why the "obvious" way fails)

Everything in sopack's design exists to satisfy these four properties of Android
(API 29+). Getting any one wrong means a crash, a security denial, or a flaky bug.

### 4.1 The big one: `execmem` is allowed, `execmod` is denied

Android confines each app with **SELinux**, a mandatory security policy. An app
runs in a domain called `untrusted_app`, which is allowed to do some things and
forbidden from others. Two permissions matter:

- **`execmem`** — "make **anonymous** memory executable." *Anonymous* memory
  means memory not backed by any file — a fresh scratch buffer. This is
  **allowed** (it's how the Java JIT and WebView work).
- **`execmod`** — "re-add execute permission to a **file-backed** page that the
  process has **modified**." This is **denied**.

Now see why the textbook packer approach (like PC's UPX) is **impossible** here:

> Textbook approach: take the file-mapped `.text`, make it writable, decrypt it
> in place, make it executable again.

That last "make it executable again" touches a **modified, file-backed** page →
that's the **`execmod`** check → **denied** → the load fails. So:

> **sopack can never decrypt `.text` in place on its file mapping.** It must
> decrypt into *fresh anonymous* memory (the `execmem` path) instead.

This single rule is the reason for the elaborate "mmap → decrypt → move it back"
dance you'll see in section 5.4. Keep it in mind.

### 4.2 Never Write+Execute at the same moment

The scratch buffer is `RW` while we're writing plaintext into it, then flipped to
`R-X` before anything executes from it. It is never both at once. (W^X, from 3.6.)

### 4.3 ARM64 instruction-cache coherency

**ARM64** is the 64-bit ARM CPU architecture that basically all modern Android
phones use (the ABI is called `arm64-v8a`). ARM64 CPUs have separate caches for
**data** and **instructions**, and — unlike x86 — they are **not automatically
kept in sync** for freshly written code.

Concretely: we just wrote decrypted instructions into memory (that went through
the *data* path). If we jump to that memory, the CPU's *instruction* cache may
still hold the **old, stale** bytes → random crashes. So after decrypting, on
ARM64 we must run the architecture's cache-maintenance sequence
(`DC CVAU → DSB ISH → IC IVAU → DSB ISH → ISB`, i.e. "flush the I-cache") on the
same thread that will run the code. (32-bit ARM uses a `cacheflush` syscall;
x86_64 caches are coherent and need nothing.)

### 4.4 16 KB pages (Android 15+)

Memory is managed in fixed-size chunks called **pages**. For years Android pages
were **4 KB**. Newer 64-bit devices (Android 15+) use **16 KB** pages, and since
late 2025 Google Play requires apps to support them. Every block we add and every
memory operation must be aligned to the **page size** — and crucially, sopack
**reads the real page size at runtime** from the kernel rather than assuming,
because it could be 4 KB or 16 KB depending on the device. The injected code
block is aligned to 16 KB so it loads correctly on both.

---

## 5. How sopack works, step by step

sopack is three pieces plus a thin command-line wrapper:

```
sopack
 ├─ (1) the stub          a tiny C program, pre-compiled once per CPU type
 ├─ (2) the ELF injector  Python: encrypts .text, grafts in the stub, hijacks init
 └─ (3) the APK repackager Python: unzip → inject → align → re-sign
```

They communicate through **one 128-byte record** called `sopk_decinfo` — a fixed
struct defined *identically* in C (`stub/decinfo.h`) and Python
(`sopack/metadata.py`). The injector fills it in; the stub reads it. Think of it
as a **note the desktop tool leaves for the runtime stub**: "here's the key,
here's how big the code is, here's where to find it."

### 5.1 Step 1 — Encrypt the code

The injector finds the `.text` section and encrypts its bytes with a **stream
cipher** — either **ChaCha20** (a well-known real cipher) or plain **XOR** (weak,
for testing). A stream cipher is chosen deliberately because it's
**length-preserving**: the encrypted bytes are exactly as long as the originals,
so nothing in the file shifts — same size, same offsets, ELF layout untouched. A
fresh random key + nonce is generated per library and stored in the note.

### 5.2 Step 2 — Graft the stub in as a new executable block

The **stub** is the small piece of decryptor code that will run on the device.
It's pre-compiled once per CPU type into a flat blob and shipped inside sopack.
The injector appends it to the `.so` as a **new `PT_LOAD` segment** with `R+X`
(read+execute) permission, aligned to 16 KB. (sopack uses a library called
**LIEF** to do this ELF surgery safely — LIEF inserts the new program header and
fixes up all the other addresses to stay consistent.)

### 5.3 The stub is "freestanding" — and how it finds itself under ASLR

This is one of the elegant parts. The stub is injected into *someone else's*
finished library. That means it **cannot rely on anything external**: no libc, no
imported functions, no relocations of its own — there's nothing to link them
against, and a stray relocation would corrupt the host library. So the stub is
**freestanding**: it makes raw Linux **syscalls** directly, brings its own
`memcpy` and cipher, and reads the page size itself.

But remember the ASLR problem (3.3): the stub doesn't know its own runtime
address. The trick:

> The stub carries the 128-byte note (`g_decinfo`) inside its own segment, and the
> compiler references that note **PC-relatively** — i.e. "relative to where I'm
> currently executing." So at runtime the stub gets `&g_decinfo` **for free**,
> with no hardcoded address and no load base needed.

Then **every address it needs is stored as a signed *offset* from that note**:

```
runtime address of .text        = &g_decinfo + delta_text
runtime address of original init = &g_decinfo + delta_init   (only if chaining)
```

The injector, which *does* know the file layout, computes those deltas and writes
them into the note. No load bias ever required. That's why the note stores
`delta_text`/`delta_init` (offsets) instead of absolute addresses.

> **A deep ARM64 gotcha that cost a debugging session.** "Reference PC-relatively"
> on ARM64 can be done two ways: `adr` (a **byte**-accurate relative address) or
> `adrp`+`add` (a **page**-aligned relative address). `adrp` only lands correctly
> if the segment sits at a page-aligned virtual address — and the injection tool
> sometimes places it at a *non*-page-aligned address, so `adrp` would compute the
> note's location slightly *wrong*, the stub would read the key from the wrong
> place, and you'd get a garbage decrypt. The fix: build the ARM64 stub with
> `-mcmodel=tiny`, which forces the byte-accurate `adr`, and the build script
> *refuses to ship* an ARM64 stub that contains any `adrp`. (x86_64 and 32-bit ARM
> are byte-relative already.)

### 5.4 Step 4 — What the stub does at load time (the `execmem` dance)

When the loader calls the stub (as `DT_INIT`), it performs the following. Every
step here is dictated by a constraint from section 4:

1. **De-whiten and read the note** (whitening is explained in section 7), and
   check a magic value to confirm it was really patched. If not, it just chains
   through — "**fail open**," never crash.
2. Compute the page-aligned window around `.text` and **`mmap` fresh anonymous
   `RW` memory** the size of that window. *(Anonymous, because of the
   `execmem`-vs-`execmod` rule — 4.1.)*
3. **Copy** the encrypted window in and **decrypt only the exact `.text`
   sub-range** (the partial neighbor bytes at the window edges were never
   encrypted, so they're left alone).
4. **`mremap(..., MREMAP_FIXED)` the decrypted pages onto the *original* `.text`
   virtual address.** This is the crucial move:
   - The destination becomes an **anonymous** mapping → the later "make it
     executable" step is an **`execmem`** check (allowed), never `execmod`
     (denied). *(4.1.)*
   - Putting the code **back at its original address** keeps every PC-relative
     reference, every function-pointer table (GOT/PLT), and every C++ exception
     unwind table **still valid** — because they were all computed for that
     address. If we ran the code from some other address, all those would point
     to the wrong place.
   - *Fallback:* if a particular device refuses `MREMAP_FIXED` over a file
     mapping, the stub instead unmaps that window and maps fresh anonymous pages
     at the same address, then copies the decrypted bytes in — same `execmem`
     result, different kernel path.
5. **`mprotect` the window to `R-X`** (write phase over, execute phase begins —
   W^X preserved, 4.2), **flush the instruction cache** on ARM64 (4.3), and then
   **chain the original init** if we displaced one (5.5).

If any syscall fails, the stub **fails open** (jumps to the chain/return path)
rather than crashing — so a mis-encrypted library degrades gracefully during
debugging instead of hard-crashing. With `--log`, it emits a staged log line at
each step so you can see exactly how far it got.

> **Two subtle correctness rules baked into the stub:**
> - The note (`g_decinfo`) is declared **`volatile`**. The injector patches it
>   *after* compilation. If it weren't `volatile`, the compiler would "helpfully"
>   assume `text_size == 0` (its initial value) and **delete the entire stub as
>   dead code**. (This actually shipped once as a 130-byte do-nothing "stub.")
> - Raw syscalls return **`-errno`**, not `-1`. Error checks look for a return in
>   `[-4095, -1]`, not `== MAP_FAILED`. Getting this wrong once made a failed
>   `mmap` look like success.

### 5.5 "Chaining" the original init

If the library already had a `DT_INIT` and we took its place, we must not lose the
original — so the injector records the original's offset (`delta_init`), and after
decrypting, the stub **calls the original init** (forwarding the same
`argc/argv/envp` bionic would have passed). That's "chaining." If we *added* a new
`DT_INIT` where there was none, there's nothing to chain.

---

## 6. The hardest part, explained slowly: hijacking the init (the libflutter crash)

We need our stub to be the **first** thing that runs. From section 3.5 we know
`DT_INIT` runs before `DT_INIT_ARRAY`. So there are two situations:

**Case A — the library already has a usable `DT_INIT`.**
Easy: repoint that single `.dynamic` field to our stub, and chain the original
(5.5). `DT_INIT` lives in `.dynamic` and is **not** touched by relocations, so
repointing it is stable and safe.

**Case B — the library has no usable `DT_INIT` (it only uses `DT_INIT_ARRAY`, or
nothing).** This is the common case — it's the shape of `libflutter.so` and most
NDK-built C++ libraries. The tempting idea is: *"just overwrite the first entry
of `DT_INIT_ARRAY` with a pointer to our stub."* **This is a trap, and it's the
bug that taught the whole project a lesson.**

Here's why it fails, and it ties directly back to relocations (3.4):

> Every Android `.so` is position-independent. So each slot of `DT_INIT_ARRAY` is
> **not** a fixed pointer in the file — it's filled in **at load time by an
> `R_*_RELATIVE` relocation**. In the file the slot reads `0` (or an addend). If
> we overwrite that slot with our stub's address, the loader then **runs the
> relocation and overwrites our value back** to the original constructor's
> address. Our write is **silently reverted.** The stub never runs, `.text` stays
> encrypted, and the library's real constructor executes **encrypted bytes** →
> `SIGILL` (illegal instruction) crash inside the init-array loop.

That was the real `libflutter.so` crash. The lesson:

> **Never hijack `DT_INIT_ARRAY`.** Instead, **add a `DT_INIT`** — because
> `DT_INIT` is not relocated *and* runs before the array anyway.

**But how do you add a `DT_INIT` entry without breaking everything?** The naive
way — ask LIEF to add a new `.dynamic` entry — makes `.dynamic` grow, which forces
it into a new 4 KB-aligned segment. That breaks 16 KB loading (4.4) *and* makes
bionic reject the library. So sopack does careful, hand-rolled surgery instead:

> **The `DT_NULL` trick.** Recall `DT_NULL` (tag `0`) is the "end of table"
> terminator (3.5). sopack **overwrites the existing `DT_NULL` terminator with a
> `DT_INIT` entry**, relying on the *next* word being zero so it becomes the new
> terminator. `.dynamic` doesn't grow and doesn't move — only the new 16 KB stub
> segment is added.

There's a subtlety that makes this safe: whether the slot after the terminator
reads as `DT_NULL` at runtime is decided by the segment's declared in-memory size
(bytes beyond the file contents are **kernel zero-filled**), not by whatever
happens to sit there in the file. And bionic stops at the first entry whose **tag
word** is zero, ignoring its value — so even a "tag `0`, non-zero value" slot is a
valid terminator. sopack checks these exact runtime conditions and **refuses
loudly** if they don't hold, rather than silently corrupting the library. (When
the simple in-place trick isn't possible — e.g. an x86-64 layout quirk — it falls
back to repurposing a redundant `DT_HASH`, or as a last resort growing `.dynamic`
via LIEF, each guarded so it never bricks the library.)

Finally, the injector runs a **`_self_verify()`** pass before emitting anything.
It re-opens its own output and asserts every runtime assumption, including a
**loader-aware check**: that `DT_INIT` really points at the stub — i.e. what the
loader will actually call first, *not* a value a relocation would overwrite. That
one check would have caught the libflutter crash at pack time instead of on the
phone.

---

## 7. Making static analysis harder: "whitening"

Encrypting `.text` isn't enough by itself, because the key has to travel with the
app inside that 128-byte note. In the first version, the note started with a
constant magic value `"SOPK"`. An analyst's attack was trivial:

> `grep` the file for `SOPK`, read the 128-byte struct at that offset, lift the
> 32-byte key and the code's location/size, and decrypt everything with a ~10-line
> script — **without ever running the app.**

The magic and the plaintext key were two giant signposts. The fix is **whitening**
(the note is scrambled at rest):

- The whole 128-byte note is XOR-masked with a keystream whose **key is a checksum
  the stub computes over its own code bytes** (the 1024 bytes just before the note
  — real code the injector never rewrites). **No new secret is stored anywhere** —
  the recipe lives inside the stub's own instructions.
- **Consequence 1:** the constant `SOPK` magic **never appears in the shipped
  file**, so the grep-and-decrypt attack finds nothing. The injector even asserts
  the magic byte-pattern is absent from its output.
- **Consequence 2:** the key/size/offsets are just noise on disk. To recover them
  you now have to reproduce the checksum-and-keystream derivation — i.e. actually
  **reverse-engineer the stub**, a real RE session instead of a one-liner.
- **Free bonus (integrity):** the magic only *reappears* after a correct
  de-whiten. If someone tampers with the stub, the checksum changes, the
  de-whiten produces garbage, the magic check fails, and the stub **fails open**
  (chains the original init) instead of running still-encrypted code.

Two related, smaller measures:
- **String hygiene:** the one string that would literally name the packer in a
  `strings` dump — the log tag `"sopack"` — is stored XOR-obfuscated and decoded
  on the stack, so the name never appears in a packed library.
- **Section-header stripping was tried and *rejected*.** It would hide *where*
  `.text` is, but on-device tests showed **Android 14+ bionic refuses to load a
  library with no section header table** (it crashes at load). It was also
  marginal once whitening works, so it was removed.

The ceiling, stated plainly:

> The stub is **byte-identical in every packed app** and contains the *complete*
> recipe. So an analyst reverses it **once** and has a universal offline unpacker
> for that version. Whitening raises the *cost* of that one-time reverse; it does
> not remove the ceiling. (Two ways to break the ceiling — a *polymorphic*
> per-pack stub, or an *external/server-derived* key — are discussed in the
> architecture doc but are deliberately **not** the default because each breaks
> the clean "prebuilt blob" model.)

---

## 8. Step 5 — Repackaging the APK

Once each targeted `.so` is injected, the APK is rebuilt:

1. **Unzip** the APK and inject each matching `lib/<abi>/<name>.so`.
2. Write the injected `.so` back **STORED (uncompressed)** — a `.so` must be
   directly memory-mappable, so it can't be zip-compressed. Drop the old
   signature.
3. **16 KB-align** the `.so` inside the zip (`zipalign -P 16`, or a built-in
   Python aligner on hosts without a matching `zipalign`) so its data starts on a
   16 KB boundary — required for 16 KB-page devices (4.4).
4. **Self-sign** the APK with a generated keystore (Android refuses to install an
   unsigned APK).

> **A consequence you must plan for:** re-signing gives the APK a **new signing
> identity**. So the packed app is effectively a *different app*: it **cannot be
> installed as an update over the original**, and any in-app signature-pinning /
> integrity check (common in banking apps) will notice the new certificate and may
> refuse to run — regardless of whether the encryption itself succeeded.

---

## 9. The two byte-for-byte contracts (why the tool has "mirror" files)

sopack is half Python (desktop) and half C (device). Two things must be **exactly
identical** on both sides, or you get silent, maddening breakage:

1. **The cipher** — `sopack/cipher.py` ⇄ `stub/stub_cipher.h` (both the ChaCha20/XOR
   *and* the whitening keystream). If they disagree by one byte, the stub decrypts
   to garbage.
2. **The 128-byte note layout** — `sopack/metadata.py` ⇄ `stub/decinfo.h`. If the
   Python packer and the C stub lay the struct out differently, the stub reads the
   key from the wrong offset.

Tests pin both: a cipher **KAT** (Known-Answer Test against the official RFC 8439
ChaCha20 vector) means "Python's keystream is correct," and since the C is a
line-for-line mirror, the stub will decrypt exactly what Python encrypted. A
layout test pins the struct. And an on-device/`dlopen` integration test proves the
two halves actually agree end to end.

---

## 10. Putting it all together — the life of one packed library

```
DESKTOP (Python injector)                        DEVICE (freestanding C stub)
───────────────────────────                      ────────────────────────────
1. find .text, encrypt it (ChaCha20)
2. append the stub as a new R+X 16KB segment
3. make the stub run first:
     • has usable DT_INIT? repoint + chain
     • else add DT_INIT by overwriting DT_NULL
       (never touch DT_INIT_ARRAY!)
4. write the 128-byte note (key, deltas, size),
   then WHITEN it (no SOPK magic on disk)
5. _self_verify: decrypt round-trips, no magic
   leaks, DT_INIT truly points at the stub
6. repackage APK: STORED, 16KB-align, re-sign
                                        ─────►    loader mmaps segments, relocates,
                                                  then calls DT_INIT = our stub:
                                                    a. de-whiten note (checksum over
                                                       own code), verify magic
                                                    b. mmap anon RW window
                                                    c. copy + decrypt exact .text
                                                    d. mremap onto ORIGINAL .text VA
                                                       (→ execmem, addresses stay valid)
                                                    e. mprotect R-X, flush I-cache
                                                    f. chain original init if any
                                                  loader then runs DT_INIT_ARRAY —
                                                  now on decrypted code. App runs.
```

---

## 11. One-paragraph summary you can keep in your head

sopack takes a finished Android `.so` you don't have source for, **encrypts its
machine code**, and **grafts on a tiny self-contained decryptor (the stub)** as a
new executable segment. It makes the stub run first by installing it as the
library's **`DT_INIT`** (adding one by overwriting the `.dynamic` `DT_NULL`
terminator when needed — and *never* touching `DT_INIT_ARRAY`, because relocations
would silently undo that and crash). At load, the stub finds itself PC-relatively
(no hardcoded addresses under ASLR), decrypts the code **into fresh anonymous
memory and moves it back onto the original address** — a dance forced entirely by
Android's `execmem`-allowed / `execmod`-denied SELinux rule — flushes the ARM64
instruction cache, and hands off to the real code. The key is hidden on disk by
**whitening** the metadata with a checksum of the stub's own bytes. Then the APK
is re-zipped, 16 KB-aligned, and re-signed. It's strong **anti-static-analysis
obfuscation**, not cryptography — because the key ships in the app and the
decrypted code is dumpable at runtime.