# What sopack actually protects

Read this before deciding whether sopack fits your threat model, and before describing it
to anyone else. The short version: **this is obfuscation, not cryptographic protection.**
It raises the cost of a static attack on arm64. It does not make your algorithms secret,
and it does not survive an attacker who runs your app.

The implementation of each measure is in
[`technical/HARDENING.md`](./technical/HARDENING.md); the design reasoning is in
[`technical/ARCHITECTURE.md`](./technical/ARCHITECTURE.md) §9.

## What you get

| Technique | Status | Effect on a static analyst |
| --------- | ------ | -------------------------- |
| Metadata record whitened with a key derived from the stub's own code | ✅ shipped (device-confirmed) | No key and no magic in the file; recovery requires reversing the stub |
| No magic at rest - the packer patches by known offset | ✅ shipped | Nothing to `grep` for; a pack-time guard proves it |
| String hygiene - the `sopack` tag is obfuscated | ✅ shipped | The packer's name is absent from a `strings` dump |
| The `--cipher wbaes` artifacts are stripped at pack time | ✅ shipped (host-verified) | Removes the single largest shortcut: named functions and the SDK's whole API |
| Section-header stripping | ❌ removed | Incompatible with Android 14+ bionic; also low value once the key is unrecoverable |

Confirmed end-to-end on-device (Android 16, arm64, a real Flutter app): the packed library
decrypts and the app runs, with no SELinux `avc` denial, and neither `SOPK` nor `sopack`
appears in the shipped library.

With `--cipher wbaes` you additionally get **no portable key in the binary at all** - the
long-term AES key is sealed into a white-box and never reconstructed at runtime. See the
ceiling below for what that does and does not buy.

## Threat model, and the honest ceiling

- **In scope (what these techniques raise the cost of):** a *static* analyst reading the
  APK without running it - pulling the key out of the file, locating `.text`,
  fingerprinting the packer, and writing an offline decryptor.
- **Out of scope (always wins, by design):** a *dynamic* analyst. After load, plaintext
  `.text` lives in a readable `R-X` mapping; Frida or a `/proc/self/maps` dump recovers
  everything.
- **The ceiling:** the decryption stub ships **byte-identical in every packed app** and
  contains the *complete* de-obfuscation recipe. An analyst reverses it **once** and has a
  universal offline unpacker for every app at that sopack version. The measures above raise
  the one-time reversing cost (grep-and-decrypt → a real RE session); they do **not** remove
  the ceiling. Two ways to break it - a polymorphic per-pack stub, or an external /
  server-derived key - are described in `technical/ARCHITECTURE.md` §9e; both leave the
  clean, prebuilt-blob architecture and are not the default.

### The `--cipher wbaes` ceiling specifically

The white-box is Chow-style AES, academically broken by BGE-class attacks. It protects
against **static** analysis, not dynamic. Key wrapping removes the "a portable key ships in
the binary" weakness and narrows the story in exactly one documented way, which upstream
states and we should not paper over:

- the **session** key is an ordinary key in ordinary memory between the unwrap and the
  `wbc_wipe`, so a process dump yields it without attacking the white-box at all;
- the **long-term** key keeps its full protection - it is diffused into lookup tables and
  never reconstructed.

Each protected library gets its own session key, so a dump scoped to one library does not
generalise to the others.

## What is deliberately NOT hidden

- **That only `arm64-v8a` is protected.** `armeabi-v7a` / `x86` / `x86_64` ship cleartext
  `.text`, so an analyst who wants the *algorithm* reads another ABI's build and never
  touches the encryption. This is a deliberate scope decision: the protection raises
  device-level attack cost on arm64, it does not keep algorithms secret. (Extending it is
  discussed in [`technical/IMPROVEMENTS.md`](./technical/IMPROVEMENTS.md) §2.)
- **The packer's structural fingerprint.** The appended R+X `PT_LOAD` with `DT_INIT`
  pointing into it cannot be removed without breaking the mechanism. "Make key extraction
  hard" is achievable; "make sopack unfingerprintable" is not.
- **Where `.text` is.** Section-header stripping was removed (it breaks loading on Android
  14+), and the location is derivable from program headers regardless. Harmless once the key
  is unrecoverable.
- **The wbaes artifacts.** The `'SRTT'`/`'SRTW'` region magics in their section-less
  read-only `PT_LOAD`s, the `libsopk_rt_<target>.so` names in each target's `DT_NEEDED`, and
  the fixed `libsopk_wb.so` provider name are all one-line detection signatures. None can be
  removed while a helper still has to find its own region and be loaded by name. Renaming
  buys an analyst-minute, not security.
- **Runtime plaintext.** See the threat model above.

## Two consequences to communicate

- **The APK is re-signed with a generated key**, so the packed app has a *different signing
  identity* from your original. It cannot be shipped as an update to the original listing
  unless you sign it with your own keystore (`--keystore`), and any service that pins your
  certificate will reject it.
- **Integrity/tamper checks in the app may fire.** The libraries have been modified after
  build; an app that checksums its own natives, or a DRM/anti-tamper SDK, can notice. See
  [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md).
