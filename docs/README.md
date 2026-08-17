# sopack documentation

Two audiences, two directories.

## Using sopack

Start here if you want to pack an APK.

- **[BUILDING.md](./BUILDING.md)** - install the toolchain, build the stub blobs, pack an
  APK, verify the result. **Start here.** §6 covers the two harness scripts:
  `scripts/device_test.sh` (pack the whole `test_apks/` corpus and run it on a device) and
  `scripts/artifact_generation.sh` (build the portable `artifacts/` bundle - tool included, so
  the second machine needs no checkout).
- **[SECURITY.md](./SECURITY.md)** - what this actually protects, the honest ceiling, and
  what is deliberately left visible. Read it before describing sopack to anyone else.
- **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - concrete failure modes (SIGILL at load,
  missing logcat line, signing/tamper issues, the `--cipher wbaes` fail codes, toolchain
  errors) with causes and fixes.

## Changing sopack

[`technical/`](./technical/) - the internals. You need these to modify the packer, the
stub, or the white-box integration; you do not need them to use the tool.

- **[technical/ARCHITECTURE.md](./technical/ARCHITECTURE.md)** - the deep dive: the Android
  constraints that shape the design, the three components (runtime stub, ELF injector, APK
  repackager), the reasoning and hard-won insights behind each decision, and the key
  lifecycle in both cipher modes.
- **[technical/WBAES.md](./technical/WBAES.md)** - everything about `--cipher wbaes`.
  Part I is the boundary with the **whitebox-cryptography** SDK: the version contract, what
  sopack consumes and refuses, the artifact flow, and what an upstream change breaks. Part II
  is the six-phase build-and-verify procedure. Read it before using or upgrading that mode -
  it has prerequisites the other modes do not.
- **[technical/PAGE-ALIGNMENT.md](./technical/PAGE-ALIGNMENT.md)** - 16 KB pages, end to end:
  why a 4 KB-aligned input library is unpackable, every mapping step from the APK entry offset
  to the decryptor's `mremap` window, which step crashes and how far from the cause, why the
  packer cannot repair the library, and which parts of the refusal are sopack's own limitation.
  Read it when a pack fails with a `16 KB` error.
- **[technical/HARDENING.md](./technical/HARDENING.md)** - the implementation of every
  anti-static-analysis technique (metadata whitening, string hygiene, the pack-time strip, and
  why section-header stripping was rejected), with the code and the tests that lock each one.
- **[technical/IMPROVEMENTS.md](./technical/IMPROVEMENTS.md)** - changes that are understood
  and deliberately **not** done, each with the trade-off it loses on today and the measurement
  that would justify revisiting it - plus the ones that have since **shipped**, kept for their
  measured result. Read it before proposing an optimisation - the shapes that look obvious and
  do not work are recorded here.

For a one-page overview, see the top-level [`README.md`](../README.md). For the terse
invariant list, see `CLAUDE.md` in the repo root.
