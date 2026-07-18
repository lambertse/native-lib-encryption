# sopack documentation

- **[building.md](./building.md)** — install the toolchain, build the stub blobs, pack
  an APK, and verify the result. Start here to *use* sopack.
- **[architecture.md](./architecture.md)** — the deep dive: the Android constraints
  that shape the design, the three components (runtime stub, ELF injector, APK
  repackager), the reasoning and the hard-won insights behind each decision, and how it
  was built and validated.
- **[troubleshooting.md](./troubleshooting.md)** — concrete failure modes (SIGILL at
  load, missing logcat line, signing/tamper issues, toolchain errors) with causes and
  fixes.

For a one-page overview, see the top-level [`README.md`](../README.md).
