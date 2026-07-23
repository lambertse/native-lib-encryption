# sopack documentation

- **[building.md](./building.md)** — install the toolchain, build the stub blobs, pack
  an APK, and verify the result. Start here to *use* sopack.
- **[architecture.md](./architecture.md)** — the deep dive: the Android constraints
  that shape the design, the three components (runtime stub, ELF injector, APK
  repackager), the reasoning and the hard-won insights behind each decision, and how it
  was built and validated.
- **[static-analysis-hardening.md](./static-analysis-hardening.md)** — every technique
  used to make static analysis of a packed `.so` harder (metadata whitening, string hygiene;
  and why section-header stripping was rejected), with the code and the honest limits.
- **[troubleshooting.md](./troubleshooting.md)** — concrete failure modes (SIGILL at
  load, missing logcat line, signing/tamper issues, toolchain errors) with causes and
  fixes.

For a one-page overview, see the top-level [`README.md`](../README.md).
