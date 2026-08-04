# sopack documentation

- **[building.md](./building.md)** — install the toolchain, build the stub blobs, pack
  an APK, and verify the result. Start here to *use* sopack.
- **[architecture.md](./architecture.md)** — the deep dive: the Android constraints
  that shape the design, the three components (runtime stub, ELF injector, APK
  repackager), the reasoning and the hard-won insights behind each decision, and how it
  was built and validated.
- **[wbaes-verification.md](./wbaes-verification.md)** — the six-phase procedure for
  `--cipher wbaes` (white-box AES-128 key wrapping): building the host `wb_keygen` and the
  per-ABI helper skeleton, a host round-trip through the real white-box, and what to check
  on device. Read it before using that mode — it has prerequisites the other modes do not.
- **[static-analysis-hardening.md](./static-analysis-hardening.md)** — every technique
  used to make static analysis of a packed `.so` harder (metadata whitening, string hygiene;
  and why section-header stripping was rejected), with the code and the honest limits.
- **[troubleshooting.md](./troubleshooting.md)** — concrete failure modes (SIGILL at
  load, missing logcat line, signing/tamper issues, toolchain errors) with causes and
  fixes.

For a one-page overview, see the top-level [`README.md`](../README.md).
