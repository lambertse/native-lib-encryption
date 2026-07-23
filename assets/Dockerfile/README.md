# sopack Docker environment

A self-contained image with the full sopack toolchain: the native stub compiler
(clang/lld/llvm), Python + LIEF, the JDK + `apksigner`, and — for the `--obfuscate`
path — the **Android NDK r26d** and the **O-MVLL 1.6.0** obfuscator.

You only need Docker installed on the host. Nothing else is required to build or pack.

## One-time host setup (Apple Silicon / arm64 Macs)

The Android NDK and O-MVLL are published only as **x86_64** binaries. On an arm64 Mac they
run under Docker Desktop's Rosetta. Enable it once:

> Docker Desktop → **Settings → General → "Use Rosetta for x86/amd64 emulation"** → Apply & restart.

On an x86_64 host this step is unnecessary — the NDK/O-MVLL run natively.

## Build the image

From the **repository root** (that is the build context):

```bash
docker build -f assets/Dockerfile/Dockerfile -t sopack .
```

## Pack an APK

Mount a directory containing your input APK as `/work`:

```bash
# Plain pack (default prebuilt stub, no toolchain emulation involved):
docker run --rm -v "$PWD:/work" -w /work sopack \
    pack in.apk --lib libfoo.so -o out.apk

# Obfuscated + per-pack polymorphic stub (recompiles the stub with O-MVLL under Rosetta):
docker run --rm -v "$PWD:/work" -w /work sopack \
    pack in.apk --lib libfoo.so -o out.apk --obfuscate
```

The `ENTRYPOINT` is `sopack`, so everything after the image name is passed straight to the
CLI. Run `docker run --rm sopack --help` for all options.

## What's inside

| Component | Version | Location | Arch |
|---|---|---|---|
| Debian base | 12 (bookworm) | — | arm64-native |
| clang / lld / llvm | 14 (Debian) | `/usr/bin` | native |
| Python + LIEF | 3.11 + 1.0.0 | system | native |
| JDK + apksigner | 17 | `/usr/bin` | native |
| Android NDK | r26d | `/opt/android-ndk-r26d` | x86_64 (Rosetta) |
| O-MVLL | 1.6.0 | `/opt/omvll` | x86_64 (Rosetta) |

`ANDROID_NDK_HOME`, `OMVLL_PLUGIN`, and `OMVLL_PYTHONPATH` are set in the image so
`stub/build_stubs.sh` finds the obfuscation toolchain automatically.

## Keeping this in sync with the host machine

The image is pinned via `ARG`s at the top of the Dockerfile. When the project's toolchain
changes, update the Dockerfile and rebuild:

- **NDK / O-MVLL:** `NDK_VERSION`, `OMVLL_VERSION`, `OMVLL_ASSET` must move **together** —
  the O-MVLL plugin is compiled against a specific NDK's LLVM and won't load into another.
  Check the compatible NDK on the O-MVLL release notes
  (<https://github.com/open-obfuscator/o-mvll/releases>) before bumping. **Also mind glibc:**
  the plugin is x86_64-linked against a build-host glibc — O-MVLL 1.6.0 needs only GLIBC_2.35
  (fine on this Debian 12 / glibc 2.36 base), but 1.8.0+ needs GLIBC_2.38, so bumping O-MVLL
  past 1.7 means also moving the base image to a newer distro (e.g. `ubuntu:24.04`).
- **Base packages** (clang/JDK/etc.): change the `apt-get install` line.
- **amd64 lib set:** if a newly added NDK/O-MVLL tool fails to start under emulation with a
  missing `.so`, add its `<lib>:amd64` package to the multiarch `apt-get install` line
  (find the missing lib with `llvm-readelf -d <tool> | grep NEEDED`).

## Notes / limitations

- The default (non-obfuscated) stubs are prebuilt at image-build time with the native
  clang. The obfuscated stubs are rebuilt **per pack** at runtime (Rosetta), so `--obfuscate`
  is slower than a plain pack.
- Sample APKs and large fixtures under `assets/` are excluded from the image via
  `.dockerignore`; mount your APKs at `/work` instead.
- `zipalign` is not installed; sopack falls back to its built-in 16 KB Python aligner.
