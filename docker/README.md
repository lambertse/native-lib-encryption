# Building the portable pack bundle for Linux/x86_64

`scripts/artifact_generation.sh` produces a bundle pinned to the host that generated it, because
one file in it — `bin/wb_keygen` — is a native host binary. To install and pack on a **Linux
x86_64** machine, the bundle has to be generated on one. This image is that machine.

Everything else in the bundle is host-neutral: the wheel is pure Python, and the stub blobs and
both wbaes skeletons are Android target ELFs that do not care what packed them.

## Build the image

```bash
docker build --platform linux/amd64 -t sopack-bundler docker/
```

The build context is `docker/`, not the repo root — the image carries no sopack source; the
checkout arrives as a bind mount at run time.

It downloads the NDK, the O-MVLL Linux plugin, libsodium and a CPython 3.10 stdlib and bakes
them in, so container runs afterwards need no network. The NDK dominates both the download and
the resulting image size (a few GB unpacked).

**The pre-warm is best-effort.** The image clones the submodule's repo at build time to bake
those dependencies in, defaulting to `--build-arg WBC_REF=feat/linux-omvll` — the branch carrying
Linux O-MVLL support. If that ref is not on the remote yet, the build **still succeeds**; it
prints a note and the entrypoint fetches into the mounted submodule on the first run instead
(~150 MB, once, and the container then needs network). Once the commit is pushed, rebuild with a
SHA to bake it in — a branch name resolves to whatever its tip is at build time, which can drift
from the submodule pin:

```bash
docker build --platform linux/amd64 --build-arg WBC_REF=<sha> -t sopack-bundler docker/
```

## Generate a bundle

```bash
mkdir -p out
docker run --rm --platform linux/amd64 \
    -v "$PWD:/workspace" -v "$PWD/out:/out" \
    --user "$(id -u):$(id -g)" \
    sopack-bundler --tar
```

Arguments after the image name go straight to `artifact_generation.sh` (`--abi`, `--api`,
`--force`, `--allow-unobfuscated-provider`, …). The bundle lands in **`./out/bundle/`**, and
`--tar` writes `./out/sopack-bundle-arm64-v8a-linux-x86_64-<rev>.tar.gz` beside it. The extra
level of directory is not cosmetic: the archive is always written *beside* the bundle, so with
the bundle at the mount root the tarball would land inside the container and be lost.

`--user` keeps `./out` and the checkout owned by you rather than root. It works because the
entrypoint installs sopack into a venv under `/tmp` instead of the system `dist-packages`, which
a non-root uid cannot write to. Drop it if your Docker setup makes the bind mounts unwritable to
your uid; you will then need to `sudo chown -R "$(id -u):$(id -g)" out` afterwards.

`--abi` is the **Android** target ABI and stays `arm64-v8a`. The x86_64 in play here is the
*host*; the two are unrelated axes and conflating them is an easy mistake.

## Testing it the first time

The three things most likely to go wrong are unprovable without running the image, so work up to
a full bundle rather than starting there.

**1. The toolchain and the O-MVLL plugin load at all.** This is the real unknown: the plugin is
an LLVM pass-plugin `dlopen`ed into NDK r29's clang, and nothing before this proves it works on
Linux.

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/workspace" -v "$PWD/out:/out" \
    --entrypoint bash sopack-bundler -c '
      pip install -qe /workspace --break-system-packages 2>/dev/null || pip install -qe /workspace
      cd /workspace && ./scripts/build_wbaes.sh --abi arm64-v8a --api 24'
```

Expect `Host phases 1-4 PASS`. If the plugin fails to load, it fails here, in Phase 4, and the
fallback is `--allow-unobfuscated-provider` on the real run below.

**2. A full bundle.**

```bash
mkdir -p out
docker run --rm --platform linux/amd64 \
    -v "$PWD:/workspace" -v "$PWD/out:/out" --user "$(id -u):$(id -g)" \
    sopack-bundler --tar
```

Check the receipts it prints: `wb_keygen linkage: static`, `host-os: Linux`,
`host-arch: x86_64`, `provider-obfuscation: omvll`.

**3. `install.sh`, in a container that has none of the toolchain.** Testing it inside the builder
proves nothing — every library is there by construction. Use an image resembling your target:

```bash
docker run --rm -it --platform linux/amd64 -v "$PWD/out/bundle:/bundle" rockylinux:9 bash -c '
    dnf install -y -q python3 java-17-openjdk-headless >/dev/null
    cp -r /bundle /tmp/b && cd /tmp/b && ./install.sh
    ./venv/bin/sopack --help'
```

That is the check that actually exercises the static keygen on a foreign distro. It needs network
for pip to fetch `lief`.

## Install on the target machine

```bash
mkdir -p ~/sopack-bundle && tar xzf sopack-bundle-*.tar.gz -C ~/sopack-bundle
~/sopack-bundle/install.sh
~/sopack-bundle/venv/bin/sopack pack your.apk -o packed.apk
```

The target needs **python3 ≥ 3.9 with `venv`** (on Debian/Ubuntu that is a separate
`python3-venv` package, and `install.sh` dies with a clear message without it), a **JDK**
(`keytool` runs on the first pack even without `--keystore`), **`apksigner`**, and **network
once** so pip can fetch `lief`. It needs no NDK, no cmake, no whitebox-cryptography, and no
sopack checkout.

## Two things worth knowing before you run it

**Build on a native amd64 host.** `--platform linux/amd64` is not a preference — Google ships no
`linux-aarch64` NDK toolchain and O-MVLL's Linux plugin is x86_64-only, so an arm64 image
hard-fails. Docker Desktop on Apple Silicon *will* run this under qemu, but that emulates a
64 MB x86_64 LLVM pass-plugin with an embedded CPython being `dlopen`ed into an x86_64 clang,
which is the likeliest place an emulated build diverges from a native one. Treat an emulated
build as unvalidated for release artifacts.

**The build writes into the mounted checkout.** The bundle goes to `/out`, but `vendor/wbc/`,
`sopack/stubs/*.so` and the submodule's `build-host/`/`build-android/` are regenerated in place.
All are gitignored and rebuildable, but they are *per-host*: pointing this at a checkout you also
build on from a Mac replaces that Mac's copies with Linux ones, and it will need
`./scripts/build_wbaes.sh` before it can pack again. Use a separate clone if that matters. The
entrypoint warns when it detects this.

## What the image pins, and why

| Pin | Value | Why |
|---|---|---|
| Base | `ubuntu:24.04` (glibc 2.39) | the O-MVLL 1.9.1 Linux plugin requires **`GLIBC_2.38`**. On `debian:bookworm` (2.36) clang refuses to load it — once per translation unit — and the build dies in Phase 4. Asserted at image build time |
| NDK | `29.0.14206865` (`android-ndk-r29-linux.zip`) | dictated by O-MVLL: its plugin is built against r29's clang, and an LLVM pass-plugin only loads into the compiler it was built for |
| O-MVLL | 1.9.1 Linux, SHA256 `f1f8f888…` | pinned in the whitebox-cryptography submodule's `third_party/fetch_deps.sh` |
| Static C++ link | asserted, not assumed | `build_wbaes.sh` links `wb_keygen` with `-static -static-libstdc++ -static-libgcc` so the bundle carries no glibc floor and installs on any distro; gate 4 of the bundler refuses a dynamically linked one. The image proves the link works at build time rather than naming a `libstdc++-N-dev` package that tracks the base's default gcc |

**The base image's glibc and the bundle's portability are unrelated.** The base needs to be *new*
so O-MVLL loads; the bundle stays distro-agnostic because its only native binary is static. Do not
"fix" a target-side glibc complaint by changing the base — check gate 4 instead.

Bumping the NDK means bumping the O-MVLL pin in the submodule too, or the plugin stops loading —
and a plugin that fails to load is the one way to get an unobfuscated provider out of a build
that otherwise looks successful.
