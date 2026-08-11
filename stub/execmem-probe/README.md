# execmem probe - does this device allow decrypt-and-execute?

A ~60-line standalone `.so` that answers one question, in isolation from the packer:

> Can an app copy `.text` into anonymous memory, `mremap` it back onto the original
> `.text` VA, flip it to `R-X`, and execute it - without a SELinux denial or a crash?

That is exactly what every packed library does at load
([`docs/technical/ARCHITECTURE.md`](../../docs/technical/ARCHITECTURE.md) §2a, §12e), and
it is the one property the build host cannot check: it depends on the device's SELinux
policy and page size. The probe deliberately **does not decrypt** anything, so a failure
here can never be blamed on the cipher or on the ELF surgery.

*(Historical note: this directory used to be called `phase0`, after the original staged
build plan - "prove the riskiest runtime assumption before writing any ELF surgery",
§7 of the architecture doc. That plan finished long ago, and the name collided with the
unrelated Phase 1–6 verification procedure in `docs/technical/WBAES.md`.)*

## When to use it

- **Before trusting a new device class.** Run it on real Android 14/15 hardware and a
  16 KB-page device before packing anything you care about.
- **When a packed app fails on one specific device.** This separates a sopack bug from
  device policy. If the probe fails there, no amount of packer correctness will help -
  see [`docs/TROUBLESHOOTING.md`](../../docs/TROUBLESHOOTING.md), specifically the
  `avc: denied { execmod }` and `E:mremap FAILED` entries. Hardened ROMs
  (GrapheneOS-style) that restrict JIT-style mappings are the usual cause.

## Build

```bash
NDK=/path/to/ndk
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
for pair in "arm64-v8a:aarch64-linux-android24" \
            "armeabi-v7a:armv7a-linux-androideabi24" \
            "x86_64:x86_64-linux-android24"; do
  abi=${pair%%:*}; triple=${pair##*:}
  mkdir -p out/$abi
  $TC/clang --target=$triple -O2 -fPIC -shared \
      -Wl,-z,max-page-size=16384 -llog \
      execmem_probe.c -o out/$abi/libexecmem_probe.so
done
```

## Run it - it MUST be loaded by an app

An `adb shell` executable runs in the `shell` SELinux domain, which is permitted things
an app is not. It would pass vacuously and tell you nothing. Load the library from an
app so it runs in `untrusted_app`:

1. Drop `out/<abi>/libexecmem_probe.so` into any **debuggable** app's
   `src/main/jniLibs/<abi>/`.
2. In an `Activity`/`Application`: `System.loadLibrary("execmem_probe");` - the
   constructor fires on load, so there is nothing else to call.
3. Watch the log:

```bash
adb logcat -c && adb logcat -s sopack-execmem
adb logcat | grep -i 'avc: denied'      # in a second shell
```

## Pass criteria

- `target(5) = 38 … mremap-onto-base OK`
- **no** `avc: denied { execmod }` or `{ execmem }`
- **no** SIGSEGV
- passes on every target ABI, on both 4 KB and 16 KB page devices

Any other outcome means the runtime approach does not hold on that device, and packed
libraries will not run there either. Report the device, ABI, Android version and
`getconf PAGE_SIZE`.
