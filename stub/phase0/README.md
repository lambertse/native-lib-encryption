# Phase 0 — runtime-path spike

Validates the one assumption that can't be fixed by iterating on the tool: that an app
can `mremap` decrypted pages onto the original `.text` VA and execute them under W^X /
SELinux on modern Android (4 KB **and** 16 KB pages). Run this **before** trusting the
injector.

## Build the .so

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
      phase0.c -o out/$abi/libphase0.so
done
```

## Run it (must be inside an app → untrusted_app domain)

An `adb shell` executable runs in the `shell` SELinux domain and is **not** a valid
test. Load the library from an app:

1. Drop `out/<abi>/libphase0.so` into any **debuggable** app's
   `src/main/jniLibs/<abi>/`.
2. In an `Activity`/`Application`: `System.loadLibrary("phase0");` — the constructor
   fires on load.
3. Watch the log on a real Android 14/15 device and a 16 KB emulator/Pixel:

```bash
adb logcat -c && adb logcat -s sopack-phase0
# also check for denials:
adb logcat | grep -i 'avc: denied'
```

## Pass criteria (gate to trust the injector)

- `target(5) = 38 … mremap-onto-base OK`
- **no** `avc: denied { execmod }` or `{ execmem }`
- **no** SIGSEGV
- passes on every target ABI, on both 4 KB and 16 KB page devices

If `mremap FIXED FAILED` or an `avc: denied` appears, the injector's runtime approach
must be revisited (e.g. per-device policy differences) before proceeding.
