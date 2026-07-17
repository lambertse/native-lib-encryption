"""sopack — black-box Android .so encryptor / APK repackager.

Given an APK and a list of native libraries, encrypts each library's `.text` and
injects a freestanding runtime stub that decrypts it at load time (W^X / SELinux
`execmem`-safe, via mremap onto the original .text VA), then re-zips and self-signs.

Security value is obfuscation only: the key ships in the binary.
"""

__version__ = "0.1.0"
