"""O-MVLL obfuscation config for the sopack decryption stub.

Used only when build_stubs.sh runs with OMVLL_PLUGIN set (the ``--obfuscate`` path). The
config applies ONLY the pass set that was empirically confirmed to keep the stub
relocation-free, undefined-symbol-free and adrp-free — i.e. the constraints the guards in
build_stubs.sh enforce. Anything that breaks those constraints is deliberately excluded:

  enabled   arithmetic (MBA), control-flow-flattening, control-flow-breaking
  excluded  basic_block_duplicate  -> emits a call to libc ``lrand48`` (undefined in the
                                       freestanding, nostdlib stub)
            indirect_call/string   -> no benefit here: the scoped functions have no
                                       external calls and the only strings live in the
                                       (already XOR-obfuscated) logging path

Scope: the decryption / whitening crown-jewels only. ``sopk_entry`` inlines
``sopk_decrypt`` and the whitening-key derivation; ``sopk_chacha20_apply`` is emitted as a
standalone function. O-MVLL is semantics-preserving, so obfuscating the raw-syscall glue
that also lives in ``sopk_entry`` is safe.

SOPK_SEED (optional, set per pack by the ``--obfuscate`` path) seeds O-MVLL's RNG so every
pack gets a deterministic-but-unique obfuscation shape -> polymorphism (no universal
unpacker across apps).
"""
import os
from functools import lru_cache

import omvll

# Functions carrying the decrypt/whiten logic (see module docstring).
_TARGETS = {"sopk_entry", "sopk_chacha20_apply"}


def _in_scope(func) -> bool:
    for attr in ("demangled_name", "name"):
        try:
            value = getattr(func, attr)
            if value and value in _TARGETS:
                return True
        except Exception:
            pass
    return False


_seed = os.environ.get("SOPK_SEED")
if _seed:
    # Deterministic-but-unique obfuscation per pack -> polymorphism. The seed is a global
    # O-MVLL setting (omvll.config), NOT an ObfuscationConfig attribute. shuffle_functions
    # adds per-seed function reordering on top of the per-pass RNG choices.
    # probability_seed is a *signed int32* in O-MVLL's binding — mask to 31 bits so a large
    # seed can't overflow it (that raised "TypeError: incompatible function arguments").
    omvll.config.probability_seed = int(_seed) & 0x7FFFFFFF
    omvll.config.shuffle_functions = True


class SopackConfig(omvll.ObfuscationConfig):
    def obfuscate_arithmetic(self, mod, func):
        return _in_scope(func)

    def flatten_cfg(self, mod, func):
        return _in_scope(func)

    def break_control_flow(self, mod, func):
        if not _in_scope(func):
            return False
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], [], 100)


@lru_cache(maxsize=1)
def omvll_get_config():
    return SopackConfig()
