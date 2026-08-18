"""The sopack config file (YAML) - every setting except the input and output APK.

    sopack pack in.apk -o out.apk [--config PATH]

Lookup order: an explicit ``--config PATH`` (which must exist), then ``./config.yaml``,
then the built-in defaults in `Config.default()` - so a bare pack still works on a machine
that has no config file at all.

This module owns EVERY default. `cli._cmd_pack` passes each value explicitly to
`apk.repackage`, whose own signature defaults are library API (the tests call it directly),
so the long-standing skew between the two layers - the CLI defaulted `cipher` to `wbaes`
while `repackage` defaults it to `chacha20` - stops mattering rather than being papered
over. Nothing here reads `repackage`'s defaults and nothing there reads these.

Two deliberate omissions, so a later reader does not "fix" them:

* **No `wb-keygen` key.** `provision.find_wb_keygen` probes `vendor/wbc/bin/wb_keygen`,
  then a portable bundle, then `$SOPACK_WBKEYGEN`, then PATH - an order chosen so a stale
  export cannot beat the keygen `build_wbaes.sh` just gated. A config key would re-open
  "where does it rank?" for no gain.
* **`${VAR}` expansion is scoped to the three keystore fields**, not applied globally. Those
  are the only values anyone needs to keep out of a committed file, and a global expansion
  would make a library literally named `${...}` impossible to write.

The sample config is the module constant `SAMPLE_YAML` rather than a package data file, and
that is not incidental: `scripts/artifact_generation.sh` stages the portable wheel with
`cp "$SOPACK"/sopack/*.py`, so a `config.sample.yaml` sitting in this package would silently
not reach the wheel and `sopack init-config` would fail on exactly the toolchain-less
machine the bundle exists for. A string in a .py file rides along for free.
"""
from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .stubs import DEFAULT_ABIS, SUPPORTED_ABIS

CIPHERS = ("wbaes", "chacha20", "xor")
DEFAULT_CONFIG_NAME = "config.yaml"


class ConfigError(ValueError):
    """An unusable config file.

    ValueError so `cli.main`'s existing except-clause renders it as `error: ...` rather
    than a traceback; there is nothing a stack trace adds to a bad config key.
    """


# ---- the sample --------------------------------------------------------------------
# Kept byte-identical to config.sample.yaml at the repo root, and pinned by
# tests/test_config.py both ways: the file matches this string, and this string parses to
# exactly Config.default(). That makes the sample, the constant and the code defaults one
# thing that cannot drift.
SAMPLE_YAML = """\
# sopack configuration. The command line carries only the input and output APK:
#   sopack pack in.apk -o out.apk [--config PATH]
# Lookup order: --config PATH, then ./config.yaml, then these built-in defaults.
# Every key below is optional; the value shown is the default.

# wbaes  - white-box AES-128 key wrapping (DEFAULT). The long-term key is sealed
#          and never reconstructed at runtime, so no portable key ships. Needs the
#          artifacts ./scripts/build_wbaes.sh produces, or a portable bundle.
# chacha20 / xor - the freestanding stub. No build step, but the raw key ships
#          inside the binary (whitened at rest).
cipher: wbaes

# A list, or the string "all" for every supported ABI
# (arm64-v8a, armeabi-v7a, x86_64). arm64-v8a is the only ABI protected in
# practice; the others ship their .text in cleartext.
abis:
  - arm64-v8a

libraries:
  # Omit `include`, or leave it null, to encrypt EVERY lib/<abi>/*.so in the APK.
  # An explicitly empty list ([]) is an error, not a request for auto-select.
  #
  # Entries match exactly like `exclude` below: a bare basename (libfoo -> that
  # library in every selected ABI), a full APK path (lib/arm64-v8a/libfoo.so),
  # fnmatch globs, and a trailing .so that is OPTIONAL. So `libapp`, `libapp.so`
  # and `lib/arm64-v8a/libapp.so` all select the same library.
  include:
    # - libapp

  # Never encrypt these. Same matching as `include` above: fnmatch globs on the
  # basename, trailing .so optional, full APK paths too - so "libflutter" matches
  # libflutter.so but not libflutterx.so. Exclusion ALWAYS wins over `include`.
  #
  # An empty list ([]) is fine here - unlike `include`, it can only narrow
  # protection back to the two entries sopack enforces, never widen the pack.
  exclude:
    # sopack's own injected artifacts: the shared white-box provider and the
    # per-target thin helpers. These are the code that does the DECRYPTING, so
    # packing them would break every APK you re-pack. Listed here so you can see
    # them - sopack re-applies this pattern either way, and deleting the line
    # changes nothing.
    - libsopk_*
    # The V-Key/V-OS wrapper: already self-protected, so packing it buys nothing
    # and risks tripping its own integrity checks. Also enforced regardless.
    - libvosWrapperEx
    # The stock public Flutter engine. Excluded by POLICY, not necessity: it is
    # public code, so encrypting it costs load time and fragility while
    # protecting nothing of yours - encrypt libapp.so (your Dart snapshot)
    # instead. This one is a plain entry: delete it and libflutter.so gets
    # packed like anything else.
    - libflutter
    # Add your own below.
    # - libc++_shared
    # - libmy*

signing:
  sign: true            # false == the old --no-sign: leave the APK UNSIGNED
  verify: true          # print the signer certificates after signing
  min-sdk:              # override apksigner minSdkVersion if manifest detection fails

  keystore:
    # null -> ~/.sopack/debug.keystore, generated on demand
    path:
    alias: sopack
    # ${VAR} expands from the environment, so a committed config need not hold a
    # real password. A referenced variable that is not set is an error.
    store-pass: sopack
    key-pass:           # null -> same as store-pass

logging:
  stub-log: false       # the old --log: the stub emits a logcat line on decrypt
  # Permit a wbaes helper skeleton built with -DSOPK_RT_LOG. Such a build leaks the
  # target name, .text address and size to logcat: the result is NOT shippable.
  allow-helper-log: false
"""


# ---- the shape ---------------------------------------------------------------------
@dataclass(frozen=True)
class KeystoreConfig:
    path: str | None = None                 # None -> apk.DEFAULT_KEYSTORE_PATH
    alias: str = "sopack"
    store_pass: str = "sopack"
    key_pass: str | None = None             # None -> same as store_pass


@dataclass(frozen=True)
class SigningConfig:
    sign: bool = True
    verify: bool = True
    min_sdk: int | None = None
    keystore: KeystoreConfig = field(default_factory=KeystoreConfig)


#: The exclusion list a config gets when it says nothing. The first two mirror
#: `apk.ALWAYS_EXCLUDE_PATTERNS`, which `build_excludes` prepends unconditionally - they are
#: here so a reader of the config can SEE what is being excluded, and deleting them from a
#: config is a no-op. `libflutter` is the odd one out: it lives only here, so removing it
#: from a config really does start packing it. `tests/test_config.py` pins that this stays a
#: superset of ALWAYS_EXCLUDE_PATTERNS so the visible list cannot drift from the enforced one.
DEFAULT_EXCLUDES = ("libsopk_*", "libvosWrapperEx", "libflutter")


@dataclass(frozen=True)
class LibraryConfig:
    # None means auto-select every lib/<abi>/*.so. This is NOT the same as an empty
    # tuple, and apk.repackage() relies on the distinction - see _build_libraries.
    include: tuple[str, ...] | None = None
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES


@dataclass(frozen=True)
class LoggingConfig:
    stub_log: bool = False
    allow_helper_log: bool = False


@dataclass(frozen=True)
class Config:
    cipher: str = "wbaes"
    abis: tuple[str, ...] = DEFAULT_ABIS
    libraries: LibraryConfig = field(default_factory=LibraryConfig)
    signing: SigningConfig = field(default_factory=SigningConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @staticmethod
    def default() -> "Config":
        return Config()


# ---- validation helpers ------------------------------------------------------------
_TOP_KEYS = frozenset({"cipher", "abis", "libraries", "signing", "logging"})
_LIB_KEYS = frozenset({"include", "exclude"})
_SIGN_KEYS = frozenset({"sign", "verify", "min-sdk", "keystore"})
_KS_KEYS = frozenset({"path", "alias", "store-pass", "key-pass"})
_LOG_KEYS = frozenset({"stub-log", "allow-helper-log"})

# Keys that USED to exist, by full dotted path, mapped to what replaced them - the config
# counterpart of cli._REMOVED_FLAGS. An upgrading user has the old key sitting in their file
# and the generic unknown-key path would only offer a did-you-mean that suggests nothing
# useful. Keyed on the dotted path, not the bare name, so a top-level `default-excludes:`
# still gets the ordinary "wrong section" treatment - that is a different mistake.
_REMOVED_KEYS = {
    "libraries.default-excludes":
        "the built-in exclusion list it toggled is gone. Every excluded pattern is now "
        "written out in `libraries.exclude`, so delete the entry you no longer want "
        "(`libflutter`) instead of flipping this. Note `libsopk_*` and `libvosWrapperEx` "
        "stay excluded either way - sopack enforces those regardless of the config",
}

# Braced form only, so a literal `$HOME` in a password stays literal, and `$${VAR}` is an
# escape for a literal `${VAR}`. os.path.expandvars is deliberately not used: it expands the
# bare form too, and it leaves an UNSET variable in place instead of failing.
_ENV_RE = re.compile(r"\$(\$)?\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _typename(value) -> str:
    return {dict: "a mapping", list: "a list", str: "a string",
            bool: "a boolean", int: "a number", float: "a number"}.get(type(value),
                                                                       repr(value))


def _at(where: str, key: str) -> str:
    return f"{where}.{key}" if where else key


def _check_keys(data: dict, allowed: frozenset, where: str) -> None:
    """Reject unknown keys, at every nesting level.

    This is the guard that replaces argparse. `--ciper xor` was an error; `ciper: xor`
    must not silently pack with the default cipher instead. Only the dash spelling is
    accepted - taking `store_pass` too would mean two spellings to keep working forever.
    """
    for key in data:
        if key in allowed:
            continue
        if not isinstance(key, str):
            raise ConfigError(f"{where or 'top level'}: keys must be strings, got {key!r}")
        # A key we deliberately retired gets its own message before the generic path, which
        # would otherwise suggest the nearest surviving key - unhelpful when the answer is
        # "that setting no longer exists, here is what replaced it".
        retired = _REMOVED_KEYS.get(_at(where, key))
        if retired:
            raise ConfigError(f"{_at(where, key)}: removed - {retired}.")
        if key.replace("_", "-") in allowed:
            hint = (f" - config keys use dashes, not underscores; "
                    f"did you mean {key.replace('_', '-')!r}?")
        else:
            near = difflib.get_close_matches(key, sorted(allowed), n=1)
            hint = f" - did you mean {near[0]!r}?" if near else ""
        raise ConfigError(f"{_at(where, key)}: unknown key{hint}. "
                          f"Valid keys here: {', '.join(sorted(allowed))}")


def _mapping(value, where: str) -> dict:
    """A group key that is absent or null means "that group's defaults"."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a mapping of key: value, got {_typename(value)}")
    return value


def _as_bool(value, where: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{where}: expected true or false, got {_typename(value)} "
                          f"({value!r}). Note a quoted \"true\" is a string, not a boolean.")
    return value


def _as_int(value, where: str) -> int | None:
    # bool is a subclass of int, so it has to be rejected before the isinstance check.
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: expected a whole number, got {_typename(value)} ({value!r})")
    return value


def _as_str(value, where: str, default: str | None) -> str | None:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"{where}: expected a string, got {_typename(value)} ({value!r}). "
                          f"Quote it if it looks like a number or a boolean.")
    return value


def _as_str_list(value, where: str) -> tuple[str, ...] | None:
    """None -> None (the key is absent). Otherwise a list of non-empty strings."""
    if value is None:
        return None
    if isinstance(value, str):
        raise ConfigError(f"{where}: expected a list, got the single string {value!r}. "
                          f"Even one entry is a list:\n"
                          f"  {where.split('.')[-1]}:\n    - {value}")
    if not isinstance(value, list):
        raise ConfigError(f"{where}: expected a list, got {_typename(value)}")
    out = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"{where}[{i}]: expected a non-empty name, got {item!r}")
        out.append(item.strip())
    return tuple(out)


def _expand_env(value: str | None, where: str) -> str | None:
    """Expand ${VAR} from the environment. An unset variable is an error, never "".

    Silently expanding an unset variable to the empty string would sign with an empty
    password, which apksigner accepts for a keystore created with one - so the mistake
    would survive all the way to a shipped APK.
    """
    if value is None:
        return None

    def sub(m: "re.Match") -> str:
        escaped, name = m.group(1), m.group(2)
        if escaped:
            return "${%s}" % name           # $${VAR} -> a literal ${VAR}
        try:
            return os.environ[name]
        except KeyError:
            raise ConfigError(f"{where}: references ${{{name}}}, which is not set in the "
                              f"environment") from None

    return _ENV_RE.sub(sub, value)


# ---- parsing -----------------------------------------------------------------------
def _build_abis(value, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        if value != "all":
            raise ConfigError(f"abis: expected a list, or the string \"all\"; got {value!r}. "
                              f"A single ABI is still a list:\n  abis:\n    - {value}")
        return tuple(SUPPORTED_ABIS)
    abis = _as_str_list(value, "abis")
    if not abis:
        raise ConfigError("abis: the list is empty. Name at least one ABI, or remove the "
                          f"key for the default ({', '.join(DEFAULT_ABIS)}).")
    # This check used to live in cli._cmd_pack; argparse never had `choices` for --abi.
    for abi in abis:
        if abi not in SUPPORTED_ABIS:
            raise ConfigError(f"abis: unsupported ABI {abi!r}; choose from "
                              f"{', '.join(SUPPORTED_ABIS)}, or \"all\"")
    return tuple(dict.fromkeys(abis))       # de-duplicate, preserving the written order


def _build_libraries(raw) -> LibraryConfig:
    data = _mapping(raw, "libraries")
    _check_keys(data, _LIB_KEYS, "libraries")
    d = LibraryConfig()

    # An absent or null `include` means auto-select every lib/<abi>/*.so; an explicitly
    # EMPTY list is a user error rather than a request to widen the scope to the whole
    # APK. apk.repackage() treats None and [] as different things and the two are not
    # interchangeable - this mirrors the old rejection of an empty --libs file.
    include = data.get("include")
    if isinstance(include, list) and not include:
        raise ConfigError(
            "libraries.include: the list is empty. Remove the key (or leave it null) to "
            "encrypt every lib/<abi>/*.so - an empty list would silently widen the scope "
            "to the whole APK, which is never what an empty list is meant to say.")

    # `exclude` is the MIRROR IMAGE of `include` on empty lists, and the asymmetry is
    # deliberate rather than an oversight:
    #   include: []   ERROR   - it would WIDEN the pack to the whole APK, silently swapping
    #                           the strict "named library must inject" contract for the
    #                           fail-soft auto-select one.
    #   exclude: []   VALID   - it can only NARROW protection, and only as far as the two
    #                           patterns apk.build_excludes prepends unconditionally. There
    #                           is no unsafe reading of it.
    # Absent/null is not [] here either: it means "give me the documented default list",
    # so a config that never mentions `exclude` still excludes libflutter, exactly as
    # before this key existed.
    exclude = _as_str_list(data.get("exclude"), "libraries.exclude")
    return LibraryConfig(
        include=_as_str_list(include, "libraries.include"),
        exclude=d.exclude if exclude is None else exclude,
    )


def _build_keystore(raw) -> KeystoreConfig:
    data = _mapping(raw, "signing.keystore")
    _check_keys(data, _KS_KEYS, "signing.keystore")
    d = KeystoreConfig()

    def val(key: str, default: str | None) -> str | None:
        where = f"signing.keystore.{key}"
        return _expand_env(_as_str(data.get(key), where, default), where)

    path = val("path", d.path)
    return KeystoreConfig(
        # expanduser after expansion, so ${HOME}-free "~/release.jks" works too.
        path=os.path.expanduser(path) if path else None,
        alias=val("alias", d.alias),
        store_pass=val("store-pass", d.store_pass),
        key_pass=val("key-pass", d.key_pass),
    )


def _build_signing(raw) -> SigningConfig:
    data = _mapping(raw, "signing")
    _check_keys(data, _SIGN_KEYS, "signing")
    d = SigningConfig()
    return SigningConfig(
        sign=_as_bool(data.get("sign"), "signing.sign", d.sign),
        verify=_as_bool(data.get("verify"), "signing.verify", d.verify),
        min_sdk=_as_int(data.get("min-sdk"), "signing.min-sdk"),
        keystore=_build_keystore(data.get("keystore")),
    )


def _build_logging(raw) -> LoggingConfig:
    data = _mapping(raw, "logging")
    _check_keys(data, _LOG_KEYS, "logging")
    d = LoggingConfig()
    return LoggingConfig(
        stub_log=_as_bool(data.get("stub-log"), "logging.stub-log", d.stub_log),
        allow_helper_log=_as_bool(data.get("allow-helper-log"),
                                  "logging.allow-helper-log", d.allow_helper_log),
    )


def _build(data: dict) -> Config:
    _check_keys(data, _TOP_KEYS, "")
    d = Config.default()

    cipher = data.get("cipher")
    if cipher is None:
        cipher = d.cipher
    elif cipher not in CIPHERS:
        raise ConfigError(f"cipher: expected one of {', '.join(CIPHERS)}; got {cipher!r}")

    return Config(
        cipher=cipher,
        abis=_build_abis(data.get("abis"), d.abis),
        libraries=_build_libraries(data.get("libraries")),
        signing=_build_signing(data.get("signing")),
        logging=_build_logging(data.get("logging")),
    )


def _yaml_module():
    """Import PyYAML, or explain how to get it.

    An editable install that predates the dependency bump otherwise dies with a bare
    ModuleNotFoundError from inside a config load, which says nothing about sopack.
    """
    try:
        import yaml
    except ImportError as e:                # pragma: no cover - environment-dependent
        raise ConfigError(
            "PyYAML is required to read a sopack config file but is not installed. "
            "Run `pip install -e .` in the sopack checkout, or `pip install 'pyyaml>=6'`."
        ) from e
    return yaml


def _strict_loader(yaml, source: str):
    """A SafeLoader that rejects duplicate keys instead of silently keeping the last.

    `yaml.safe_load` accepts a mapping with `verify: true` and `verify: false` in it and
    returns the second - which is the same silent-acceptance failure the unknown-key check
    exists to close, only harder to spot because both spellings are valid keys.
    """
    class _StrictLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                mark = key_node.start_mark
                raise ConfigError(f"{source}: duplicate key {key!r} at line {mark.line + 1}. "
                                  f"YAML would silently keep only the last one.")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    _StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return _StrictLoader


def loads(text: str, source: str = "<config>") -> Config:
    """Parse config text. Every error is prefixed with `source` so it names the file."""
    yaml = _yaml_module()                   # deferred: nothing but the CLI path needs it

    try:
        data = yaml.load(text, Loader=_strict_loader(yaml, source))
    except yaml.YAMLError as e:
        raise ConfigError(f"{source}: not valid YAML: {e}") from None
    if data is None:
        return Config.default()             # an empty (or all-comment) file == defaults
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: the top level must be a mapping of key: value, "
                          f"got {_typename(data)}")
    try:
        return _build(data)
    except ConfigError as e:
        raise ConfigError(f"{source}: {e}") from None


def load(path: str | None = None, cwd: str | None = None) -> tuple[Config, str | None]:
    """Resolve, read and parse the config.

    Returns (config, source) where `source` is the file it came from, or None when no
    file was found and the built-in defaults apply - the caller reports which, because
    "packed with settings you did not write" should never be silent.

    An explicitly named `path` must exist; a missing ./config.yaml is not an error.
    """
    if path:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"config file not found: {path}")
    else:
        base = Path(cwd or Path.cwd())
        p = base / DEFAULT_CONFIG_NAME
        if not p.is_file():
            # A near-miss filename must not fall through to the defaults in silence: the
            # user wrote a config and would be told nothing about it being ignored, which
            # is the one failure mode this whole lookup order introduces.
            near = base / "config.yml"
            if near.is_file():
                raise ConfigError(
                    f"found {near} but sopack looks for {DEFAULT_CONFIG_NAME}. "
                    f"Rename it, or pass --config {near}.")
            return Config.default(), None
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"could not read {p}: {e}") from None
    return loads(text, source=str(p)), str(p)
