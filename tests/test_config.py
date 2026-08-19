"""The YAML config layer: the sample, the defaults, and every way a config can be wrong.

The command line carries only the input and output APK, so this module is where all the
validation that argparse used to do now lives. Two properties matter more than the rest and
have several tests each:

* `libraries.include` absent/null (auto-select everything) is NOT the same as `include: []`.
  apk.repackage() branches on `wanted_libs is None`, and collapsing the two would silently
  widen a pack to the whole APK.
* An unknown or misplaced key is an ERROR. `--ciper xor` used to be an argparse failure;
  `ciper: xor` must not quietly pack with the default cipher instead.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import mkapk

from sopack import config
from sopack.config import Config, ConfigError, loads
from sopack.stubs import DEFAULT_ABIS, SUPPORTED_ABIS

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = REPO_ROOT / "config.sample.yaml"


# ---- 1. the sample is the defaults, and cannot drift -------------------------------
def test_committed_sample_matches_the_packaged_template():
    """config.sample.yaml is a pinned copy of config.SAMPLE_YAML, not a second source.

    The constant is what `sopack init-config` writes, including from the portable bundle
    wheel; the file is what a reader of the repo sees. They have to be one thing.
    """
    assert SAMPLE_PATH.read_text(encoding="utf-8") == config.SAMPLE_YAML


def test_sample_round_trips_to_exactly_the_defaults():
    """Every value in the sample is its default, so `init-config` then `pack` behaves
    identically to a bare `pack`. This one assertion pins the sample, the SAMPLE_YAML
    constant, the dataclass defaults and stubs.DEFAULT_ABIS together."""
    assert loads(config.SAMPLE_YAML) == Config.default()


@pytest.mark.parametrize("key", [
    "cipher", "abis", "libraries", "include", "exclude",
    "signing", "sign", "verify", "min-sdk", "keystore", "path", "alias",
    "store-pass", "key-pass", "logging", "stub-log", "allow-helper-log",
    # the host troubleshooting log
    "file", "enabled", "dir", "level", "max-size-mb", "max-files", "max-runs",
    "max-index-lines",
])
def test_sample_documents_every_key(key):
    """A new option that the sample does not mention is an undocumented option."""
    assert f"{key}:" in config.SAMPLE_YAML


@pytest.mark.parametrize("pattern", ["libsopk_*", "libvosWrapperEx", "libflutter"])
def test_sample_spells_out_every_excluded_pattern(pattern):
    """The point of the whole exclusion rework: what gets skipped is visible DATA in the
    config, not a hidden built-in behind a boolean. A reader of the file must be able to see
    every pattern that will be applied."""
    assert f"- {pattern}" in config.SAMPLE_YAML


def test_default_excludes_cover_the_patterns_enforced_in_code():
    """The config's list is for VISIBILITY; apk.build_excludes is the enforcement point.
    If the two drift, the config stops telling the truth about what is excluded - so the
    shipped default must stay a superset of what is enforced."""
    from sopack.apk import ALWAYS_EXCLUDE_PATTERNS

    shipped = Config.default().libraries.exclude
    assert set(ALWAYS_EXCLUDE_PATTERNS) <= set(shipped)
    assert "libflutter" in shipped        # policy-only: config is its ONLY home


def test_config_owns_the_user_facing_cipher_default():
    """The protected mode is the one you get by default. chacha20/xor ship the raw key
    (whitened) in the binary, so leaving them as the default meant the tool's whole point was
    opt-in. Note apk.repackage() still defaults to chacha20 - that is the LIBRARY default and
    is unreachable from the CLI, which always passes cipher= explicitly."""
    assert Config.default().cipher == "wbaes"
    assert loads("cipher: chacha20\n").cipher == "chacha20"


# ---- 2. lookup ---------------------------------------------------------------------
def test_no_file_means_built_in_defaults(tmp_path):
    cfg, source = config.load(None, cwd=str(tmp_path))
    assert cfg == Config.default()
    assert source is None            # the CLI says so out loud rather than pretending


def test_cwd_config_is_picked_up(tmp_path):
    (tmp_path / "config.yaml").write_text("cipher: xor\n")
    cfg, source = config.load(None, cwd=str(tmp_path))
    assert cfg.cipher == "xor"
    assert source == str(tmp_path / "config.yaml")


def test_explicit_config_wins_over_cwd(tmp_path):
    (tmp_path / "config.yaml").write_text("cipher: xor\n")
    other = tmp_path / "other.yaml"
    other.write_text("cipher: chacha20\n")
    cfg, source = config.load(str(other), cwd=str(tmp_path))
    assert cfg.cipher == "chacha20"
    assert source == str(other)


def test_missing_explicit_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="config file not found"):
        config.load(str(tmp_path / "nope.yaml"))


def test_config_directory_is_an_error_not_a_traceback(tmp_path):
    (tmp_path / "adir").mkdir()
    with pytest.raises(ConfigError):
        config.load(str(tmp_path / "adir"))


def test_config_yml_is_not_silently_ignored(tmp_path):
    """The one failure mode CWD lookup introduces: a config that is never read and never
    mentioned. A near-miss filename has to say so."""
    (tmp_path / "config.yml").write_text("cipher: xor\n")
    with pytest.raises(ConfigError, match="config.yaml"):
        config.load(None, cwd=str(tmp_path))


def test_errors_name_the_file(tmp_path):
    bad = tmp_path / "mine.yaml"
    bad.write_text("ciper: xor\n")
    with pytest.raises(ConfigError, match="mine.yaml"):
        config.load(str(bad))


# ---- 3. degenerate documents -------------------------------------------------------
@pytest.mark.parametrize("text", ["", "\n", "# only a comment\n"])
def test_empty_document_is_the_defaults(text):
    assert loads(text) == Config.default()


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "42\n"])
def test_non_mapping_document_is_an_error(text):
    with pytest.raises(ConfigError, match="top level"):
        loads(text)


def test_malformed_yaml_names_the_file():
    with pytest.raises(ConfigError, match="mine.yaml: not valid YAML"):
        loads("a: [1, 2\n", "mine.yaml")


@pytest.mark.parametrize("text", ["signing:\n", "libraries:\n", "logging:\n",
                                  "signing:\n  keystore:\n"])
def test_a_null_section_means_that_sections_defaults(text):
    assert loads(text) == Config.default()


def test_duplicate_key_is_an_error():
    """yaml.safe_load keeps the LAST of a repeated key and says nothing. That is the same
    silent-acceptance class the unknown-key check exists to close, only harder to spot
    because both spellings are valid keys."""
    with pytest.raises(ConfigError, match="duplicate key"):
        loads("signing:\n  verify: true\n  verify: false\n")


# ---- 4. unknown and misplaced keys -------------------------------------------------
@pytest.mark.parametrize("text,bad", [
    ("ciper: xor\n", "ciper"),                                   # typo
    ("lib:\n  - a.so\n", "lib"),                                 # stale flag name
    ("wb-keygen: /x\n", "wb-keygen"),                            # a key that never existed
    ("verify: false\n", "verify"),                               # flattened: wrong level
    ("min-sdk: 24\n", "min-sdk"),                                # flattened
    ("no-sign: true\n", "no-sign"),                              # flattened + old polarity
    ("libraries:\n  cipher: wbaes\n", "cipher"),                 # right key, wrong section
    ("signing:\n  stub-log: true\n", "stub-log"),                # right key, wrong section
    ("signing:\n  keystore:\n    password: x\n", "password"),    # invented key
    # logging.file: a nested section, so it needs the same guard at its own level
    ("logging:\n  file:\n    maxsize: 5\n", "maxsize"),           # typo in a subkey
    ("logging:\n  max-runs: 5\n", "max-runs"),                    # right key, wrong level
    ("logging:\n  dir: /tmp/x\n", "dir"),                         # right key, wrong level
    ("file:\n  enabled: true\n", "file"),                         # flattened to the top level
    ("max-files: 5\n", "max-files"),                              # flattened to the top level
    ("signing:\n  file:\n    enabled: true\n", "file"),           # right key, wrong section
])
def test_unknown_or_misplaced_keys_are_an_error(text, bad):
    """A silently ignored `verify: false` is worse than a typo - the user believes they
    turned something off. Every level is checked, not just the top."""
    with pytest.raises(ConfigError, match=f"unknown key|{bad}"):
        loads(text)


@pytest.mark.parametrize("text", [
    "signing:\n  min_sdk: 24\n",
    "signing:\n  keystore:\n    store_pass: x\n",
    "logging:\n  stub_log: true\n",
    "logging:\n  file:\n    max_size_mb: 5\n",
    "logging:\n  file:\n    max_files: 5\n",
    "logging:\n  file:\n    max_runs: 5\n",
    "logging:\n  file:\n    max_index_lines: 5\n",
])
def test_underscore_spellings_are_rejected_with_a_hint(text):
    """One spelling, not two. Accepting both would mean keeping both working forever."""
    with pytest.raises(ConfigError, match="dashes, not underscores"):
        loads(text)


# ---- logging.file: the host troubleshooting log -------------------------------------
@pytest.mark.parametrize("key", ["max-size-mb", "max-files", "max-runs", "max-index-lines"])
@pytest.mark.parametrize("value", [0, -1, -50])
def test_log_caps_must_be_positive(key, value):
    """Zero is the dangerous one, and it is why these do not go through the plain _as_int.
    `max-files: 0` makes RotatingFileHandler stop rotating (one unbounded file) and
    `max-runs: 0` would delete every record as it is written - so a user who set either to
    "off" would get the exact opposite of a bounded log. `enabled: false` is how you turn it
    off, and the message says so."""
    with pytest.raises(ConfigError, match=">= 1"):
        loads(f"logging:\n  file:\n    {key}: {value}\n")


@pytest.mark.parametrize("key", ["max-size-mb", "max-files", "max-runs", "max-index-lines"])
def test_log_caps_reject_a_boolean(key):
    """bool is a subclass of int, so `max-files: true` would otherwise be accepted as 1."""
    with pytest.raises(ConfigError, match="whole number"):
        loads(f"logging:\n  file:\n    {key}: true\n")


def test_log_level_is_checked_against_a_known_set():
    with pytest.raises(ConfigError, match="expected one of"):
        loads("logging:\n  file:\n    level: verbose\n")


def test_log_level_is_case_insensitive_and_normalised():
    assert loads("logging:\n  file:\n    level: DEBUG\n").logging.file.level == "debug"


def test_log_file_must_be_a_mapping():
    with pytest.raises(ConfigError, match="expected a mapping"):
        loads("logging:\n  file: yes-please\n")


def test_log_dir_expands_a_tilde():
    """Matches signing.keystore.path. Note ${VAR} is deliberately NOT expanded here - that stays
    scoped to the keystore fields, and $SOPACK_LOG_DIR already covers redirecting from the
    environment."""
    got = loads("logging:\n  file:\n    dir: ~/mylogs\n").logging.file.dir
    assert got == os.path.expanduser("~/mylogs")
    assert "~" not in got


def test_log_dir_default_is_none_not_a_home_path():
    """Config.default() must not depend on who is running it, or the sample-vs-defaults test
    would pass or fail based on $HOME. diag resolves None to ~/.sopack/logs instead."""
    assert Config.default().logging.file.dir is None


def test_partial_log_file_section_keeps_the_other_defaults():
    got = loads("logging:\n  file:\n    max-runs: 7\n").logging.file
    d = config.LogFileConfig()
    assert got.max_runs == 7
    assert (got.enabled, got.level, got.max_size_mb, got.max_files, got.max_index_lines) == \
           (d.enabled, d.level, d.max_size_mb, d.max_files, d.max_index_lines)


def test_index_cap_defaults_far_above_the_run_cap():
    """The whole point of separating them: run directories are bulky and get pruned early, while
    the index is the batch history and has to outlive them. If these ever converge, a pruned run
    takes last week's triage data with it."""
    d = config.LogFileConfig()
    assert d.max_index_lines > d.max_runs * 5


def test_the_device_log_keys_and_the_host_log_keys_stay_separate():
    """logging.stub-log/allow-helper-log control what the INJECTED code prints to logcat; the
    logging.file block controls what the packer records locally. Conflating them is the mistake
    the nesting exists to prevent, so the two must not share a level."""
    assert "file" in config._LOG_KEYS
    assert not (config._LOG_KEYS - {"file"}) & config._LOGFILE_KEYS


def test_retired_key_gets_a_targeted_message():
    """`libraries.default-excludes` existed and was removed. An upgrading user has it sitting
    in their file, and the generic unknown-key path would only offer a did-you-mean that
    suggests nothing useful - the answer is "that setting is gone, here is what replaced it"."""
    with pytest.raises(ConfigError, match="removed") as e:
        loads("libraries:\n  default-excludes: true\n")
    assert "libraries.exclude" in str(e.value)


def test_a_retired_key_in_the_wrong_section_is_not_mistaken_for_the_retired_one():
    """_REMOVED_KEYS is keyed on the full dotted path. A TOP-LEVEL `default-excludes:` is a
    wrong-section mistake, not the retired key, and must get the ordinary message."""
    with pytest.raises(ConfigError, match="unknown key") as e:
        loads("default-excludes: true\n")
    assert "removed" not in str(e.value)


def test_unknown_key_suggests_the_near_miss():
    with pytest.raises(ConfigError, match="did you mean 'cipher'"):
        loads("ciper: xor\n")


# ---- 5. libraries.include: None is not [] ------------------------------------------
@pytest.mark.parametrize("text", [
    "libraries:\n  exclude: []\n",          # include absent entirely
    "libraries:\n  include:\n",             # include explicitly null
    "libraries:\n  include: null\n",
])
def test_absent_or_null_include_means_auto_select(text):
    assert loads(text).libraries.include is None


def test_explicit_include_is_a_tuple_of_names():
    cfg = loads("libraries:\n  include:\n    - libfoo.so\n    - lib/arm64-v8a/libbar.so\n")
    assert cfg.libraries.include == ("libfoo.so", "lib/arm64-v8a/libbar.so")


def test_empty_include_is_an_error_not_auto_select():
    """`include: []` must NOT silently widen the scope to every library. The two are not
    interchangeable downstream: under auto-select an un-injectable library is skipped with a
    warning and ships in cleartext, while an explicitly named one aborts the pack."""
    with pytest.raises(ConfigError, match="empty"):
        loads("libraries:\n  include: []\n")


@pytest.mark.parametrize("text", [
    "libraries:\n  include: ['']\n",
    "libraries:\n  include: ['  ']\n",
    "libraries:\n  include: [libfoo.so, '']\n",
])
def test_blank_entries_in_include_are_an_error(text):
    with pytest.raises(ConfigError):
        loads(text)


def test_scalar_include_is_an_error():
    """`include: a.so,b.so` would otherwise become one bogus entry matching nothing, and
    surface far away as repackage's "no .so entries matched"."""
    with pytest.raises(ConfigError, match="expected a list"):
        loads("libraries:\n  include: libfoo.so\n")


def test_absent_exclude_means_the_documented_default_list():
    """Absent is not []. A config that never mentions `exclude` still gets the shipped list,
    so behaviour is unchanged from before the key was user-visible."""
    assert loads("libraries:\n  include:\n").libraries.exclude \
        == Config.default().libraries.exclude
    assert loads("").libraries.exclude == Config.default().libraries.exclude


def test_explicit_exclude_replaces_the_default_list():
    assert loads("libraries:\n  exclude: ['libc++_shared', 'libmy*']\n").libraries.exclude \
        == ("libc++_shared", "libmy*")


def test_empty_exclude_is_allowed_unlike_empty_include():
    """The asymmetry is deliberate: `include: []` would WIDEN the pack to the whole APK,
    while `exclude: []` can only narrow protection back to what apk.build_excludes enforces
    unconditionally - there is no unsafe reading of it."""
    assert loads("libraries:\n  exclude: []\n").libraries.exclude == ()


# ---- 6. abis -----------------------------------------------------------------------
def test_abi_default_is_arm64_only():
    assert DEFAULT_ABIS == ("arm64-v8a",)
    assert Config.default().abis == DEFAULT_ABIS
    assert loads("").abis == DEFAULT_ABIS


def test_abis_all_expands_to_every_supported_abi():
    assert loads("abis: all\n").abis == tuple(SUPPORTED_ABIS)


def test_abis_list_is_taken_in_order_and_deduplicated():
    assert loads("abis: [x86_64, arm64-v8a]\n").abis == ("x86_64", "arm64-v8a")
    assert loads("abis: [arm64-v8a, arm64-v8a]\n").abis == ("arm64-v8a",)


def test_unsupported_abi_still_rejected():
    """This check used to live in cli._cmd_pack; argparse never had `choices` for --abi, so
    moving the surface into YAML could have dropped it entirely."""
    with pytest.raises(ConfigError, match="unsupported ABI"):
        loads("abis: [mips]\n")


def test_empty_abis_is_an_error():
    with pytest.raises(ConfigError, match="empty"):
        loads("abis: []\n")


def test_scalar_abi_other_than_all_is_an_error():
    with pytest.raises(ConfigError, match='expected a list'):
        loads("abis: arm64-v8a\n")


# ---- 7. types ----------------------------------------------------------------------
def test_bad_cipher_is_an_error():
    with pytest.raises(ConfigError, match="expected one of"):
        loads("cipher: aes\n")


@pytest.mark.parametrize("text", ["signing:\n  verify: 'true'\n",
                                  "signing:\n  sign: 1\n",
                                  "logging:\n  stub-log: 'yes'\n"])
def test_booleans_must_be_real_booleans(text):
    """YAML's unquoted yes/on ARE booleans, so only the quoted forms reach this - which is
    exactly the confusion worth catching."""
    with pytest.raises(ConfigError, match="expected true or false"):
        loads(text)


@pytest.mark.parametrize("text", ["signing:\n  min-sdk: '24'\n",
                                  "signing:\n  min-sdk: 24.5\n",
                                  "signing:\n  min-sdk: true\n"])
def test_min_sdk_must_be_a_whole_number_or_null(text):
    with pytest.raises(ConfigError, match="whole number"):
        loads(text)


def test_min_sdk_null_is_the_default():
    assert loads("signing:\n  min-sdk:\n").signing.min_sdk is None
    assert loads("signing:\n  min-sdk: 24\n").signing.min_sdk == 24


def test_non_mapping_section_is_a_type_error():
    with pytest.raises(ConfigError, match="expected a mapping"):
        loads("libraries: nope\n")


# ---- 8. ${ENV} expansion, scoped to the keystore -----------------------------------
def test_env_expansion_in_keystore(monkeypatch):
    monkeypatch.setenv("SOPACK_TEST_PASS", "hunter2")
    monkeypatch.setenv("SOPACK_TEST_KS", "/keys/release.jks")
    cfg = loads("signing:\n  keystore:\n"
                "    path: ${SOPACK_TEST_KS}\n"
                "    store-pass: ${SOPACK_TEST_PASS}\n")
    assert cfg.signing.keystore.path == "/keys/release.jks"
    assert cfg.signing.keystore.store_pass == "hunter2"


def test_unset_env_var_is_an_error_naming_the_var(monkeypatch):
    """Never substitute an empty string: apksigner accepts an empty password for a keystore
    created with one, so the mistake would survive all the way to a shipped APK."""
    monkeypatch.delenv("SOPACK_NOT_SET", raising=False)
    with pytest.raises(ConfigError, match=r"SOPACK_NOT_SET"):
        loads("signing:\n  keystore:\n    store-pass: ${SOPACK_NOT_SET}\n")


def test_literal_passwords_still_work():
    assert loads("signing:\n  keystore:\n    store-pass: plaintext\n") \
        .signing.keystore.store_pass == "plaintext"


def test_bare_dollar_name_is_literal(monkeypatch):
    monkeypatch.setenv("SOPACK_TEST_PASS", "hunter2")
    assert loads("signing:\n  keystore:\n    store-pass: $SOPACK_TEST_PASS\n") \
        .signing.keystore.store_pass == "$SOPACK_TEST_PASS"


def test_double_dollar_escapes_to_a_literal(monkeypatch):
    monkeypatch.setenv("SOPACK_TEST_PASS", "hunter2")
    assert loads("signing:\n  keystore:\n    store-pass: $${SOPACK_TEST_PASS}\n") \
        .signing.keystore.store_pass == "${SOPACK_TEST_PASS}"


def test_expansion_does_not_reach_outside_the_keystore():
    """libraries.exclude holds fnmatch globs, which must stay literal. Documented, and this
    is the test that keeps it documented."""
    assert loads("libraries:\n  exclude: ['${NOT_SET_ANYWHERE}']\n").libraries.exclude \
        == ("${NOT_SET_ANYWHERE}",)


def test_keystore_path_expands_a_tilde():
    got = loads("signing:\n  keystore:\n    path: ~/keys/release.jks\n").signing.keystore.path
    assert got.endswith("/keys/release.jks") and not got.startswith("~")


def test_keystore_defaults_match_the_old_flag_defaults():
    ks = Config.default().signing.keystore
    assert (ks.path, ks.alias, ks.store_pass, ks.key_pass) == (None, "sopack", "sopack", None)


# ---- 9. the CLI boundary: config values -> repackage() kwargs ----------------------
# Everything above tests the parsed Config. These test what _cmd_pack actually PASSES, which
# is where a polarity inversion or a dropped field lives: `default-excludes: false` has to
# arrive as `no_sign=True`, and a flipped boolean passes every test above while silently
# shipping an unsigned APK.
@pytest.fixture
def packed(tmp_path, monkeypatch):
    """Run cli._cmd_pack against a captured repackage() and return its kwargs."""
    from sopack import apk, cli

    calls = {}

    class _Res:
        injected, untouched, failed, signed = [], [], [], False

    def _fake_repackage(in_apk, out_apk, wanted_libs, **kw):
        calls.update(kw, wanted_libs=wanted_libs)
        return _Res()

    monkeypatch.setattr(cli, "repackage", _fake_repackage)
    # repackage is faked, but _cmd_pack now validates the input APK up front so a missing input
    # gets exit 4 with a clear message instead of an ENOENT from deep inside the pack (which was
    # indistinguishable from an unwritable OUTPUT path). So the input has to actually exist.
    # A real, DETECTABLE APK, not just a real zip: _cmd_pack classifies the input by content
    # (container.detect) before it calls repackage, so an empty zip is now correctly rejected as
    # "neither an APK nor a bundle" - which would fail these tests for a reason they are not about.
    src = mkapk(tmp_path / "in.apk")
    monkeypatch.setenv("SOPACK_LOG_DIR", str(tmp_path / "logs"))

    def run(yaml_text):
        cfg = tmp_path / "c.yaml"
        cfg.write_text(yaml_text)
        assert cli.main(["pack", str(src), "-o", str(tmp_path / "out.apk"),
                         "--config", str(cfg)]) == 0
        return calls

    return run


def test_defaults_reach_repackage_unchanged(packed):
    kw = packed("")
    assert kw["cipher"] == "wbaes"
    assert kw["abis"] == DEFAULT_ABIS
    assert kw["wanted_libs"] is None          # auto-select, not []
    assert kw["exclude_libs"] == list(Config.default().libraries.exclude)
    assert kw["no_sign"] is False
    assert kw["log"] is False
    assert kw["allow_helper_log"] is False
    assert kw["min_sdk"] is None


def test_positive_config_keys_invert_correctly_at_the_boundary(packed):
    """The one surviving polarity flip. `sign` reads positively in a file the user edits by
    hand, but repackage() takes the negative - so the inversion happens once, here, and a
    flip would otherwise pass every other test in this file while shipping an unsigned APK."""
    assert packed("signing:\n  sign: false\n")["no_sign"] is True
    assert packed("signing:\n  sign: true\n")["no_sign"] is False


def test_include_list_reaches_repackage_as_a_list(packed):
    kw = packed("libraries:\n  include: [libfoo.so]\n")
    assert kw["wanted_libs"] == ["libfoo.so"]


def test_keystore_is_built_even_without_a_path(packed):
    """Unlike the old `if args.keystore` gate, which silently dropped an alias set without a
    path. Now it applies to the same default keystore apk.py would have chosen."""
    from sopack.apk import DEFAULT_KEYSTORE_PATH

    ks = packed("signing:\n  keystore:\n    alias: myalias\n")["keystore"]
    assert ks.path == DEFAULT_KEYSTORE_PATH
    assert ks.alias == "myalias"


def test_key_pass_falls_back_to_store_pass(packed):
    """A silent-wrong-password path if it ever inverts."""
    ks = packed("signing:\n  keystore:\n    store-pass: sp\n")["keystore"]
    assert ks.key_pass == "sp"
    ks = packed("signing:\n  keystore:\n    store-pass: sp\n    key-pass: kp\n")["keystore"]
    assert (ks.store_pass, ks.key_pass) == ("sp", "kp")


def test_a_removed_flag_name_used_as_a_value_is_not_misreported(tmp_path):
    """`--config --cipher.yaml` must report the missing file, not "--cipher was removed".
    The removed-flag scan runs before argparse, so it has no positional awareness of its own."""
    from sopack import cli

    with pytest.raises(SystemExit) as e:
        cli.main(["pack", "in.apk", "-o", "out.apk", "--config", "--cipher"])
    assert "was removed" not in str(e.value)
