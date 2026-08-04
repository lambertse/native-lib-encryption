"""ELF injection engine (LIEF).

Per target .so:
  1. locate `.text`, stream-encrypt its exact bytes in place (length preserving),
  2. append the freestanding stub blob as a fresh R+X PT_LOAD segment,
  3. hijack load-time execution so the stub runs before any encrypted code:
       - DT_INIT present -> repoint to stub, chain the original,
       - else            -> add a DT_INIT in place (before DT_INIT_ARRAY),
     We never hijack DT_INIT_ARRAY: on PIC libs its slots are relocation-populated at
     load, so a file-slot overwrite is reverted and the stub never runs.
  4. patch the decinfo record (deltas, key, nonce, sizes) into the injected segment,
  5. write the rebuilt ELF.

The stub reaches `.text` and the original init at runtime via signed byte deltas from
the address of the decinfo record (which it references PC-relatively) — so no load
bias is needed. See stub/stub.c.

Requires LIEF >= 0.15. LIEF's enum names shifted across versions; _E() shims that.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

import lief

from .cipher import CIPHER_IDS, CIPHER_WBAES, WHITEN_SPAN, apply_cipher, gen_key_nonce, whiten
from .metadata import (DecInfo, FLAG_CHAIN_INIT, FLAG_LOG, FLAG_NEED_ICACHE,
                       MAGIC, SIZE as DECINFO_SIZE, VERSION)
from .provision import provision_text
from .rt_meta import (HELPER_BUILD_MARKER, REGION_MAGIC, REGION_VERSION, WRAPPED_KEY_BYTES,
                      Region)
from .stubs import Stub, helper_skeleton_path, load_stub

# Bionic-provided libraries an injected helper may depend on WITHOUT bundling anything
# (present on every Android device). Anything else in the helper's DT_NEEDED means the
# static link leaked a dependency and would fail to load.
_BIONIC_ALLOWED = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so", "libandroid.so",
    "libEGL.so", "libGLESv2.so", "libGLESv3.so", "libvulkan.so", "libjnigraphics.so",
}

# 16 KB — mandatory max-page-size alignment for the injected LOAD segment so the lib
# still loads on 16 KB-page devices (Android 15+, Play requirement).
SEGMENT_ALIGN = 16384

# Spare bytes reserved in the appended string-table segment, so the common case needs a single
# LIEF write. LIEF's rebuilt .dynstr normally has the same size (it reorders, it does not add),
# but if it grows past this we re-write once at the exact size rather than truncating.
_STRTAB_SLACK = 4096


class InjectError(RuntimeError):
    pass


# ---- LIEF enum compatibility shim -------------------------------------------------
def _seg_type_load():
    try:
        return lief.ELF.Segment.TYPE.LOAD
    except AttributeError:
        return lief.ELF.SEGMENT_TYPES.LOAD


def _seg_flags():
    try:
        return lief.ELF.Segment.FLAGS
    except AttributeError:
        return lief.ELF.SEGMENT_FLAGS


def _seg_flags_rx():
    F = _seg_flags()
    return F.R | F.X


def _seg_flags_r():
    return _seg_flags().R


def _tag(name):
    try:
        return getattr(lief.ELF.DynamicEntry.TAG, name)
    except AttributeError:
        return getattr(lief.ELF.DYNAMIC_TAGS, name)


@dataclass
class InjectResult:
    abi: str
    text_rva: int
    text_size: int
    seg_rva: int
    entry_rva: int
    strategy: str          # how load-time execution was hijacked
    cipher: str
    # wbaes only: the per-target helper .so that must be ADDED to the APK as a sibling.
    helper_path: str | None = None
    helper_soname: str | None = None


def _find_text(binary) -> "lief.ELF.Section":
    sec = binary.get_section(".text")
    if sec is not None and sec.size > 0:
        return sec
    # Fallback: first PROGBITS + EXECINSTR section.
    try:
        TYPE = lief.ELF.Section.TYPE.PROGBITS
        FLAG = lief.ELF.Section.FLAGS.EXECINSTR
    except AttributeError:
        TYPE = lief.ELF.SECTION_TYPES.PROGBITS
        FLAG = lief.ELF.SECTION_FLAGS.EXECINSTR
    for s in binary.sections:
        if s.type == TYPE and (int(s.flags) & int(FLAG)) and s.size > 0:
            return s
    raise InjectError(
        "no .text section found (library may be section-stripped); "
        "segment-granularity encryption is not implemented in v1"
    )


def _hijack_existing_init(binary, decinfo_rva: int, entry_rva: int):
    """Repoint an EXISTING DT_INIT to the stub and chain the original, in place (no
    .dynamic growth, so no extra segment is created). Only called when a usable DT_INIT
    is present.

    We deliberately do NOT hijack DT_INIT_ARRAY: on PIC libraries its slots are populated
    by R_*_RELATIVE relocations at load, so a file-level overwrite is reverted by the
    loader. Libraries with no DT_INIT get one ADDED instead (see _add_dtinit_inplace),
    which bionic invokes before DT_INIT_ARRAY."""
    init = binary.get(_tag("INIT"))
    orig = init.value
    init.value = entry_rva
    return FLAG_CHAIN_INIT, orig - decinfo_rva, "DT_INIT-hijack"


def _dynamic_soname(binary) -> str | None:
    e = binary.get(_tag("SONAME"))
    name = getattr(e, "name", None) if e is not None else None
    return name or None


def _set_soname(binary, soname: str) -> None:
    e = binary.get(_tag("SONAME"))
    if e is not None:
        e.name = soname
        return
    try:
        binary.add(lief.ELF.DynamicSharedObject(soname))
    except Exception as exc:  # pragma: no cover - skeleton always has a SONAME
        raise InjectError(f"helper skeleton has no DT_SONAME and none could be added: {exc}")


def _needed_names(binary) -> list[str]:
    return [e.name for e in binary.dynamic_entries if e.tag == _tag("NEEDED")]


class _LoaderView:
    """A read-only view of a `.so` the way the LOADER sees it: program headers plus
    `.dynamic`, never section headers.

    The wbaes path supersedes `.dynstr` with an appended copy, so its section header and
    `DT_STRTAB` legitimately point at different bytes, and only `DT_STRTAB` is what `dlsym`
    uses. Anything asserting a runtime property must read it this way."""

    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.buf = buf = f.read()
        self.is64 = is64 = buf[4] == 2
        self.W = W = "<Q" if is64 else "<I"
        e_phoff = struct.unpack_from(W, buf, 0x20 if is64 else 0x1C)[0]
        e_phentsize = struct.unpack_from("<H", buf, 0x36 if is64 else 0x2A)[0]
        e_phnum = struct.unpack_from("<H", buf, 0x38 if is64 else 0x2C)[0]
        p_offset, p_vaddr = (8, 16) if is64 else (4, 8)
        p_filesz, p_memsz = (32, 40) if is64 else (16, 20)
        self.loads, dyn = [], None
        for i in range(e_phnum):
            p = e_phoff + i * e_phentsize
            ptype = struct.unpack_from("<I", buf, p)[0]
            if ptype == _PT_LOAD:
                self.loads.append((struct.unpack_from(W, buf, p + p_vaddr)[0],
                                   struct.unpack_from(W, buf, p + p_offset)[0],
                                   struct.unpack_from(W, buf, p + p_filesz)[0],
                                   struct.unpack_from(W, buf, p + p_memsz)[0]))
            elif ptype == _PT_DYNAMIC:
                dyn = (struct.unpack_from(W, buf, p + p_offset)[0],
                       struct.unpack_from(W, buf, p + p_filesz)[0])
        self.tags: dict[int, int] = {}
        self.needed_offs: list[int] = []
        if dyn is None:
            return
        DYN = 16 if is64 else 8
        DTAG = "<q" if is64 else "<i"
        for i in range(dyn[1] // DYN):
            off = dyn[0] + i * DYN
            tag = struct.unpack_from(DTAG, buf, off)[0]
            val = struct.unpack_from(W, buf, off + (8 if is64 else 4))[0]
            if tag == _DT_NULL:
                break
            if tag == _DT_NEEDED:
                self.needed_offs.append(val)
            else:
                self.tags[tag] = val

    def vaddr_to_off(self, va: int) -> int | None:
        # p_filesz, not p_memsz: a vaddr in the .bss tail has no file bytes to read.
        for v, o, fsz, _msz in self.loads:
            if v <= va < v + fsz:
                return o + (va - v)
        return None

    def str_at(self, base: int, off: int) -> str:
        end = self.buf.index(b"\x00", base + off)
        return self.buf[base + off:end].decode("utf-8", "replace")

    def strtab_off(self) -> int | None:
        va = self.tags.get(_DT_STRTAB)
        return None if va is None else self.vaddr_to_off(va)

    def needed(self) -> list[str]:
        base = self.strtab_off()
        if base is None:
            return []
        return [self.str_at(base, o) for o in self.needed_offs]

    def dynsym_count(self) -> int | None:
        """Number of `.dynsym` entries.

        `DT_HASH`'s `nchain` IS the count. Otherwise use the `.dynsym` SECTION header size —
        safe despite this class's rule, because sopack never moves or rewrites `.dynsym`: count
        from the untouched section header, strings from the relocated `DT_STRTAB`.

        Deliberately NO `DT_GNU_HASH` fallback — it covers only defined exported symbols, so it
        under-counts (badly, for a library that exports nothing). See CLAUDE.md's invariant."""
        if _DT_HASH in self.tags:
            o = self.vaddr_to_off(self.tags[_DT_HASH])
            if o is not None:
                return struct.unpack_from("<I", self.buf, o + 4)[0]
        return self._dynsym_count_from_shdr()

    def _dynsym_count_from_shdr(self) -> int | None:
        buf, is64, W = self.buf, self.is64, self.W
        e_shoff = struct.unpack_from(W, buf, 0x28 if is64 else 0x20)[0]
        e_shentsize = struct.unpack_from("<H", buf, 0x3A if is64 else 0x2E)[0]
        e_shnum = struct.unpack_from("<H", buf, 0x3C if is64 else 0x30)[0]
        if not e_shoff or not e_shnum:
            return None
        sh_size_off = 0x20 if is64 else 0x14
        for i in range(e_shnum):
            s = e_shoff + i * e_shentsize
            if s + e_shentsize > len(buf):
                return None
            if struct.unpack_from("<I", buf, s + 4)[0] == _SHT_DYNSYM:
                size = struct.unpack_from(W, buf, s + sh_size_off)[0]
                ent = 24 if is64 else 16
                return size // ent
        return None


def _needed_via_strtab(path: str) -> list[str]:
    """Resolve DT_NEEDED names the way the LOADER does — via DT_STRTAB read from .dynamic
    (not the .dynstr section, which we may have superseded with a copy)."""
    return _LoaderView(path).needed()


def _effective_strtab(path: str) -> bytes:
    """The DT_STRTAB bytes as written — the table `.dynsym`'s st_name offsets actually index.

    Read this AFTER LIEF's write, never from a pre-write `.dynstr` section: LIEF rebuilds the
    string table with the strings sorted and rewrites every st_name to match, so the pre-write
    bytes are a different table with the same contents in a different order."""
    v = _LoaderView(path)
    base, strsz = v.strtab_off(), v.tags.get(_DT_STRSZ)
    if base is None or strsz is None:
        raise InjectError(f"{os.path.basename(path)} has no usable DT_STRTAB/DT_STRSZ")
    return v.buf[base:base + strsz]


def _walk_dynsyms(path: str, undefined_only: bool = False) -> list[str]:
    """Dynamic symbol names, resolved exactly as `dlsym` would: `DT_SYMTAB` indexed against
    `DT_STRTAB`, count from `_LoaderView.dynsym_count`, section headers ignored.

    `undefined_only` keeps just the `SHN_UNDEF` entries — what this `.so` needs the loader to
    resolve for it. Returns [] for a `.so` with no dynamic symbols at all, but RAISES if it has
    a `DT_SYMTAB` whose length cannot be established: both callers are guards, and a guard that
    silently inspects nothing is how the bug in §11f shipped."""
    v = _LoaderView(path)
    symtab_va, strtab = v.tags.get(_DT_SYMTAB), v.strtab_off()
    if symtab_va is None or strtab is None:
        return []
    symtab, n = v.vaddr_to_off(symtab_va), v.dynsym_count()
    if symtab is None or n is None:
        raise InjectError(
            f"{os.path.basename(path)} has a DT_SYMTAB whose entry count cannot be determined, "
            "so its symbols cannot be verified")
    ent = 24 if v.is64 else 16
    out = []
    for i in range(n):
        st_name, _info, _other, shndx = struct.unpack_from("<IBBH", v.buf, symtab + i * ent)
        if st_name and (shndx == 0 or not undefined_only):   # index 0 is the reserved symbol
            out.append(v.str_at(strtab, st_name))
    return out


def _dynsym_names(path: str) -> list[str]:
    """Every dynamic symbol name — pins the invariant that an injection must never change the
    target's exported symbol names (see `_self_verify_wbaes`)."""
    return _walk_dynsyms(path)


def _undefined_dynsyms(path: str) -> list[str]:
    """Symbols this `.so` imports — catches a helper skeleton linked against a 1.x
    `libwbcrypto.a`, which links cleanly and then cannot load."""
    return _walk_dynsyms(path, undefined_only=True)


def _helper_soname_for(target_soname: str) -> str:
    """Per-target helper soname. Keep it deterministic and collision-free."""
    base = target_soname[:-3] if target_soname.endswith(".so") else target_soname
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in base)
    return f"libsopk_rt_{safe}.so"


def _emit_helper(abi: str, helper_soname: str, region_bytes: bytes,
                 out_path: str) -> None:
    """Clone the ABI helper skeleton: rename its DT_SONAME and append the metadata region
    as a fresh read-only 16 KB-aligned PT_LOAD (its first bytes are the region, which the
    helper's constructor finds by magic — see stub/sopk_rt.c)."""
    skeleton = helper_skeleton_path(abi)

    # Build-marker guard. The skeleton is built by hand outside this repo, so a stale one is
    # easy to leave behind — and a stale one is SILENT: its ctor requires an exact region
    # version match, finds none, fails open, and the target runs still-encrypted .text and
    # SIGILLs with nothing pointing at the cause. Catch it here instead.
    with open(skeleton, "rb") as f:
        if HELPER_BUILD_MARKER not in f.read():
            raise InjectError(
                f"helper skeleton {os.path.basename(str(skeleton))} lacks the v{REGION_VERSION} build marker "
                f"({HELPER_BUILD_MARKER.hex()}) — it was built from an older stub/sopk_rt.c "
                "and would fail open at load, leaving encrypted .text to crash the app. "
                "Rebuild it from the current stub/sopk_rt.c against whitebox-cryptography "
                ">= 2.0.0 (see docs/wbaes-verification.md).")

    binary = lief.parse(str(skeleton))
    if binary is None:
        raise InjectError(f"LIEF failed to parse helper skeleton {skeleton}")

    # dependency-closure guard: a correctly static-linked helper needs only bionic libs.
    stray = [n for n in _needed_names(binary) if n not in _BIONIC_ALLOWED]
    if stray:
        raise InjectError(
            f"helper skeleton {os.path.basename(str(skeleton))} has non-bionic DT_NEEDED {stray} — the "
            "white-box was not statically linked in (libwbcrypto/libc++/libsodium must be "
            "static). Rebuild the skeleton.")

    # A `-shared` link permits unresolved symbols, so a skeleton built against a 1.x
    # libwbcrypto.a (no wbc_wrap_key/wbc_unwrap_key/wbc_wipe) links CLEANLY and leaves them as
    # UND imports. bionic then fails to load the helper, which makes dlopen of the TARGET fail,
    # which surfaces as a crash in whatever was loading the target — nowhere near the cause.
    # Catch it here; also tell the user the link flag that would have caught it at build time.
    unresolved = sorted({n for n in _undefined_dynsyms(str(skeleton))
                         if n.startswith(("wbc_", "sodium_"))})
    if unresolved:
        raise InjectError(
            f"helper skeleton {os.path.basename(str(skeleton))} imports {unresolved} instead of defining them — "
            "it was linked against a 1.x libwbcrypto.a (or none). The helper would fail to "
            "load, taking the target's dlopen down with it. Rebuild assets/wbc/ from "
            "whitebox-cryptography >= 2.0.0 (scripts/build_android.sh) and link with "
            "-Wl,--no-undefined so this fails at build time instead.")

    _set_soname(binary, helper_soname)

    seg = lief.ELF.Segment()
    seg.type = _seg_type_load()
    seg.flags = _seg_flags_r()          # read-only: not W, not X (region is data)
    seg.alignment = SEGMENT_ALIGN
    seg.content = list(region_bytes)
    binary.add(seg)
    binary.write(out_path)


def _inject_wbaes(in_path: str, out_path: str, abi: str,
                  wb_keygen: str | None, target_name: str | None) -> InjectResult:
    """`--cipher wbaes`: encrypt `.text` with ChaCha20 under a session key that is wrapped
    by a sealed white-box AES-128 key, and inject a per-target DT_NEEDED helper that unwraps
    and decrypts at load. No stub/decinfo/DT_INIT surgery — the helper's constructor runs
    before the target's init via dependency ordering. See sopack/provision.py for why the
    white-box no longer touches the bulk data."""
    binary = lief.parse(in_path)
    if binary is None:
        raise InjectError(f"LIEF failed to parse {in_path}")

    # The soname the on-device helper matches via dl_iterate_phdr basename. Prefer the APK
    # file name bionic will report; fall back to DT_SONAME, then the input basename.
    target_soname = (target_name or _dynamic_soname(binary)
                     or os.path.basename(in_path))

    # 1. encrypt .text under a freshly wrapped session key (host provisioning).
    text = _find_text(binary)
    text_size = int(text.size)
    plain = bytes(text.content)[:text_size]
    if len(plain) != text_size:
        raise InjectError(".text content shorter than declared size")
    prov = provision_text(plain, wb_keygen=wb_keygen)
    text.content = list(prov.ciphertext)

    # 2. inject the per-target helper as a DT_NEEDED. We do NOT use LIEF add_library: it
    #    grows .dynamic + .dynstr and on tight libs (e.g. libapp.so) LIEF spills them into
    #    4 KB-aligned segments that break 16 KB loading (Risk 2). Instead we mirror the stub
    #    path: append a 16 KB-aligned COPY of .dynstr (+ our soname) with the trusted
    #    add(seg), then raw-repoint DT_STRTAB/DT_STRSZ and add DT_NEEDED in place — keeping
    #    .dynamic and PT_DYNAMIC where they are.
    #
    #    The copied table MUST come from _effective_strtab (post-write), not from the section
    #    read here — see that function's docstring. Hence: reserve a placeholder segment, let
    #    LIEF write, then fill the placeholder with the table LIEF actually emitted.
    helper_soname = _helper_soname_for(target_soname)
    dynstr = binary.get_section(".dynstr")
    if dynstr is None:
        raise InjectError("target has no .dynstr section")
    soname_bytes = helper_soname.encode("ascii") + b"\x00"
    # LIEF's rebuild only reorders and may de-duplicate, so its table is normally the same
    # size; the slack absorbs a table that grew. An overflow is handled below, never ignored.
    reserve = len(bytes(dynstr.content)) + len(soname_bytes) + _STRTAB_SLACK

    for attempt in range(2):
        b = binary if attempt == 0 else lief.parse(in_path)
        if b is None:
            raise InjectError(f"LIEF failed to re-parse {in_path}")
        seg = lief.ELF.Segment()
        seg.type = _seg_type_load()
        seg.flags = _seg_flags_r()      # read-only data (the string table copy)
        seg.alignment = SEGMENT_ALIGN
        seg.content = [0] * reserve
        added = b.add(seg)
        # add(seg) updates in-memory vaddrs consistently (proven by the stub path): read now.
        text_rva = int(_find_text(b).virtual_address)
        strtab_rva = int(added.virtual_address)
        b.write(out_path)
        strtab_foff = int(added.file_offset)   # reliable after write (same as the stub path)

        # The table .dynsym's offsets actually refer to, straight out of the written file.
        eff = _effective_strtab(out_path)
        new_strtab = eff + soname_bytes
        if len(new_strtab) <= reserve:
            break
        if attempt:
            raise InjectError(
                f"appended string table still does not fit ({len(new_strtab)} > {reserve})")
        reserve = len(new_strtab)         # retry once at the exact size

    name_off = len(eff)

    # 3. raw ELF surgery on the written file: write the effective table into the placeholder,
    #    repoint DT_STRTAB/DT_STRSZ (and the .dynstr section header, so tools agree with the
    #    loader), and overwrite the .dynamic DT_NULL terminator with our DT_NEEDED.
    with open(out_path, "r+b") as f:
        f.seek(strtab_foff)
        f.write(new_strtab)
    _add_needed_inplace(out_path, name_off, strtab_rva, strtab_foff, len(new_strtab))

    # 4. build + emit the helper carrying this target's metadata region.
    region = Region(
        text_rva=text_rva, text_size=text_size,
        wrapped=prov.wrapped, nonce16=prov.nonce16,
        soname=target_soname.encode("utf-8"), wpass=prov.wpass, blob=prov.blob,
    ).pack()
    helper_path = out_path + ".helper.so"
    _emit_helper(abi, helper_soname, region, helper_path)

    # 5. self-verify both artifacts.
    _self_verify_wbaes(out_path, helper_path, prov.ciphertext, text_rva, text_size,
                       target_soname, helper_soname, abi, in_path)

    return InjectResult(abi=abi, text_rva=text_rva, text_size=text_size,
                        seg_rva=0, entry_rva=0, strategy="DT_NEEDED-wbaes",
                        cipher="wbaes", helper_path=helper_path,
                        helper_soname=helper_soname)


def _self_verify_wbaes(target_path, helper_path, ciphertext, text_rva, text_size,
                       target_soname, helper_soname, abi, in_path):
    """Assert every invariant the on-device helper depends on, for both artifacts."""
    tgt = lief.parse(target_path)
    if tgt is None:
        raise InjectError("re-parse of wbaes target failed")
    # (a) .text vaddr unchanged vs what we baked into the region, and content is ciphertext.
    # Read the .text bytes straight from the file at the section offset (LIEF's .content on
    # a multi-MB section is slow and, on some builds, unreliable).
    t = _find_text(tgt)
    if int(t.virtual_address) != text_rva:
        raise InjectError(f".text vaddr shifted after write: 0x{int(t.virtual_address):x}")
    with open(target_path, "rb") as f:
        f.seek(int(t.file_offset))
        if f.read(text_size) != ciphertext:
            raise InjectError("target .text is not the provisioned ciphertext")
    # (b) DT_NEEDED points at the helper — resolved via DT_STRTAB, as the loader does.
    if helper_soname not in _needed_via_strtab(target_path):
        raise InjectError(f"DT_NEEDED {helper_soname!r} missing from target")
    # (b2) EVERY existing exported symbol name still resolves to the same string. A mismatch
    # means dlsym() returns the wrong name or NULL — an APK that loads and then crashes far
    # from the cause. Cheap check; see docs/architecture.md §11f for the incident.
    before, after = _dynsym_names(in_path), _dynsym_names(target_path)
    if before != after:
        bad = next(((x, y) for x, y in zip(before, after) if x != y), None)
        detail = f"e.g. {bad[0]!r} -> {bad[1]!r}" if bad else \
                 f"count {len(before)} -> {len(after)}"
        raise InjectError(
            f"injection changed the target's dynamic symbol names ({detail}) — DT_STRTAB and "
            "the .dynsym offsets are out of sync, so dlsym() would fail on device")
    # (c) 16 KB congruence for arm64 (the only 16 KB-page device class) + no text relocs.
    _assert_16k_and_no_textrel(tgt, abi, orig_path=in_path)

    hlp = lief.parse(helper_path)
    if hlp is None:
        raise InjectError("re-parse of wbaes helper failed")
    if _dynamic_soname(hlp) != helper_soname:
        raise InjectError("helper DT_SONAME not renamed")
    stray = [n for n in _needed_names(hlp) if n not in _BIONIC_ALLOWED]
    if stray:
        raise InjectError(f"emitted helper has non-bionic DT_NEEDED {stray}")
    _assert_16k_and_no_textrel(hlp, abi)
    # (d) the region round-trips and describes THIS target.
    region = _extract_region(helper_path)
    r = Region.unpack(region)
    if (r.text_rva, r.text_size) != (text_rva, text_size):
        raise InjectError("helper region text_rva/size mismatch")
    if r.soname.decode("utf-8", "replace") != target_soname:
        raise InjectError("helper region soname mismatch")
    if len(r.blob) < WHITEN_SPAN or len(r.wpass) == 0:
        raise InjectError("helper region blob/pass missing")
    # The helper reads these as fixed-size fields, so a wrong length here is a wrong-length
    # unwrap on device (i.e. a silent garbage session key), not a parse error.
    if len(r.wrapped) != WRAPPED_KEY_BYTES:
        raise InjectError(
            f"helper region wrapped key is {len(r.wrapped)} bytes, expected {WRAPPED_KEY_BYTES}")
    if len(r.nonce16) != 16 or r.nonce16 == b"\x00" * 16:
        raise InjectError("helper region ChaCha20 nonce missing or all-zero")


def _16k_violations(binary) -> list[str]:
    """LOAD segments that would stop this `.so` loading on a 16 KB-page device."""
    load_t = _seg_type_load()
    bad = []
    for s in binary.segments:
        if s.type != load_t:
            continue
        if int(s.alignment) % SEGMENT_ALIGN != 0:
            bad.append(f"align {int(s.alignment)}")
        elif (int(s.virtual_address) - int(s.file_offset)) % SEGMENT_ALIGN != 0:
            bad.append(f"vaddr 0x{int(s.virtual_address):x} not congruent with "
                       f"offset 0x{int(s.file_offset):x}")
    return bad


def _assert_16k_and_no_textrel(binary, abi, orig_path: str | None = None):
    """16 KB page hardware is arm64-only, so this gates arm64-v8a output only — armeabi-v7a and
    x86_64 inputs commonly ship 4 KB LOADs and must not be rejected over a device class that
    cannot run them.

    `orig_path` lets the failure distinguish the two very different causes. If the INPUT already
    violates the rule, that is a property of the library we were handed: no amount of packer
    correctness can fix it, and saying "LOAD seg align 4096" without that context sends the
    reader looking for a bug in the injection."""
    if abi == "arm64-v8a":
        bad = _16k_violations(binary)
        if bad:
            pre = _16k_violations(lief.parse(orig_path)) if orig_path else []
            if pre:
                raise InjectError(
                    f"{os.path.basename(orig_path)} is not 16 KB-page compatible to begin with: "
                    f"its own LOAD segments already violate the rule ({'; '.join(pre)}) before "
                    "any injection, so the packed output cannot either. Rebuild that library "
                    "with -Wl,-z,max-page-size=16384, or pack it only for 4 KB device classes.")
            raise InjectError(
                f"the injection produced a LOAD segment that breaks 16 KB loading "
                f"({'; '.join(bad)}) — the input was clean, so this one is ours")
    if binary.get(_tag("TEXTREL")) is not None:
        raise InjectError("output has DT_TEXTREL (text relocations) — must be absent")


def _extract_region(helper_path: str) -> bytes:
    """Read the appended region back out of an emitted helper by locating the read-only
    PT_LOAD whose file bytes start with the region magic (mirrors the ctor's magic-scan)."""
    magic = REGION_MAGIC.to_bytes(4, "little")
    b = lief.parse(helper_path)
    F = _seg_flags()
    with open(helper_path, "rb") as f:
        data = f.read()
    for s in b.segments:
        if s.type != _seg_type_load():
            continue
        fl = int(s.flags)
        if (fl & int(F.W)) or (fl & int(F.X)):
            continue
        off = int(s.file_offset)
        if data[off:off + 4] == magic:
            size = int(s.physical_size) or (len(data) - off)
            return data[off:off + size]
    raise InjectError("could not find the region segment in the emitted helper")


def inject_so(in_path: str, out_path: str, abi: str,
              cipher: str = "chacha20", log: bool = False,
              wb_keygen: str | None = None,
              target_name: str | None = None) -> InjectResult:
    if CIPHER_IDS[cipher] == CIPHER_WBAES:
        return _inject_wbaes(in_path, out_path, abi, wb_keygen, target_name)
    stub: Stub = load_stub(abi)
    cipher_id = CIPHER_IDS[cipher]
    # Whitening span: the WHITEN_SPAN stub bytes immediately before g_decinfo — real
    # code/rodata the injector never rewrites (only g_decinfo, at decinfo_off, is patched).
    # The stub recomputes the same checksum over these bytes at runtime. See cipher.whiten.
    if stub.decinfo_off < WHITEN_SPAN or stub.decinfo_off > len(stub.blob):
        raise InjectError(
            f"stub layout invalid for whitening: decinfo_off={stub.decinfo_off} "
            f"span={WHITEN_SPAN} size={len(stub.blob)}")
    whiten_span = stub.blob[stub.decinfo_off - WHITEN_SPAN:stub.decinfo_off]
    # Guard against a future stub edit parking a large low-entropy (e.g. zeroed) constant
    # right before g_decinfo, which would silently weaken the whitening key to a near-fixed
    # value. Real stub code/rodata has many distinct bytes.
    if len(set(whiten_span)) < 16:
        raise InjectError(
            f"whitening span is low-entropy ({len(set(whiten_span))} distinct bytes) — "
            "the stub layout before g_decinfo changed; the whitening key would be weak")

    binary = lief.parse(in_path)
    if binary is None:
        raise InjectError(f"LIEF failed to parse {in_path}")

    # --- 1. locate + encrypt .text (length-preserving, offsets untouched) ---
    text = _find_text(binary)
    text_size = int(text.size)
    plain = bytes(text.content)[:text_size]
    if len(plain) != text_size:
        raise InjectError(".text content shorter than declared size")
    key, nonce = gen_key_nonce()
    enc = apply_cipher(cipher_id, plain, key, nonce)
    text.content = list(enc)

    # Load-time hook policy. If the library already exposes a usable DT_INIT we repoint it
    # (chaining the original). Otherwise we ADD a DT_INIT in place — even when the library
    # has a DT_INIT_ARRAY.
    #
    # We deliberately never hijack DT_INIT_ARRAY. On PIC libraries (every Android .so) each
    # INIT_ARRAY slot is filled at load time by an R_*_RELATIVE relocation, so the file slot
    # reads 0 and any pointer we write there is silently reverted by the loader (the
    # relocation addend wins) — the stub never runs and the still-encrypted constructor
    # executes as garbage (SIGILL). A DT_INIT entry lives in .dynamic, is NOT relocated
    # (bionic adds load_bias to d_ptr directly), and soinfo::call_constructors invokes
    # DT_INIT BEFORE DT_INIT_ARRAY — so our stub decrypts .text first and the library's own
    # constructors then run on decrypted code. We add it WITHOUT growing .dynamic (which
    # makes LIEF spill it into a 4 KB-aligned segment that breaks 16 KB loading) and without
    # moving .dynamic to a non-writable segment (which bionic/glibc reject): we overwrite the
    # existing DT_NULL terminator in place, using the zero word that follows as the new
    # terminator. See _add_dtinit_inplace.
    has_init = (binary.get(_tag("INIT")) is not None
                and binary.get(_tag("INIT")).value != 0)
    add_dtinit = not has_init

    # --- 2. append stub as a fresh R+X LOAD segment (raw blob; magic present) ---
    seg = lief.ELF.Segment()
    seg.type = _seg_type_load()
    seg.flags = _seg_flags_rx()
    seg.alignment = SEGMENT_ALIGN
    seg.content = list(stub.blob)
    added = binary.add(seg)
    # add() inserts a program header and re-bases existing content (LIEF updates all
    # vaddrs/relocs/dynamic entries consistently). Read .text's FINAL vaddr now, after
    # the shift, so delta_text is computed against the layout the loader will see.
    text_rva = int(_find_text(binary).virtual_address)
    seg_rva = int(added.virtual_address)
    decinfo_rva = seg_rva + stub.decinfo_off
    entry_rva = seg_rva + stub.entry_off

    # --- 3. hijack load-time execution ---
    if add_dtinit:
        flags, delta_init, strategy = 0, 0, "DT_INIT-inplace"
    else:
        flags, delta_init, strategy = _hijack_existing_init(binary, decinfo_rva, entry_rva)
    if abi == "armeabi-v7a":
        flags |= FLAG_NEED_ICACHE  # 32-bit ARM I-cache flush via cacheflush syscall
    if log:
        flags |= FLAG_LOG          # emit a logcat confirmation on successful decrypt

    # --- 4. write rebuilt ELF ---
    binary.write(out_path)
    seg_file_off = int(added.file_offset)

    # --- 5. add-DT_INIT path: overwrite the DT_NULL terminator with DT_INIT in place ---
    if add_dtinit:
        _add_dtinit_inplace(out_path, entry_rva)

    # --- 6. patch decinfo at its KNOWN blob offset, then WHITEN it in place ---
    info = DecInfo(
        cipher_id=cipher_id, flags=flags,
        delta_text=text_rva - decinfo_rva, text_size=text_size,
        delta_init=delta_init, key=key, nonce=nonce,
    )
    decinfo_off = seg_file_off + stub.decinfo_off
    _patch_decinfo(out_path, info, decinfo_off, whiten_span)

    # --- 7. desktop self-verification: turn silent on-device failures into errors ---
    _self_verify(out_path, plain, info, cipher_id, key, nonce,
                 text_rva, entry_rva, seg_rva, decinfo_off, whiten_span, strategy)

    return InjectResult(abi=abi, text_rva=text_rva, text_size=text_size,
                        seg_rva=seg_rva, entry_rva=entry_rva,
                        strategy=strategy, cipher=cipher)


_DT_NULL, _DT_INIT, _SHT_DYNAMIC, _PT_DYNAMIC, _PT_LOAD = 0, 12, 6, 2, 1
_DT_NEEDED, _DT_STRTAB, _DT_STRSZ = 1, 5, 10
_DT_HASH, _DT_SYMTAB, _SHT_DYNSYM = 4, 6, 11


def _add_needed_inplace(path: str, name_off: int, new_strtab_vaddr: int,
                        new_strtab_foff: int, new_strsz: int) -> None:
    """Add a DT_NEEDED whose name lives at `name_off` in a NEW string table (already
    appended as its own segment), WITHOUT growing/moving .dynamic. We (1) repoint
    DT_STRTAB/DT_STRSZ to the new table (a verbatim copy of the old .dynstr + our soname,
    so every existing string offset still resolves), (2) repoint the .dynstr SECTION header
    to the same copy so section-based tools (readelf -d, LIEF) agree with the loader, and
    (3) overwrite the .dynamic DT_NULL terminator in place with DT_NEEDED, using the
    following zero word as the new terminator — the same in-place trick as
    _add_dtinit_inplace (and the same loud refusal when there is no usable terminator slot).
    Class-aware raw ELF little-endian surgery."""
    with open(path, "r+b") as f:
        buf = bytearray(f.read())
        is64 = buf[4] == 2
        W = "<Q" if is64 else "<I"
        E_PHOFF, E_SHOFF = (0x20, 0x28) if is64 else (0x1C, 0x20)
        E_PHENTSIZE, E_PHNUM = (0x36, 0x38) if is64 else (0x2A, 0x2C)
        E_SHENTSIZE, E_SHNUM = (0x3A, 0x3C) if is64 else (0x2E, 0x30)
        P_OFFSET = 8 if is64 else 4
        P_FILESZ = 32 if is64 else 16
        P_MEMSZ = 40 if is64 else 20
        SH_ADDR = 16 if is64 else 12
        SH_OFFSET = 24 if is64 else 16
        SH_SIZE = 32 if is64 else 20
        _SHT_STRTAB = 3
        DYN = 16 if is64 else 8
        DTAG = "<q" if is64 else "<i"
        DPACK = "<qQ" if is64 else "<iI"

        e_phoff = struct.unpack_from(W, buf, E_PHOFF)[0]
        e_phentsize = struct.unpack_from("<H", buf, E_PHENTSIZE)[0]
        e_phnum = struct.unpack_from("<H", buf, E_PHNUM)[0]
        e_shoff = struct.unpack_from(W, buf, E_SHOFF)[0]
        e_shentsize = struct.unpack_from("<H", buf, E_SHENTSIZE)[0]
        e_shnum = struct.unpack_from("<H", buf, E_SHNUM)[0]

        ph_dyn = None
        loads = []
        for i in range(e_phnum):
            p = e_phoff + i * e_phentsize
            ptype = struct.unpack_from("<I", buf, p)[0]
            if ptype == _PT_DYNAMIC:
                ph_dyn = p
            elif ptype == _PT_LOAD:
                loads.append((struct.unpack_from(W, buf, p + P_OFFSET)[0],
                              struct.unpack_from(W, buf, p + P_FILESZ)[0],
                              struct.unpack_from(W, buf, p + P_MEMSZ)[0]))
        if ph_dyn is None:
            raise InjectError("no PT_DYNAMIC program header found")
        dyn_off = struct.unpack_from(W, buf, ph_dyn + P_OFFSET)[0]
        dyn_filesz = struct.unpack_from(W, buf, ph_dyn + P_FILESZ)[0]

        # repoint DT_STRTAB / DT_STRSZ and locate the DT_NULL terminator in one pass.
        term = None
        old_strtab_vaddr = None
        for i in range(dyn_filesz // DYN):
            off = dyn_off + i * DYN
            tag = struct.unpack_from(DTAG, buf, off)[0]
            if tag == _DT_STRTAB:
                old_strtab_vaddr = struct.unpack_from(W, buf, off + (8 if is64 else 4))[0]
                struct.pack_into(W, buf, off + (8 if is64 else 4), new_strtab_vaddr)
            elif tag == _DT_STRSZ:
                struct.pack_into(W, buf, off + (8 if is64 else 4), new_strsz)
            elif tag == _DT_NULL and term is None:
                term = i
        if term is None:
            raise InjectError(".dynamic has no DT_NULL terminator")

        # repoint the .dynstr SECTION header (the SHT_STRTAB whose addr was the old strtab)
        # to the appended copy, so section-based tools resolve the same strings as bionic.
        if old_strtab_vaddr is not None:
            for i in range(e_shnum):
                s = e_shoff + i * e_shentsize
                if (struct.unpack_from("<I", buf, s + 4)[0] == _SHT_STRTAB
                        and struct.unpack_from(W, buf, s + SH_ADDR)[0] == old_strtab_vaddr):
                    struct.pack_into(W, buf, s + SH_ADDR, new_strtab_vaddr)
                    struct.pack_into(W, buf, s + SH_OFFSET, new_strtab_foff)
                    struct.pack_into(W, buf, s + SH_SIZE, new_strsz)
                    break

        # the slot after the terminator must read DT_NULL at runtime (in-place terminator).
        new_term_off = dyn_off + (term + 1) * DYN
        if new_term_off + DYN > len(buf):
            raise InjectError("no room after .dynamic for a new terminator")
        container = next(((o, fsz, msz) for (o, fsz, msz) in loads
                          if o <= dyn_off < o + fsz), None)
        if container is None:
            raise InjectError(".dynamic is not inside a PT_LOAD segment")
        c_off, c_filesz, c_memsz = container
        seg_term = new_term_off - c_off
        if seg_term + DYN <= c_filesz:
            if struct.unpack_from(DTAG, buf, new_term_off)[0] != _DT_NULL:
                raise InjectError(
                    "slot after .dynamic terminator is file-backed with a non-DT_NULL tag; "
                    "cannot add DT_NEEDED in place (target's .dynamic is full)")
        elif seg_term + DYN > ((c_memsz + 0xFFF) & ~0xFFF):
            raise InjectError("no mapped zero slot after .dynamic for a new terminator")

        struct.pack_into(DPACK, buf, dyn_off + term * DYN, _DT_NEEDED, name_off)

        new_filesz = (term + 2) * DYN
        if new_filesz > dyn_filesz:
            struct.pack_into(W, buf, ph_dyn + P_FILESZ, new_filesz)
            struct.pack_into(W, buf, ph_dyn + P_MEMSZ, new_filesz)
        for i in range(e_shnum):
            s = e_shoff + i * e_shentsize
            if struct.unpack_from("<I", buf, s + 4)[0] == _SHT_DYNAMIC:
                if new_filesz > struct.unpack_from(W, buf, s + SH_SIZE)[0]:
                    struct.pack_into(W, buf, s + SH_SIZE, new_filesz)
                break

        f.seek(0)
        f.write(buf)


def _add_dtinit_inplace(path: str, entry_rva: int) -> None:
    """Add a DT_INIT to a library that has no init hook, WITHOUT growing/moving
    .dynamic. We overwrite the existing DT_NULL terminator in place with DT_INIT and
    rely on the zero bytes that follow (.bss / padding, which read as DT_NULL at
    runtime) as the new terminator — then formally extend PT_DYNAMIC/.dynamic to
    include that new terminator so tools agree with the loader. Keeps .dynamic in its
    original (writable, mapped) segment, so no extra or mis-aligned segment is created.
    Class-aware raw ELF little-endian surgery (ELF32 for armeabi-v7a, ELF64 otherwise)."""
    with open(path, "r+b") as f:
        buf = bytearray(f.read())
        is64 = buf[4] == 2   # e_ident[EI_CLASS]: 1=ELF32, 2=ELF64
        W = "<Q" if is64 else "<I"          # native word (8 or 4 bytes)
        WS = 8 if is64 else 4
        DYN = 16 if is64 else 8             # sizeof(Elf_Dyn)
        # header field offsets
        E_PHOFF, E_SHOFF = (0x20, 0x28) if is64 else (0x1C, 0x20)
        E_PHENTSIZE, E_PHNUM = (0x36, 0x38) if is64 else (0x2A, 0x2C)
        E_SHENTSIZE, E_SHNUM = (0x3A, 0x3C) if is64 else (0x2E, 0x30)
        # Elf_Phdr field offsets: p_offset / p_filesz / p_memsz
        P_OFFSET = 8 if is64 else 4
        P_FILESZ = 32 if is64 else 16
        P_MEMSZ = 40 if is64 else 20
        SH_SIZE = 32 if is64 else 20        # Elf_Shdr.sh_size
        # Elf_Dyn: d_tag (signed word) at 0, d_val at WS
        DTAG = "<q" if is64 else "<i"
        DPACK = "<qQ" if is64 else "<iI"

        e_phoff = struct.unpack_from(W, buf, E_PHOFF)[0]
        e_phentsize = struct.unpack_from("<H", buf, E_PHENTSIZE)[0]
        e_phnum = struct.unpack_from("<H", buf, E_PHNUM)[0]
        e_shoff = struct.unpack_from(W, buf, E_SHOFF)[0]
        e_shentsize = struct.unpack_from("<H", buf, E_SHENTSIZE)[0]
        e_shnum = struct.unpack_from("<H", buf, E_SHNUM)[0]

        # locate PT_DYNAMIC and all PT_LOAD file ranges
        ph_dyn = None
        loads = []
        for i in range(e_phnum):
            p = e_phoff + i * e_phentsize
            ptype = struct.unpack_from("<I", buf, p)[0]
            if ptype == _PT_DYNAMIC:
                ph_dyn = p
            elif ptype == _PT_LOAD:
                p_off = struct.unpack_from(W, buf, p + P_OFFSET)[0]
                p_filesz = struct.unpack_from(W, buf, p + P_FILESZ)[0]
                p_memsz = struct.unpack_from(W, buf, p + P_MEMSZ)[0]
                loads.append((p_off, p_filesz, p_memsz))
        if ph_dyn is None:
            raise InjectError("no PT_DYNAMIC program header found")
        dyn_off = struct.unpack_from(W, buf, ph_dyn + P_OFFSET)[0]
        dyn_filesz = struct.unpack_from(W, buf, ph_dyn + P_FILESZ)[0]

        # find the DT_NULL terminator
        term = None
        for i in range(dyn_filesz // DYN):
            tag = struct.unpack_from(DTAG, buf, dyn_off + i * DYN)[0]
            if tag == _DT_NULL:
                term = i
                break
        if term is None:
            raise InjectError(".dynamic has no DT_NULL terminator")

        # The slot AFTER the (to-be-overwritten) terminator becomes the new terminator.
        # bionic (and glibc) iterate .dynamic until the first entry whose d_tag == DT_NULL
        # and IGNORE that entry's d_val — so the slot qualifies as a terminator when only
        # its d_tag WORD reads as zero at runtime; the d_val may be anything. We only READ
        # this slot (never overwrite it), so a non-zero d_val there is left intact.
        #
        # Runtime zero-ness of the d_tag word is decided by the containing PT_LOAD's
        # filesz/memsz, NOT by static section names:
        #   * within filesz  -> the file bytes are mapped -> the d_tag word must be zero
        #                       (e.g. .dynstr's leading NUL, or intra-segment zero padding);
        #   * beyond filesz  -> the loader zero-fills [filesz .. roundup(memsz,page)], so
        #                       the whole entry reads as DT_NULL regardless of file bytes
        #                       (e.g. .shstrtab, which has no SHF_ALLOC).
        # We use a 4 KB page for the bound (conservative: real pages >= 4 KB only enlarge
        # the zero-filled, mapped tail).
        new_term_off = dyn_off + (term + 1) * DYN
        if new_term_off + DYN > len(buf):
            raise InjectError("no room after .dynamic for a new terminator")
        container = next(((o, fsz, msz) for (o, fsz, msz) in loads
                          if o <= dyn_off < o + fsz), None)
        if container is None:
            raise InjectError(".dynamic is not inside a PT_LOAD segment")
        c_off, c_filesz, c_memsz = container
        seg_term = new_term_off - c_off
        if seg_term + DYN <= c_filesz:
            new_tag = struct.unpack_from(DTAG, buf, new_term_off)[0]
            if new_tag != _DT_NULL:
                raise InjectError("slot after .dynamic terminator is file-backed with a "
                                  "non-DT_NULL tag; cannot add DT_INIT in place")
        elif seg_term + DYN > ((c_memsz + 0xFFF) & ~0xFFF):
            raise InjectError("no mapped zero slot after .dynamic for a new terminator")
        # else: beyond filesz but within the zero-filled mapped tail -> DT_NULL at runtime

        # overwrite DT_NULL -> DT_INIT
        struct.pack_into(DPACK, buf, dyn_off + term * DYN, _DT_INIT, entry_rva)

        # formally extend PT_DYNAMIC to cover the new terminator
        new_filesz = (term + 2) * DYN
        if new_filesz > dyn_filesz:
            struct.pack_into(W, buf, ph_dyn + P_FILESZ, new_filesz)
            struct.pack_into(W, buf, ph_dyn + P_MEMSZ, new_filesz)
        # and the SHT_DYNAMIC section header, so readelf/LIEF agree with the loader
        for i in range(e_shnum):
            s = e_shoff + i * e_shentsize
            if struct.unpack_from("<I", buf, s + 4)[0] == _SHT_DYNAMIC:
                if new_filesz > struct.unpack_from(W, buf, s + SH_SIZE)[0]:
                    struct.pack_into(W, buf, s + SH_SIZE, new_filesz)
                break

        f.seek(0)
        f.write(buf)


def _self_verify(path, plain, info, cipher_id, key, nonce, text_rva, entry_rva,
                 seg_rva, decinfo_off, whiten_span, strategy):
    """Re-parse the output and assert every invariant the runtime stub depends on."""
    with open(path, "rb") as f:
        file_bytes = f.read()

    # (5a) whitening-span immutability: the WHITEN_SPAN bytes before decinfo IN THE OUTPUT
    # FILE must equal the pristine blob span the packer whitened with — because that is the
    # exact region the stub re-checksums at runtime. If LIEF (or any write) perturbed it,
    # the stub would derive a different key and fail open on-device; catch it here instead.
    file_span = file_bytes[decinfo_off - WHITEN_SPAN:decinfo_off]
    if file_span != whiten_span:
        raise InjectError("whitening span differs in output — a pack-time write hit the "
                          "checksummed region; the stub would derive the wrong key")

    # (5b) the whitened record round-trips: de-whitening the shipped 128 bytes with the
    # key derived from the OUTPUT-FILE span (what the stub will use) must reproduce exactly
    # what we packed. A mismatch means the Python↔C whitening contract or the write chain
    # is broken.
    stored = file_bytes[decinfo_off:decinfo_off + DECINFO_SIZE]
    if whiten(stored, file_span) != info.pack():
        raise InjectError("whitened decinfo does not de-whiten to the packed record")

    # (5c) the plaintext signpost is gone: the magic+version needle must not appear
    # ANYWHERE in the file (the old grep-SOPK-read-the-key attack now finds nothing).
    if _MAGIC_NEEDLE in file_bytes:
        raise InjectError("decinfo magic still present in output — whitening did not take")

    out = lief.parse(path)
    if out is None:
        raise InjectError("re-parse of output failed")

    # (2) .text vaddr must be unchanged so delta_text is still valid.
    text = _find_text(out)
    if int(text.virtual_address) != text_rva:
        raise InjectError(
            f".text vaddr shifted: was 0x{text_rva:x}, now 0x{int(text.virtual_address):x}")

    # (1) round-trip: decrypting the output .text must reproduce the original plaintext.
    enc = bytes(text.content)[:info.text_size]
    dec = apply_cipher(cipher_id, enc, key, nonce)
    if dec != plain:
        raise InjectError("round-trip decrypt mismatch (cipher/metadata/write chain)")

    # (3) 16 KB page congruence for EVERY LOAD segment (fails only on 16 KB devices).
    load_t = _seg_type_load()
    for s in out.segments:
        if s.type != load_t:
            continue
        if int(s.alignment) % SEGMENT_ALIGN != 0:
            raise InjectError(f"LOAD seg align {int(s.alignment)} not multiple of {SEGMENT_ALIGN}")
        if (int(s.virtual_address) - int(s.file_offset)) % SEGMENT_ALIGN != 0:
            raise InjectError("LOAD seg vaddr/offset not 16 KB-congruent")
    inj = next((s for s in out.segments
                if s.type == load_t and int(s.virtual_address) == seg_rva), None)
    if inj is None:
        raise InjectError("injected segment missing after write")
    fl = int(inj.flags)
    F = (lief.ELF.Segment.FLAGS if hasattr(lief.ELF.Segment, "FLAGS")
         else lief.ELF.SEGMENT_FLAGS)
    if not (fl & int(F.R)) or not (fl & int(F.X)) or (fl & int(F.W)):
        raise InjectError(f"injected segment flags not R+X (=0x{fl:x})")

    # (4) the hook actually points at the stub, and no text relocations were introduced.
    if out.get(_tag("TEXTREL")) is not None:
        raise InjectError("output has DT_TEXTREL (text relocations) — must be absent")
    # Loader-aware hook check. The ONLY strategies we emit are DT_INIT-inplace and
    # DT_INIT-hijack; both must leave DT_INIT pointing at the stub entry. DT_INIT is the
    # FIRST thing soinfo::call_constructors runs (before DT_INIT_ARRAY) and is not subject
    # to relocation, so this is exactly what the loader will call first — unlike a file-slot
    # INIT_ARRAY value, which a load-time R_*_RELATIVE relocation would overwrite.
    if not strategy.startswith("DT_INIT-"):
        raise InjectError(f"unexpected init strategy {strategy!r}")
    init = out.get(_tag("INIT"))
    if init is None or int(init.value) != entry_rva:
        raise InjectError("DT_INIT does not point at the stub entry")


_MAGIC_NEEDLE = MAGIC.to_bytes(4, "little") + VERSION.to_bytes(4, "little")


def _patch_decinfo(path: str, info: DecInfo, decinfo_off: int, span: bytes) -> None:
    """Overwrite the 128-byte record at its KNOWN blob offset with the finalized metadata,
    then WHITEN it in place. We no longer scan for a magic: the offset is computed from
    LIEF's segment file_offset + the blob's decinfo_off (the same value _self_verify
    trusts). We assert the placeholder magic is present at that offset first (proves we
    are writing the right spot), then write the whitened record — after which the magic no
    longer appears in the file (that is the whole point; see stub/decinfo.h)."""
    with open(path, "r+b") as f:
        f.seek(decinfo_off)
        placeholder = f.read(DECINFO_SIZE)
        if placeholder[:len(_MAGIC_NEEDLE)] != _MAGIC_NEEDLE:
            raise InjectError(
                f"placeholder decinfo not at expected offset 0x{decinfo_off:x} "
                "(LIEF file-offset bookkeeping changed?)")
        f.seek(decinfo_off)
        f.write(whiten(info.pack(), span))
