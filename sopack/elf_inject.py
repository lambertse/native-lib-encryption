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
the address of the decinfo record (which it references PC-relatively) - so no load
bias is needed. See stub/stub.c.

Requires LIEF >= 0.15. LIEF's enum names shifted across versions; _E() shims that.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import sys
from dataclasses import dataclass

import lief

from .cipher import CIPHER_IDS, CIPHER_WBAES, WHITEN_SPAN, apply_cipher, gen_key_nonce, whiten
from .metadata import (DecInfo, FLAG_CHAIN_INIT, FLAG_LOG, FLAG_NEED_ICACHE,
                       MAGIC, SIZE as DECINFO_SIZE, VERSION)
from .provision import PackKey, provision_pack, provision_text
from .rt_meta import (HELPER_BUILD_MARKER, PROVIDER_ABI, PROVIDER_BUILD_MARKER,
                      PROVIDER_ENTRY, PROVIDER_SONAME, REGION_MAGIC, REGION_VERSION,
                      WB_REGION_MAGIC, WRAPPED_KEY_BYTES, TargetRegion, WbRegion)
from .stubs import Stub, helper_skeleton_path, load_stub, provider_skeleton_path

# Bionic-provided libraries an injected helper may depend on WITHOUT bundling anything
# (present on every Android device). Anything else in the helper's DT_NEEDED means the
# static link leaked a dependency and would fail to load.
_BIONIC_ALLOWED = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so", "libandroid.so",
    "libEGL.so", "libGLESv2.so", "libGLESv3.so", "libvulkan.so", "libjnigraphics.so",
}

# 16 KB - mandatory max-page-size alignment for the injected LOAD segment so the lib
# still loads on 16 KB-page devices (Android 15+, Play requirement).
SEGMENT_ALIGN = 16384


def _warn(msg: str) -> None:
    """Warnings that must survive being ignored: stderr, not the `logger` the APK layer
    threads around, because these fire deep in the injection and describe a shippable
    artifact that is not shippable."""
    print(f"WARNING: {msg}", file=sys.stderr)

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
    # wbaes only: the per-target THIN helper .so that must be ADDED to the APK as a sibling.
    helper_path: str | None = None
    helper_soname: str | None = None
    # wbaes only, and only when inject_so was called WITHOUT a pack_key: the shared provider
    # emitted alongside. apk.py passes a pack_key and emits one provider per ABI itself, so it
    # gets None here - otherwise every target would emit a provider carrying a different blob.
    provider_path: str | None = None


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

        `DT_HASH`'s `nchain` IS the count. Otherwise use the `.dynsym` SECTION header size -
        safe despite this class's rule, because sopack never moves or rewrites `.dynsym`: count
        from the untouched section header, strings from the relocated `DT_STRTAB`.

        Deliberately NO `DT_GNU_HASH` fallback - it covers only defined exported symbols, so it
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
    """Resolve DT_NEEDED names the way the LOADER does - via DT_STRTAB read from .dynamic
    (not the .dynstr section, which we may have superseded with a copy)."""
    return _LoaderView(path).needed()


def _effective_strtab(path: str) -> bytes:
    """The DT_STRTAB bytes as written - the table `.dynsym`'s st_name offsets actually index.

    Read this AFTER LIEF's write, never from a pre-write `.dynstr` section: LIEF rebuilds the
    string table with the strings sorted and rewrites every st_name to match, so the pre-write
    bytes are a different table with the same contents in a different order."""
    v = _LoaderView(path)
    base, strsz = v.strtab_off(), v.tags.get(_DT_STRSZ)
    if base is None or strsz is None:
        raise InjectError(f"{os.path.basename(path)} has no usable DT_STRTAB/DT_STRSZ")
    return v.buf[base:base + strsz]


def _walk_dynsyms(path: str, undefined_only: bool = False,
                  defined_only: bool = False) -> list[str]:
    """Dynamic symbol names, resolved exactly as `dlsym` would: `DT_SYMTAB` indexed against
    `DT_STRTAB`, count from `_LoaderView.dynsym_count`, section headers ignored.

    `undefined_only` keeps just the `SHN_UNDEF` entries - what this `.so` needs the loader to
    resolve for it; `defined_only` keeps the complement, what it offers others. Returns [] for a
    `.so` with no dynamic symbols at all, but RAISES if it has a `DT_SYMTAB` whose length cannot
    be established: every caller is a guard, and a guard that silently inspects nothing is how
    the bug in §11f shipped."""
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
        if not st_name:                                      # index 0 is the reserved symbol
            continue
        if (undefined_only and shndx != 0) or (defined_only and shndx == 0):
            continue
        out.append(v.str_at(strtab, st_name))
    return out


def _dynsym_names(path: str) -> list[str]:
    """Every dynamic symbol name - pins the invariant that an injection must never change the
    target's exported symbol names (see `_self_verify_wbaes`)."""
    return _walk_dynsyms(path)


def _undefined_dynsyms(path: str) -> list[str]:
    """Symbols this `.so` imports - catches a helper skeleton linked against a 1.x
    `libwbcrypto.a`, which links cleanly and then cannot load."""
    return _walk_dynsyms(path, undefined_only=True)


def _exported_dynsyms(path: str) -> list[str]:
    """Symbols this `.so` defines for others to resolve. The helper is supposed to export
    nothing; anything here that names the white-box hands an analyst the SDK's API surface."""
    return _walk_dynsyms(path, defined_only=True)


# Sections the loader never maps, so the helper has no business shipping them. This is NOT the
# section-header stripping that docs/technical/HARDENING.md §Method 3 researched and
# rejected: that zeroed e_shoff/e_shnum, and bionic on Android 14+ refuses to load a library
# with no section headers. Here the table itself stays valid - only its non-ALLOC entries go,
# and `.shstrtab` has to stay because e_shstrndx must point at a real string table.
_KEEP_NONALLOC = frozenset({".shstrtab"})

# Host build paths leak a developer username and pin dependency versions for CVE matching.
_HOST_PATH_RE = re.compile(rb"/(?:Users|home|private/var)/[A-Za-z0-9._/+-]{4,160}")


_SHF_ALLOC = 0x2
_SHT_NOBITS = 8


def _strip_nonalloc(path: str) -> list[tuple[str, int]]:
    """Strip `path` in place: zero and drop every non-`SHF_ALLOC` section, then pull `.shstrtab`
    and the section header table down past the last mapped byte and truncate. Returns
    `(name, size)` for each section removed, largest first.

    On the arm64 skeleton the removed set is exactly `.symtab`, `.strtab`, `.comment` and the six
    `.debug_*` sections - 2.7 MB of a 3.2 MB file, and the only place the `sopk_rt_ctor`/`wbc_*`/
    VM-handler symbol names and the host build paths appear. A static-analysis report on a
    shipped APK named the unstripped helper as the single largest shortcut it had.

    Raw surgery rather than LIEF, for two reasons found by measurement:
      * LIEF re-creates `.symtab`/`.strtab` from its own symbol model on `write()`, so removing
        those two sections through LIEF does not remove them from the output.
      * LIEF keeps the sections it retains at their original file offsets, so deleting 2.7 MB out
        of the middle of the file leaves a 2.7 MB hole of padding instead of a smaller file. The
        content is gone, but a STORED APK entry still carries every zero.
    Nothing mapped moves here: only non-ALLOC content is touched, plus `.shstrtab` and the
    section header table, neither of which is covered by a `PT_LOAD`. That also means this is
    NOT the section-header stripping bionic rejects (see `_KEEP_NONALLOC`) - the table stays,
    it just gets shorter and moves down."""
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    if buf[:4] != b"\x7fELF":
        raise InjectError(f"{os.path.basename(path)} is not an ELF file")
    is64, little = buf[4] == 2, buf[5] == 1
    if not little:
        raise InjectError("big-endian ELF is not supported (no Android ABI uses it)")

    # Header, section-header and program-header field offsets for the two ELF classes.
    if is64:
        (e_shoff,) = struct.unpack_from("<Q", buf, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
        (e_phoff,) = struct.unpack_from("<Q", buf, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 0x36)
        SH_OFF, SH_SIZE, SZ = 0x18, 0x20, "<Q"
        PH_OFF, PH_FILESZ = 0x08, 0x20
    else:
        (e_shoff,) = struct.unpack_from("<I", buf, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x2E)
        (e_phoff,) = struct.unpack_from("<I", buf, 0x1C)
        e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 0x2A)
        SH_OFF, SH_SIZE, SZ = 0x10, 0x14, "<I"
        PH_OFF, PH_FILESZ = 0x04, 0x10
    if e_shoff == 0 or e_shnum == 0:
        raise InjectError(
            f"{os.path.basename(path)} has no section header table - bionic (Android 14+) "
            "refuses to load such a library, so it cannot have come from this tool")

    def shdr(i: int) -> int:
        return e_shoff + i * e_shentsize

    def fld(i: int, off: int, fmt: str = "<I") -> int:
        return struct.unpack_from(fmt, buf, shdr(i) + off)[0]

    # Read the existing section table.
    strtab_off = fld(e_shstrndx, SH_OFF, SZ)

    def name_of(i: int) -> str:
        start = strtab_off + fld(i, 0x00)
        end = buf.index(b"\x00", start)
        return buf[start:end].decode("utf-8", "replace")

    names = [name_of(i) for i in range(e_shnum)]
    flags = [fld(i, 0x08, SZ) for i in range(e_shnum)]
    types = [fld(i, 0x04) for i in range(e_shnum)]
    offs = [fld(i, SH_OFF, SZ) for i in range(e_shnum)]
    sizes = [fld(i, SH_SIZE, SZ) for i in range(e_shnum)]

    # Index 0 is the reserved null entry and must survive. Keep anything the loader maps, plus
    # the section-name table itself (e_shstrndx has to point at a real one).
    def keep(i: int) -> bool:
        return i == 0 or bool(flags[i] & _SHF_ALLOC) or i == e_shstrndx

    kept = [i for i in range(e_shnum) if keep(i)]
    dropped = [i for i in range(e_shnum) if not keep(i)]
    if not dropped:
        return []

    # Highest byte the loader or a kept section still needs. `.shstrtab` is excluded because it
    # is what we are about to move; NOBITS occupies no file space.
    keep_end = 0
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        p_off = struct.unpack_from(SZ, buf, p + PH_OFF)[0]
        p_filesz = struct.unpack_from(SZ, buf, p + PH_FILESZ)[0]
        keep_end = max(keep_end, p_off + p_filesz)
    for i in kept:
        if i == e_shstrndx or types[i] == _SHT_NOBITS:
            continue
        keep_end = max(keep_end, offs[i] + sizes[i])

    # Erase dropped content wherever it lies - a dropped section below keep_end cannot be
    # truncated away, so zero it rather than leave readable DWARF in the shipped file.
    for i in dropped:
        if types[i] == _SHT_NOBITS:
            continue
        lo, hi = offs[i], min(offs[i] + sizes[i], len(buf))
        if lo < hi:
            buf[lo:hi] = b"\x00" * (hi - lo)

    # Rebuild .shstrtab with only the surviving names, so ".debug_info"/".symtab" do not linger
    # as strings advertising what was removed.
    new_names = bytearray(b"\x00")
    name_at: dict[str, int] = {"": 0}
    for i in kept:
        if names[i] and names[i] not in name_at:
            name_at[names[i]] = len(new_names)
            new_names += names[i].encode() + b"\x00"

    old_to_new = {old: new for new, old in enumerate(kept)}
    shstrtab_off = (keep_end + 15) & ~15
    new_shoff = (shstrtab_off + len(new_names) + 15) & ~15

    table = bytearray()
    for i in kept:
        ent = bytearray(buf[shdr(i):shdr(i) + e_shentsize])
        struct.pack_into("<I", ent, 0x00, name_at.get(names[i], 0))
        if i == e_shstrndx:
            struct.pack_into(SZ, ent, SH_OFF, shstrtab_off)
            struct.pack_into(SZ, ent, SH_SIZE, len(new_names))
        # sh_link/sh_info are section indices (e.g. .dynsym -> .dynstr, .rela.* -> .dynsym) and
        # every index shifts when entries are removed. A stale sh_link is how a "stripped" lib
        # ends up with tooling reading the wrong table.
        link_off, info_off = (0x28, 0x2C) if is64 else (0x18, 0x1C)
        for off in (link_off, info_off):
            (val,) = struct.unpack_from("<I", ent, off)
            if val:
                struct.pack_into("<I", ent, off, old_to_new.get(val, 0))
        table += ent

    out = buf[:keep_end]
    out += b"\x00" * (shstrtab_off - len(out))
    out += new_names
    out += b"\x00" * (new_shoff - len(out))
    out += table

    struct.pack_into(SZ, out, 0x28 if is64 else 0x20, new_shoff)
    struct.pack_into("<HH", out, 0x3C if is64 else 0x30,
                     len(kept), old_to_new[e_shstrndx])

    with open(path, "wb") as f:
        f.write(out)
    return sorted(((names[i], sizes[i]) for i in dropped), key=lambda t: -t[1])


def _host_paths_in(data: bytes) -> list[str]:
    """Host build paths left in `data`, including this host's own $HOME."""
    hits = {m.group().decode("utf-8", "replace") for m in _HOST_PATH_RE.finditer(data)}
    home = os.path.expanduser("~").encode()
    if len(home) > 4 and home in data:
        hits.add(home.decode("utf-8", "replace"))
    return sorted(hits)


def _helper_soname_for(target_soname: str) -> str:
    """Per-target helper soname. Keep it deterministic and collision-free."""
    base = target_soname[:-3] if target_soname.endswith(".so") else target_soname
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in base)
    return f"libsopk_rt_{safe}.so"


# The two hand-built wbaes artifacts. Guards differ per kind, so every check below says which
# one it applies to rather than assuming there is only a helper.
_KIND_THIN = "thin helper"
_KIND_PROVIDER = "white-box provider"


def _check_wbaes_skeleton(skeleton: str, kind: str, allow_helper_log: bool) -> None:
    """Every guard that can be applied to a hand-built skeleton BEFORE it is copied.

    These exist because both skeletons are built OUTSIDE this repo, so the host is the only place
    a bad one can be caught. `scripts/build_wbaes.sh --release` and Phase 4's checks already
    describe a correct build; they did not prevent a tracing, unstripped helper reaching a shipped
    APK, because nothing refused one."""
    name = os.path.basename(skeleton)
    is_thin = kind == _KIND_THIN
    marker = HELPER_BUILD_MARKER if is_thin else PROVIDER_BUILD_MARKER
    source = "stub/sopk_rt.c" if is_thin else "stub/sopk_wb.c"
    phase = "Phase 4 step 4b" if is_thin else "Phase 4 step 4a"

    # Build-marker guard. A stale skeleton is SILENT: its ctor requires an exact region version
    # match and finds none. Catch it here instead. Safe across the strip below: the marker lives
    # in .rodata (SHF_ALLOC), so it survives into the emitted artifact.
    #
    # The two kinds carry DIFFERENT markers on purpose. With one shared value, "freshly built
    # thin helper + stale provider" would pass both guards - and that mismatched pair is the real
    # failure mode now that two artifacts must be rebuilt together. So name the file to rebuild.
    with open(skeleton, "rb") as f:
        if marker not in f.read():
            raise InjectError(
                f"{kind} skeleton {name} lacks the v{REGION_VERSION} build marker "
                f"({marker.hex()}) - it was built from an older {source}, so its region layout "
                f"or flow no longer matches this packer. Rebuild THIS artifact from the current "
                f"{source} against whitebox-cryptography >= 3.0.0 (docs/technical/WBAES.md "
                f"{phase}, or run ./scripts/build_wbaes.sh --release, which builds both).")

    binary = lief.parse(skeleton)
    if binary is None:
        raise InjectError(f"LIEF failed to parse {kind} skeleton {skeleton}")

    # Dependency-closure guard. `_BIONIC_ALLOWED` means "provided by every Android device" and
    # must keep meaning exactly that, so the provider soname is added as ONE literal extra name
    # for the thin kind only - never a pattern or prefix. Everything this guard was built to
    # catch (a leaked libc++_shared.so from a non-static white-box, a dynamic libwbcrypto) is
    # still caught.
    allowed = _BIONIC_ALLOWED | ({PROVIDER_SONAME} if is_thin else set())
    needed = _needed_names(binary)
    stray = [n for n in needed if n not in allowed]
    if stray:
        extra = (f" (besides bionic, a {kind} may depend only on {PROVIDER_SONAME})" if is_thin
                 else f" (a {kind} may depend only on bionic libs)")
        raise InjectError(
            f"{kind} skeleton {name} has unexpected DT_NEEDED {stray}{extra} - the white-box "
            "was not statically linked in (libwbcrypto/libc++/libsodium must be static). "
            "Rebuild the skeleton.")
    # POSITIVE containment, and this is new: a thin helper that lost its provider dependency
    # would otherwise fail on device as "cannot locate symbol sopk_wb_k", taking the target's
    # dlopen down with it, nowhere near the cause.
    if is_thin and PROVIDER_SONAME not in needed:
        raise InjectError(
            f"{kind} skeleton {name} does not depend on {PROVIDER_SONAME} - since the v3 split "
            f"it must call into the shared provider for its session key. It was probably linked "
            f"without the provider .so as an input; see docs/technical/WBAES.md {phase}.")
    if not is_thin and any(n.startswith("libsopk_rt") for n in needed):
        raise InjectError(
            f"{kind} skeleton {name} depends on a thin helper {needed} - the dependency runs the "
            "other way, and a cycle would deadlock bionic's loader.")

    # A `-shared` link permits unresolved symbols, so a skeleton built against a pre-3.0.0
    # libwbcrypto.a (no wbc_blob_kdf_tier) links CLEANLY and leaves it as a UND import. bionic
    # then fails to load it, which makes dlopen of the TARGET fail, which surfaces as a crash in
    # whatever was loading the target - nowhere near the cause.
    undefined = _undefined_dynsyms(skeleton)
    wb_unresolved = sorted({n for n in undefined if n.startswith(("wbc_", "sodium_"))})
    if wb_unresolved:
        if is_thin:
            # Since v3 the thin helper links no white-box at all, so ANY reference is wrong.
            raise InjectError(
                f"{kind} skeleton {name} references white-box symbols {wb_unresolved} - since "
                f"the v3 split it must not touch the white-box; only {PROVIDER_SONAME} does. It "
                f"was probably built from stub/sopk_wb.c, or linked libwbcrypto.a by mistake.")
        raise InjectError(
            f"{kind} skeleton {name} imports {wb_unresolved} instead of defining them - it was "
            "linked against a pre-3.0.0 libwbcrypto.a (or none). Note wbc_blob_kdf_tier in "
            "particular is the 3.0.0-only symbol. It would fail to load, taking every thin "
            "helper and their targets with it. Rebuild vendor/wbc/ from whitebox-cryptography "
            ">= 3.0.0 (scripts/build_android.sh) and link with -Wl,--no-undefined so this fails "
            "at build time instead.")
    # The thin helper must import the provider entry point - the other half of the pairing check.
    if is_thin and PROVIDER_ENTRY not in undefined:
        raise InjectError(
            f"{kind} skeleton {name} does not import {PROVIDER_ENTRY} - it cannot obtain a "
            f"session key, so its ctor would abort on every load. Rebuild it from {source}.")

    # Tracing guard. A -DSOPK_RT_LOG build announces the target soname, .text RVA and size, and a
    # final "OK" to logcat - which hands anyone with adb the exact address and length to dump,
    # plus confirmation the dump is valid. Refuse by default.
    logging_built = ("liblog.so" in needed or "__android_log_print" in undefined)
    if logging_built and not allow_helper_log:
        raise InjectError(
            f"{kind} skeleton {name} was built with -DSOPK_RT_LOG (imports __android_log_print "
            "/ needs liblog.so). Shipped, it logs the target soname, .text RVA and size, and a "
            "final \"OK\" to logcat - an attacker with adb gets the exact address and length to "
            "dump.\n"
            "  To fix:  ./scripts/build_wbaes.sh --release\n"
            "  To keep: set `logging.allow-helper-log: true` (on-device verification only; "
            "the result is NOT shippable)")
    if logging_built:
        # Every pack, not once per run: the whole reason this flag needs a loud footprint is that
        # "remember to drop -DSOPK_RT_LOG" is exactly the convention that already failed. Name
        # the artifact, since either of the two can be the tracing one.
        _warn(f"{name} is a TRACING build (logging.allow-helper-log): it logs the target name, .text "
              "address and size to logcat. DO NOT SHIP THIS APK.")

    # Export hygiene. Re-exported white-box symbols publish the SDK's whole API surface, and
    # Phase 4 checks for them only in a script the user can skip.
    exported = _exported_dynsyms(skeleton)
    leaked = sorted({n for n in exported
                     if n.startswith(("wbc_", "sodium_")) or "wbaes" in n
                     or n.startswith("_ZN2vm")})
    if leaked:
        raise InjectError(
            f"{kind} skeleton {name} re-exports white-box symbols {leaked[:8]}"
            f"{' …' if len(leaked) > 8 else ''} - WBC_API visibility is baked into "
            "libwbcrypto.a's objects, so -fvisibility=hidden cannot hide them. Relink with "
            "-Wl,--exclude-libs,ALL (or a version script).")
    if is_thin:
        if exported:
            _warn(f"{name} exports {len(exported)} symbol(s) (expected none): "
                  f"{exported[:5]}. Relink with -Wl,--exclude-libs,ALL.")
    else:
        # The provider is the first sopack artifact that legitimately EXPORTS something, so the
        # expectation inverts: exactly one name, no more and no fewer. Zero means
        # --exclude-libs,ALL or a `{ local: *; };` version script swallowed the entry, which the
        # thin link would then fail on - loudly, but far from here.
        if PROVIDER_ENTRY not in exported:
            raise InjectError(
                f"{kind} skeleton {name} does not export {PROVIDER_ENTRY} (exports "
                f"{exported[:5] or 'nothing'}) - a `{{ local: *; }};` version script or "
                f"-fvisibility=hidden without an explicit "
                f"__attribute__((visibility(\"default\"))) swallowed it. No thin helper could "
                f"then link or load against this provider.")
        extra_exports = [n for n in exported if n != PROVIDER_ENTRY]
        if extra_exports:
            _warn(f"{name} exports {len(extra_exports)} symbol(s) beyond {PROVIDER_ENTRY}: "
                  f"{extra_exports[:5]}. Only the one entry point should be visible.")


def _emit_wbaes_artifact(skeleton: str, region_bytes: bytes, out_path: str,
                         new_soname: str | None, kind: str) -> None:
    """Strip a checked skeleton, optionally rename its DT_SONAME, and append `region_bytes` as a
    fresh read-only 16 KB-aligned PT_LOAD whose first bytes are the region - which the artifact's
    own code finds by magic (stub/sopk_rt.c, stub/sopk_wb.c).

    `new_soname=None` means DO NOT RENAME, which is mandatory for the provider: every thin
    helper's DT_NEEDED string is the provider's DT_SONAME as recorded at link time, so renaming
    it here would silently break all of them."""
    name = os.path.basename(skeleton)

    # Snapshot before any write. LIEF rebuilds .dynstr with the strings SORTED on write(),
    # rewriting every st_name to match; on the target that desync shipped once and cost a Flutter
    # app its Dart snapshot pointers (§11f). Here it would silently break the undefined/exported
    # symbol guards above - and, for the provider, the exported name a thin helper resolves by
    # string.
    dynsyms_before = _dynsym_names(skeleton)

    # Strip FIRST, on a copy, and only then let LIEF append the region. The order matters twice:
    #   * LIEF re-creates `.symtab`/`.strtab` from its own symbol model on write(), so stripping
    #     after a LIEF write does not remove them. Stripping first leaves LIEF nothing to
    #     regenerate from.
    #   * `_strip_nonalloc` truncates at the last byte any PT_LOAD still needs. LIEF picks the
    #     appended region segment's file offset itself, and if it landed above the debug sections
    #     that truncation point would jump past them - content still erased, but the file would
    #     stay multi-megabyte. Stripping before the segment exists removes the dependency on
    #     where LIEF chooses to put it.
    shutil.copyfile(skeleton, out_path)
    removed = _strip_nonalloc(out_path)
    if removed:
        total = sum(sz for _, sz in removed)
        shown = ", ".join(n for n, _ in removed[:6])
        _warn(f"{kind} skeleton {name} shipped {len(removed)} non-ALLOC sections "
              f"({shown}{' …' if len(removed) > 6 else ''}; {total:,} bytes) - stripped them. "
              "Build with ./scripts/build_wbaes.sh --release, which passes -g0 and "
              "llvm-strip --strip-all, so the packer does not have to.")

    binary = lief.parse(out_path)
    if binary is None:
        raise InjectError(
            f"LIEF cannot parse {name} after stripping it - the section surgery produced a "
            "malformed ELF, which is a bug in _strip_nonalloc, not in the skeleton")

    if new_soname is not None:
        _set_soname(binary, new_soname)

    seg = lief.ELF.Segment()
    seg.type = _seg_type_load()
    seg.flags = _seg_flags_r()          # read-only: not W, not X (region is data)
    seg.alignment = SEGMENT_ALIGN
    seg.content = list(region_bytes)
    binary.add(seg)
    binary.write(out_path)

    dynsyms_after = _dynsym_names(out_path)
    if dynsyms_before != dynsyms_after:
        bad = next(((x, y) for x, y in zip(dynsyms_before, dynsyms_after) if x != y), None)
        detail = f"e.g. {bad[0]!r} -> {bad[1]!r}" if bad else \
                 f"count {len(dynsyms_before)} -> {len(dynsyms_after)}"
        raise InjectError(
            f"emitting {kind} {os.path.basename(out_path)} changed its dynamic symbol names "
            f"({detail}) - DT_STRTAB and the .dynsym offsets are out of sync, so the "
            "undefined/exported symbol guards no longer inspect what they claim to, and bionic "
            "may fail to resolve between the helper and the provider")

    # Residual host paths. After the strip there should be none; anything left is in a mapped
    # section, which no amount of post-processing here can fix - it needs the archive rebuilt
    # with -ffile-prefix-map. Warn rather than refuse, since that is another repo.
    with open(out_path, "rb") as f:
        residual = _host_paths_in(f.read())
    if residual:
        _warn(f"{os.path.basename(out_path)} still contains host build paths in mapped "
              f"sections: {residual[:3]}. These leak a developer username and pin dependency "
              "versions. Rebuild libwbcrypto.a with -ffile-prefix-map=<src>=. in the "
              "whitebox-cryptography repo.")


def _emit_helper(abi: str, helper_soname: str, region_bytes: bytes,
                 out_path: str, allow_helper_log: bool = False) -> None:
    """Emit one THIN per-target helper: guards, strip, rename to `helper_soname`, append its
    target region. Renaming is correct here (one per target) and forbidden for the provider."""
    skeleton = str(helper_skeleton_path(abi))
    _check_wbaes_skeleton(skeleton, _KIND_THIN, allow_helper_log)
    _emit_wbaes_artifact(skeleton, region_bytes, out_path, helper_soname, _KIND_THIN)


def emit_provider(abi: str, pack: PackKey, out_path: str,
                  allow_helper_log: bool = False) -> None:
    """Emit the ONE shared white-box provider for `abi`, carrying the pack's sealed blob and
    whitened passphrase. Called once per ABI by apk.py, after the per-entry loop.

    Deliberately does NOT rename the artifact: each thin helper's DT_NEEDED string is whatever
    the linker recorded as this skeleton's DT_SONAME, so it is asserted rather than set."""
    skeleton = str(provider_skeleton_path(abi))
    _check_wbaes_skeleton(skeleton, _KIND_PROVIDER, allow_helper_log)

    soname = _dynamic_soname(lief.parse(skeleton))
    if soname != PROVIDER_SONAME:
        raise InjectError(
            f"{_KIND_PROVIDER} skeleton {os.path.basename(skeleton)} has DT_SONAME "
            f"{soname!r}, expected {PROVIDER_SONAME!r}. Every thin helper records the provider's "
            f"DT_SONAME as its DT_NEEDED at LINK time, so this cannot be corrected here - "
            f"relink with -Wl,-soname,{PROVIDER_SONAME}. Without an explicit -soname, lld "
            f"records the file PATH it was handed and the APK will not load.")

    region = WbRegion(wpass=pack.wpass, blob=pack.blob).pack()
    _emit_wbaes_artifact(skeleton, region, out_path, None, _KIND_PROVIDER)
    _self_verify_provider(out_path, abi, pack)


def _inject_wbaes(in_path: str, out_path: str, abi: str,
                  wb_keygen: str | None, target_name: str | None,
                  allow_helper_log: bool = False,
                  pack_key: PackKey | None = None) -> InjectResult:
    """`cipher: wbaes`: encrypt `.text` with ChaCha20 under a session key that is wrapped
    by a sealed white-box AES-128 key, and inject a per-target DT_NEEDED helper that unwraps
    and decrypts at load. No stub/decinfo/DT_INIT surgery - the helper's constructor runs
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
    # One long-term key per (pack, ABI), supplied by apk.py which knows the whole target set.
    # Standalone callers get one sealed here, plus a matching provider emitted at step 6.
    own_pack_key = pack_key is None
    if own_pack_key:
        pack_key = provision_pack(wb_keygen=wb_keygen)
    prov = provision_text(plain, pack_key)
    text.content = list(prov.ciphertext)

    # 2. inject the per-target helper as a DT_NEEDED. We do NOT use LIEF add_library: it
    #    grows .dynamic + .dynstr and on tight libs (e.g. libapp.so) LIEF spills them into
    #    4 KB-aligned segments that break 16 KB loading (Risk 2). Instead we mirror the stub
    #    path: append a 16 KB-aligned COPY of .dynstr (+ our soname) with the trusted
    #    add(seg), then raw-repoint DT_STRTAB/DT_STRSZ and add DT_NEEDED in place - keeping
    #    .dynamic and PT_DYNAMIC where they are.
    #
    #    The copied table MUST come from _effective_strtab (post-write), not from the section
    #    read here - see that function's docstring. Hence: reserve a placeholder segment, let
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

    # 4. build + emit the THIN helper carrying this target's region. Since v3 the region holds
    #    no blob and no passphrase - those live once, in the shared provider - so this artifact
    #    is a few KB rather than ~920 KB.
    region = TargetRegion(
        text_rva=text_rva, text_size=text_size,
        wrapped=prov.wrapped, nonce16=prov.nonce16,
        soname=target_soname.encode("utf-8"),
    ).pack()
    helper_path = out_path + ".helper.so"
    _emit_helper(abi, helper_soname, region, helper_path,
                 allow_helper_log=allow_helper_log)

    # 5. self-verify both artifacts.
    _self_verify_wbaes(out_path, helper_path, prov.ciphertext, text_rva, text_size,
                       target_soname, helper_soname, abi, in_path, pack_key)

    # 6. A standalone caller (tests, direct inject_so use) gets a provider emitted beside the
    #    helper, since nobody else will. apk.py supplies pack_key and emits one per ABI itself.
    provider_path = None
    if own_pack_key:
        provider_path = out_path + ".provider.so"
        emit_provider(abi, pack_key, provider_path, allow_helper_log=allow_helper_log)

    return InjectResult(abi=abi, text_rva=text_rva, text_size=text_size,
                        seg_rva=0, entry_rva=0, strategy="DT_NEEDED-wbaes",
                        cipher="wbaes", helper_path=helper_path,
                        helper_soname=helper_soname, provider_path=provider_path)


def _self_verify_wbaes(target_path, helper_path, ciphertext, text_rva, text_size,
                       target_soname, helper_soname, abi, in_path, pack_key=None):
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
    # (b) DT_NEEDED points at the helper - resolved via DT_STRTAB, as the loader does.
    if helper_soname not in _needed_via_strtab(target_path):
        raise InjectError(f"DT_NEEDED {helper_soname!r} missing from target")
    # (b2) EVERY existing exported symbol name still resolves to the same string. A mismatch
    # means dlsym() returns the wrong name or NULL - an APK that loads and then crashes far
    # from the cause. Cheap check; see docs/technical/ARCHITECTURE.md §11f for the incident.
    before, after = _dynsym_names(in_path), _dynsym_names(target_path)
    if before != after:
        bad = next(((x, y) for x, y in zip(before, after) if x != y), None)
        detail = f"e.g. {bad[0]!r} -> {bad[1]!r}" if bad else \
                 f"count {len(before)} -> {len(after)}"
        raise InjectError(
            f"injection changed the target's dynamic symbol names ({detail}) - DT_STRTAB and "
            "the .dynsym offsets are out of sync, so dlsym() would fail on device")
    # (c) 16 KB congruence for arm64 (the only 16 KB-page device class) + no text relocs.
    _assert_16k_and_no_textrel(tgt, abi, orig_path=in_path,
                               what=f"the packed target {target_soname}")

    hlp = lief.parse(helper_path)
    if hlp is None:
        raise InjectError("re-parse of wbaes helper failed")
    if _dynamic_soname(hlp) != helper_soname:
        raise InjectError("helper DT_SONAME not renamed")
    # Bionic libs plus exactly one more: the shared provider. Not a loosening - the name is a
    # single literal, so a leaked libc++_shared.so is still caught.
    stray = [n for n in _needed_names(hlp)
             if n not in _BIONIC_ALLOWED and n != PROVIDER_SONAME]
    if stray:
        raise InjectError(f"emitted helper has unexpected DT_NEEDED {stray}")
    _assert_16k_and_no_textrel(hlp, abi, what=f"the emitted thin helper {helper_soname}")
    # The strip actually happened. A silently-skipped strip ships 2.7 MB of DWARF and the full
    # symbol table, which is the single largest analysis shortcut in the whole design.
    leftover = sorted(s.name for s in hlp.sections
                      if s.name and s.name not in _KEEP_NONALLOC
                      and not s.has(lief.ELF.Section.FLAGS.ALLOC))
    if leftover:
        raise InjectError(
            f"emitted helper still has non-ALLOC sections {leftover} - the strip did not take "
            "effect, so the helper would ship its symbol table and debug info")
    # Absence of the sections is not the same as absence of their bytes. Stripping erases and
    # truncates, so once only `.shstrtab` is left the file should be little more than its mapped
    # segments plus the section table; anything much larger means a multi-MB hole of padding
    # survived, which a STORED APK entry still carries in full. Checked rather than observed,
    # because the "~470 KB not 3.2 MB" claim in the docs otherwise rests on a layout accident.
    mapped_end = max((int(s.file_offset) + int(s.physical_size)) for s in hlp.segments)
    shstr = hlp.get_section(".shstrtab")
    tail = int(shstr.size) + hlp.header.numberof_sections * hlp.header.section_header_size
    budget = mapped_end + tail + SEGMENT_ALIGN     # one page of alignment slack
    actual = os.path.getsize(helper_path)
    if actual > budget:
        raise InjectError(
            f"emitted helper is {actual:,} bytes but its mapped content plus section table needs "
            f"only {budget:,} - {actual - budget:,} bytes of stripped-out padding were left "
            "behind, so the APK carries them. _strip_nonalloc did not compact the file")
    # ...and it did NOT turn into the section-header stripping that bionic (Android 14+)
    # refuses to load: e_shnum must stay non-zero and e_shstrndx must point at a real
    # .shstrtab. See docs/technical/HARDENING.md §Method 3.
    if hlp.header.numberof_sections == 0 or hlp.get_section(".shstrtab") is None:
        raise InjectError(
            "emitted helper lost its section header table (e_shnum=0 or no .shstrtab) - "
            "bionic on Android 14+ rejects that outright ('has no section headers')")
    for need in (".dynsym", ".dynstr"):
        if hlp.get_section(need) is None:
            raise InjectError(f"emitted helper lost {need}, so it cannot be linked against")
    # Deliberately NOT asserted here: that the build marker survived into the emitted helper.
    # Nothing reads it there - the stale-skeleton guard always reads sopack/stubs/, never a
    # previously emitted helper - so the assertion would only be able to fail spuriously (a
    # test fixture carrying the marker as trailing bytes rather than in .rodata).
    # (d) the region round-trips and describes THIS target.
    region = _extract_region(helper_path)
    r = TargetRegion.unpack(region)
    if (r.text_rva, r.text_size) != (text_rva, text_size):
        raise InjectError("helper region text_rva/size mismatch")
    if r.soname.decode("utf-8", "replace") != target_soname:
        raise InjectError("helper region soname mismatch")
    # (d2) the thin helper must still be wired to the shared provider AFTER the emit. Read both
    # the way bionic does: LIEF re-sorts .dynstr on write(), and if that desynced the st_name
    # offsets these names would resolve mid-string on device - the failure that shipped once.
    # A missing dependency here is a 100% load failure that surfaces inside whatever dlopen'd
    # the target, so it must never leave the host.
    if PROVIDER_SONAME not in _needed_names(hlp):
        raise InjectError(
            f"emitted helper {helper_soname} does not depend on {PROVIDER_SONAME} - it cannot "
            "obtain a session key, and bionic would fail the target's dlopen")
    if PROVIDER_ENTRY not in _undefined_dynsyms(helper_path):
        raise InjectError(
            f"emitted helper {helper_soname} no longer imports {PROVIDER_ENTRY} - the emit "
            "desynced its .dynsym/.dynstr, so the symbol it resolves at load is not the one the "
            "provider exports")
    # (d3) the blob must NOT be here. It lives once, in the provider; a target region carrying it
    # would mean a v2-shaped region slipped through and every helper is ~920 KB again.
    if len(region) > 4096:
        raise InjectError(
            f"emitted helper {helper_soname} region is {len(region):,} bytes - a target region "
            "is a 96-byte header plus a soname. This looks like a pre-v3 region still carrying "
            "the sealed blob.")
    # (d4) neither the long-term key nor anything derived from it may reach a thin helper.
    if pack_key is not None:
        with open(helper_path, "rb") as f:
            helper_bytes = f.read()
        for secret, what in ((pack_key.kek, "the long-term key"), (pack_key.blob, "the blob")):
            if secret in helper_bytes:
                raise InjectError(
                    f"emitted helper {helper_soname} contains {what} - thin helpers must carry "
                    "neither; only the shared provider does")

    # The helper reads these as fixed-size fields, so a wrong length here is a wrong-length
    # unwrap on device (i.e. a silent garbage session key), not a parse error.
    if len(r.wrapped) != WRAPPED_KEY_BYTES:
        raise InjectError(
            f"helper region wrapped key is {len(r.wrapped)} bytes, expected {WRAPPED_KEY_BYTES}")
    if len(r.nonce16) != 16 or r.nonce16 == b"\x00" * 16:
        raise InjectError("helper region ChaCha20 nonce missing or all-zero")


def _16k_violations(binary) -> list[str]:
    """LOAD segments that would stop this `.so` loading on a 16 KB-page device.

    Each entry names the offending segment by phdr INDEX and prints its whole placement, not
    just the failing field: the cause is almost always a LIEF version that placed or invented a
    segment we did not ask for, and "align 4096" alone does not say which one of six LOADs that
    was. See docs/TROUBLESHOOTING.md §16 KB."""
    load_t = _seg_type_load()
    bad = []
    for i, s in enumerate(binary.segments):
        if s.type != load_t:
            continue
        where = (f"LOAD[phdr {i}] off=0x{int(s.file_offset):x} "
                 f"vaddr=0x{int(s.virtual_address):x} align=0x{int(s.alignment):x}")
        if int(s.alignment) % SEGMENT_ALIGN != 0:
            bad.append(f"{where}: align {int(s.alignment)} is not a multiple of {SEGMENT_ALIGN}")
        elif (int(s.virtual_address) - int(s.file_offset)) % SEGMENT_ALIGN != 0:
            bad.append(f"{where}: vaddr not congruent with offset mod {SEGMENT_ALIGN}")
    return bad


def _assert_16k_and_no_textrel(binary, abi, orig_path: str | None = None,
                               what: str = "the output"):
    """16 KB page hardware is arm64-only, so this gates arm64-v8a output only - armeabi-v7a and
    x86_64 inputs commonly ship 4 KB LOADs and must not be rejected over a device class that
    cannot run them.

    `orig_path` lets the failure distinguish the two very different causes. If the INPUT already
    violates the rule, that is a property of the library we were handed: no amount of packer
    correctness can fix it, and saying "LOAD seg align 4096" without that context sends the
    reader looking for a bug in the injection.

    `what` names the artifact. Three different artifacts reach this check - the packed target,
    the thin helper, the shared provider - and only the target has an `orig_path`, so without a
    label the other two used to report "the input was clean, so this one is ours" about a file
    that has no input at all. That wording is what pinned an entire troubleshooting entry to the
    target-side story and left a real failure log un-attributable."""
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
            checked = (f"Its input {os.path.basename(orig_path)} is clean, so this one is ours."
                       if orig_path else
                       "It is emitted from a skeleton, so there is no input to blame - "
                       "this one is ours.")
            raise InjectError(
                f"{what} has a LOAD segment that breaks 16 KB loading. {checked}\n  "
                + "\n  ".join(bad) +
                f"\nLIEF {lief.__version__} placed those segments. This is a known "
                "LIEF-version-dependent failure: sopack appends its segments with a 16 KB "
                "alignment, but some LIEF builds relocate the program headers or invent an extra "
                "4 KB-aligned LOAD when the append does not fit the existing layout. LIEF 1.0.0 "
                "is verified clean on all three artifacts - upgrade with "
                "`pip install -U 'lief>=1.0'` and re-pack. See docs/TROUBLESHOOTING.md §16 KB.")
    if binary.get(_tag("TEXTREL")) is not None:
        raise InjectError("output has DT_TEXTREL (text relocations) - must be absent")


def _self_verify_provider(provider_path: str, abi: str, pack: PackKey) -> None:
    """Assert every invariant the thin helpers depend on in the SHARED provider.

    Kept separate from `_self_verify_wbaes` because the provider is emitted once per ABI, after
    the per-target loop - a per-target verifier structurally cannot see it."""
    name = os.path.basename(provider_path)
    b = lief.parse(provider_path)
    if b is None:
        raise InjectError(f"re-parse of emitted provider {name} failed")

    # (a) DT_SONAME survived the emit unchanged. Every thin helper's DT_NEEDED is this string.
    soname = _dynamic_soname(b)
    if soname != PROVIDER_SONAME:
        raise InjectError(
            f"emitted provider {name} has DT_SONAME {soname!r}, expected {PROVIDER_SONAME!r} - "
            "the emit must not rename it, or every thin helper's DT_NEEDED dangles")

    # (b) it still exports exactly the one entry point, read the way bionic resolves it.
    exported = _exported_dynsyms(provider_path)
    if PROVIDER_ENTRY not in exported:
        raise InjectError(
            f"emitted provider {name} no longer exports {PROVIDER_ENTRY} - no thin helper could "
            "resolve against it, and bionic would fail every target's dlopen")

    # (c) bionic-only dependencies (the provider is the bottom of the chain).
    stray = [n for n in _needed_names(b) if n not in _BIONIC_ALLOWED]
    if stray:
        raise InjectError(f"emitted provider {name} has non-bionic DT_NEEDED {stray}")

    # (d) the region round-trips, and is a PROVIDER region rather than a target one.
    r = WbRegion.unpack(_extract_region(provider_path, WB_REGION_MAGIC))
    if r.blob != pack.blob or r.wpass != pack.wpass:
        raise InjectError(f"emitted provider {name} region does not round-trip")
    # blob >= WHITEN_SPAN is a precondition, not a nicety: the passphrase's whitening key is
    # derived from the blob's first WHITEN_SPAN bytes, so a shorter blob reads past it on device.
    if len(r.blob) < WHITEN_SPAN or len(r.wpass) == 0:
        raise InjectError(f"emitted provider {name} region blob/pass missing or too short")

    # (e) the long-term key must never reach any output. Cheap byte-scan, and the one check that
    # would catch a refactor accidentally packing PackKey.kek instead of PackKey.blob.
    with open(provider_path, "rb") as f:
        blob_bytes = f.read()
    if pack.kek in blob_bytes:
        raise InjectError(
            f"emitted provider {name} CONTAINS THE LONG-TERM KEY in cleartext - the whole point "
            "of the white-box is that this key is never reconstructable from what ships")

    _assert_16k_and_no_textrel(b, abi, what=f"the emitted shared provider {name}")


def _extract_region(helper_path: str, magic_int: int = REGION_MAGIC) -> bytes:
    """Read an appended region back out of an emitted artifact by locating the read-only
    PT_LOAD whose file bytes start with the region magic (mirrors the ctor's magic-scan).

    `magic_int` selects the kind: REGION_MAGIC ('SRTT', a thin helper's target region) or
    WB_REGION_MAGIC ('SRTW', the provider's). They differ so neither can be mistaken for the
    other - passing the wrong one finds nothing rather than parsing garbage."""
    magic = magic_int.to_bytes(4, "little")
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
    raise InjectError(
        f"could not find a region segment with magic {magic!r} in "
        f"{os.path.basename(helper_path)}")


def inject_so(in_path: str, out_path: str, abi: str,
              cipher: str = "chacha20", log: bool = False,
              wb_keygen: str | None = None,
              target_name: str | None = None,
              allow_helper_log: bool = False,
              pack_key: "PackKey | None" = None) -> InjectResult:
    if CIPHER_IDS[cipher] == CIPHER_WBAES:
        return _inject_wbaes(in_path, out_path, abi, wb_keygen, target_name,
                             allow_helper_log=allow_helper_log, pack_key=pack_key)
    stub: Stub = load_stub(abi)
    cipher_id = CIPHER_IDS[cipher]
    # Whitening span: the WHITEN_SPAN stub bytes immediately before g_decinfo - real
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
            f"whitening span is low-entropy ({len(set(whiten_span))} distinct bytes) - "
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
    # (chaining the original). Otherwise we ADD a DT_INIT in place - even when the library
    # has a DT_INIT_ARRAY.
    #
    # We deliberately never hijack DT_INIT_ARRAY. On PIC libraries (every Android .so) each
    # INIT_ARRAY slot is filled at load time by an R_*_RELATIVE relocation, so the file slot
    # reads 0 and any pointer we write there is silently reverted by the loader (the
    # relocation addend wins) - the stub never runs and the still-encrypted constructor
    # executes as garbage (SIGILL). A DT_INIT entry lives in .dynamic, is NOT relocated
    # (bionic adds load_bias to d_ptr directly), and soinfo::call_constructors invokes
    # DT_INIT BEFORE DT_INIT_ARRAY - so our stub decrypts .text first and the library's own
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
    following zero word as the new terminator - the same in-place trick as
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
    runtime) as the new terminator - then formally extend PT_DYNAMIC/.dynamic to
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
        # and IGNORE that entry's d_val - so the slot qualifies as a terminator when only
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
    # FILE must equal the pristine blob span the packer whitened with - because that is the
    # exact region the stub re-checksums at runtime. If LIEF (or any write) perturbed it,
    # the stub would derive a different key and fail open on-device; catch it here instead.
    file_span = file_bytes[decinfo_off - WHITEN_SPAN:decinfo_off]
    if file_span != whiten_span:
        raise InjectError("whitening span differs in output - a pack-time write hit the "
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
        raise InjectError("decinfo magic still present in output - whitening did not take")

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
        raise InjectError("output has DT_TEXTREL (text relocations) - must be absent")
    # Loader-aware hook check. The ONLY strategies we emit are DT_INIT-inplace and
    # DT_INIT-hijack; both must leave DT_INIT pointing at the stub entry. DT_INIT is the
    # FIRST thing soinfo::call_constructors runs (before DT_INIT_ARRAY) and is not subject
    # to relocation, so this is exactly what the loader will call first - unlike a file-slot
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
    are writing the right spot), then write the whitened record - after which the magic no
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
