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

from dataclasses import dataclass

import lief

from .cipher import CIPHER_IDS, apply_cipher, gen_key_nonce
from .metadata import (DecInfo, FLAG_CHAIN_INIT, FLAG_LOG, FLAG_NEED_ICACHE,
                       MAGIC, VERSION)
from .stubs import Stub, load_stub

# 16 KB — mandatory max-page-size alignment for the injected LOAD segment so the lib
# still loads on 16 KB-page devices (Android 15+, Play requirement).
SEGMENT_ALIGN = 16384


class InjectError(RuntimeError):
    pass


# ---- LIEF enum compatibility shim -------------------------------------------------
def _seg_type_load():
    try:
        return lief.ELF.Segment.TYPE.LOAD
    except AttributeError:
        return lief.ELF.SEGMENT_TYPES.LOAD


def _seg_type_dynamic():
    try:
        return lief.ELF.Segment.TYPE.DYNAMIC
    except AttributeError:
        return lief.ELF.SEGMENT_TYPES.DYNAMIC


def _seg_flags_rx():
    try:
        F = lief.ELF.Segment.FLAGS
    except AttributeError:
        F = lief.ELF.SEGMENT_FLAGS
    return F.R | F.X


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
    loader. Libraries with no DT_INIT get one ADDED instead (see _add_dtinit),
    which bionic invokes before DT_INIT_ARRAY."""
    init = binary.get(_tag("INIT"))
    orig = init.value
    init.value = entry_rva
    return FLAG_CHAIN_INIT, orig - decinfo_rva, "DT_INIT-hijack"


class _NeedGrow(InjectError):
    """Internal signal: the library has no usable DT_INIT, its .dynamic terminator slot is
    unusable, and it has no redundant DT_HASH to repurpose — so the raw post-write add is
    impossible and the caller must retry, adding DT_INIT via LIEF (which grows .dynamic)."""


def inject_so(in_path: str, out_path: str, abi: str,
              cipher: str = "chacha20", log: bool = False) -> InjectResult:
    try:
        return _inject_once(in_path, out_path, abi, cipher, log, grow=False)
    except _NeedGrow:
        # Last-resort fallback (e.g. a gnu-hash-only x86_64 lib with no usable terminator
        # slot): re-inject from scratch, adding a real DT_INIT dynamic entry via LIEF.
        return _inject_once(in_path, out_path, abi, cipher, log, grow=True)


def _inject_once(in_path: str, out_path: str, abi: str, cipher: str,
                 log: bool, grow: bool) -> InjectResult:
    stub: Stub = load_stub(abi)
    cipher_id = CIPHER_IDS[cipher]

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
    # terminator. When that word is a file-backed non-zero value (x86-64's GOT[0]=&_DYNAMIC),
    # we instead repurpose a redundant DT_HASH entry. See _add_dtinit.
    has_init = (binary.get(_tag("INIT")) is not None
                and binary.get(_tag("INIT")).value != 0)
    add_dtinit = not has_init
    if grow and not add_dtinit:
        raise InjectError("grow fallback requested for a library that already has DT_INIT")

    # --- 2a. grow fallback: add the DT_INIT dynamic entry via LIEF FIRST (placeholder
    #        value), so the stub segment placed next — and thus entry_rva — is computed
    #        against the already-grown .dynamic. The value is fixed up below (layout-neutral).
    grow_entry = None
    if grow:
        grow_entry = binary.add(lief.ELF.DynamicEntry(_tag("INIT"), 0))

    # --- 2b. append stub as a fresh R+X LOAD segment (raw blob; magic present) ---
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
    if grow:
        # LIEF wrote a real DT_INIT; just point it at the stub (scalar, no relayout).
        entry_obj = grow_entry if grow_entry is not None else binary.get(_tag("INIT"))
        entry_obj.value = entry_rva
        flags, delta_init, strategy = 0, 0, "DT_INIT-grow-dynamic"
    elif add_dtinit:
        # strategy is decided post-write by _add_dtinit (inplace vs repurpose-hash)
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

    # --- 5. add-DT_INIT path: overwrite the DT_NULL terminator with DT_INIT in place,
    #        or (x86-64 etc.) repurpose a redundant DT_HASH. Returns the strategy used.
    #        Raises _NeedGrow when neither works -> inject_so retries with grow=True. ---
    if add_dtinit and not grow:
        strategy = _add_dtinit(out_path, entry_rva)

    # --- 6. patch decinfo into the output file directly (version-independent) ---
    info = DecInfo(
        cipher_id=cipher_id, flags=flags,
        delta_text=text_rva - decinfo_rva, text_size=text_size,
        delta_init=delta_init, key=key, nonce=nonce,
    )
    found_off = _patch_decinfo(out_path, info)

    # --- 7. desktop self-verification: turn silent on-device failures into errors ---
    _self_verify(out_path, plain, info, cipher_id, key, nonce,
                 text_rva, entry_rva, seg_rva, seg_file_off + stub.decinfo_off,
                 found_off, strategy, abi)

    return InjectResult(abi=abi, text_rva=text_rva, text_size=text_size,
                        seg_rva=seg_rva, entry_rva=entry_rva,
                        strategy=strategy, cipher=cipher)


_DT_NULL, _DT_INIT, _SHT_DYNAMIC, _PT_DYNAMIC, _PT_LOAD = 0, 12, 6, 2, 1
_DT_HASH, _DT_GNU_HASH = 4, 0x6FFFFEF5   # SysV hash / GNU hash dynamic tags


def _add_dtinit(path: str, entry_rva: int) -> str:
    """Add a DT_INIT to a library that has no init hook, WITHOUT growing/moving
    .dynamic, and return the strategy actually used.

    Primary (`DT_INIT-inplace`): overwrite the existing DT_NULL terminator with DT_INIT
    and rely on the zero word that follows (.bss / padding / zero-filled tail, which
    reads as DT_NULL at runtime) as the new terminator — then formally extend
    PT_DYNAMIC/.dynamic to include it so tools agree with the loader.

    Fallback (`DT_INIT-repurpose-hash`): when the word after the terminator is a
    file-backed non-zero value (e.g. x86-64, whose psABI packs a non-zero
    `GOT[0] = &_DYNAMIC` right after .dynamic), the terminator slot cannot be reused.
    Instead repurpose a REDUNDANT `DT_HASH` entry as DT_INIT — valid ONLY when
    `DT_GNU_HASH` is also present (a gnu-hash-only library is a configuration bionic/glibc
    load natively; a sysv-hash-only library would be bricked). This leaves the terminator
    and the entry count untouched, so no PT_DYNAMIC/section resize is needed.

    Either way .dynamic stays in its original (writable, mapped) segment — no extra or
    mis-aligned segment is created. Raises InjectError when neither strategy applies.
    Class-aware raw ELF little-endian surgery (ELF32 for armeabi-v7a, ELF64 otherwise)."""
    import struct
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
        slot_usable = True
        if seg_term + DYN <= c_filesz:
            # file-backed: the d_tag word must already read as zero at runtime
            slot_usable = (struct.unpack_from(DTAG, buf, new_term_off)[0] == _DT_NULL)
        elif seg_term + DYN > ((c_memsz + 0xFFF) & ~0xFFF):
            slot_usable = False                 # past the zero-filled mapped tail
        # else: beyond filesz but within the zero-filled mapped tail -> DT_NULL at runtime

        if slot_usable:
            # PRIMARY: overwrite DT_NULL -> DT_INIT; the following zero word is the new
            # terminator. Formally extend PT_DYNAMIC/.dynamic to cover it.
            struct.pack_into(DPACK, buf, dyn_off + term * DYN, _DT_INIT, entry_rva)
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
            return "DT_INIT-inplace"

        # FALLBACK: terminator slot unusable -> repurpose a redundant DT_HASH (guarded by
        # DT_GNU_HASH presence). Only the DT_HASH slot's tag/value change; the terminator
        # and entry count are left as-is, so no PT_DYNAMIC/.dynamic resize is needed.
        has_gnu_hash = False
        hash_slot = None
        for i in range(dyn_filesz // DYN):
            t = struct.unpack_from(DTAG, buf, dyn_off + i * DYN)[0]
            if t == _DT_GNU_HASH:
                has_gnu_hash = True
            elif t == _DT_HASH:
                hash_slot = dyn_off + i * DYN
        if has_gnu_hash and hash_slot is not None:
            struct.pack_into(DPACK, buf, hash_slot, _DT_INIT, entry_rva)
            f.seek(0)
            f.write(buf)
            return "DT_INIT-repurpose-hash"

        raise _NeedGrow(
            "no usable .dynamic terminator slot after DT_NULL, and no redundant DT_HASH "
            "to repurpose (requires DT_GNU_HASH present) — retrying with LIEF grow")


def _self_verify(path, plain, info, cipher_id, key, nonce, text_rva, entry_rva,
                 seg_rva, expected_decinfo_off, found_decinfo_off, strategy, abi):
    """Re-parse the output and assert every invariant the runtime stub depends on."""
    # (5) magic scan landed exactly where LIEF placed the segment's decinfo.
    if found_decinfo_off != expected_decinfo_off:
        raise InjectError(
            f"decinfo offset mismatch: scan={found_decinfo_off} "
            f"expected={expected_decinfo_off} (LIEF bookkeeping / magic collision)")

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

    # (3) 16 KB page congruence for EVERY LOAD segment — but ONLY on arm64-v8a. 16 KB
    # page-size hardware is arm64-exclusive (Pixel 8+/armv9, Android 15+); those devices
    # are 64-bit-only and cannot execute armeabi-v7a at all, and no shipping x86_64 device
    # runs 16 KB pages either. So congruence with the input's pre-existing 4 KB-aligned
    # LOAD segments (common on 32-bit and some x86_64 libs) is irrelevant off arm64, and
    # enforcing it there would abort a pack over a device class that can't exist. The
    # injected segment itself is always SEGMENT_ALIGN-aligned (line 152) on every ABI.
    load_t = _seg_type_load()
    if abi == "arm64-v8a":
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

    # (3b) PT_DYNAMIC must stay inside a WRITABLE PT_LOAD. The DT_INIT-grow-dynamic
    # fallback adds a dynamic entry via LIEF, which — when .dynamic has no trailing slack
    # (the common real-lib case, e.g. libsurface_util_jni) — RELOCATES .dynamic into a new
    # segment. bionic rejects a library whose .dynamic is not in a loaded, writable range,
    # and self-verify's other checks (round-trip, DT_INIT==entry) are blind to this. So
    # assert containment explicitly. inplace/repurpose leave .dynamic in place -> pass
    # trivially; this makes a future no-slack lib that LIEF mis-lays fail LOUDLY at pack
    # time instead of silently on-device.
    dyn = next((s for s in out.segments if s.type == _seg_type_dynamic()), None)
    if dyn is not None:
        dv, dsz = int(dyn.virtual_address), int(dyn.virtual_size)
        host = next((s for s in out.segments
                     if s.type == load_t and (int(s.flags) & int(F.W))
                     and int(s.virtual_address) <= dv
                     and dv + dsz <= int(s.virtual_address) + int(s.virtual_size)), None)
        if host is None:
            raise InjectError(
                f"PT_DYNAMIC (0x{dv:x}+0x{dsz:x}) is not contained in a writable PT_LOAD "
                f"after {strategy} — the loader would reject this library")

    # (4) the hook actually points at the stub, and no text relocations were introduced.
    if out.get(_tag("TEXTREL")) is not None:
        raise InjectError("output has DT_TEXTREL (text relocations) — must be absent")
    # Loader-aware hook check. The strategies we emit (DT_INIT-hijack, DT_INIT-inplace,
    # DT_INIT-repurpose-hash, DT_INIT-grow-dynamic) must all leave DT_INIT pointing at the
    # stub entry. DT_INIT is the
    # FIRST thing soinfo::call_constructors runs (before DT_INIT_ARRAY) and is not subject
    # to relocation, so this is exactly what the loader will call first — unlike a file-slot
    # INIT_ARRAY value, which a load-time R_*_RELATIVE relocation would overwrite.
    if not strategy.startswith("DT_INIT-"):
        raise InjectError(f"unexpected init strategy {strategy!r}")
    init = out.get(_tag("INIT"))
    if init is None or int(init.value) != entry_rva:
        raise InjectError("DT_INIT does not point at the stub entry")


def _patch_decinfo(path: str, info: DecInfo) -> int:
    """Locate the placeholder decinfo in the freshly written file and overwrite the
    128-byte record with the finalized metadata. The needle is magic+version (8 bytes,
    matching the stub's g_decinfo initializer), which makes a chance collision with
    random encrypted .text negligible. Scanning avoids depending on LIEF's post-add
    file-offset bookkeeping."""
    needle = MAGIC.to_bytes(4, "little") + VERSION.to_bytes(4, "little")
    with open(path, "r+b") as f:
        blob = f.read()
        idx = blob.find(needle)
        if idx < 0:
            raise InjectError("could not locate injected decinfo (magic not found)")
        if blob.find(needle, idx + 1) >= 0:
            raise InjectError("ambiguous decinfo: placeholder signature appears twice")
        f.seek(idx)
        f.write(info.pack())
    return idx
