"""ELF injection engine (LIEF).

Per target .so:
  1. locate `.text`, stream-encrypt its exact bytes in place (length preserving),
  2. append the freestanding stub blob as a fresh R+X PT_LOAD segment,
  3. hijack load-time execution so the stub runs before any encrypted code:
       - DT_INIT present  -> repoint to stub, chain the original,
       - else DT_INIT_ARRAY[0] -> overwrite, chain the original,
       - else add a DT_INIT,
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
    """Hijack an EXISTING DT_INIT / DT_INIT_ARRAY in place (no .dynamic growth, so no
    extra segment is created). Returns (flags, delta_init, strategy) or None if the
    library has no init hook to hijack."""
    init = binary.get(_tag("INIT"))
    if init is not None and init.value != 0:
        orig = init.value
        init.value = entry_rva
        return FLAG_CHAIN_INIT, orig - decinfo_rva, "DT_INIT-hijack"

    init_array = binary.get(_tag("INIT_ARRAY"))
    if init_array is not None:
        arr = list(init_array.array)
        if arr:
            orig = arr[0]
            arr[0] = entry_rva
            init_array.array = arr
            if orig != 0:
                return FLAG_CHAIN_INIT, orig - decinfo_rva, "DT_INIT_ARRAY[0]-hijack"
            return 0, 0, "DT_INIT_ARRAY[0]-fill"
    return None


def inject_so(in_path: str, out_path: str, abi: str,
              cipher: str = "chacha20", log: bool = False) -> InjectResult:
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

    # Does the library already have an init hook? If not, we ADD a DT_INIT — but WITHOUT
    # growing .dynamic (which makes LIEF spill it into a small 4 KB-aligned segment that
    # breaks 16 KB loading) and without moving .dynamic into a non-writable segment
    # (which glibc/bionic reject). Instead we overwrite the existing DT_NULL terminator
    # in place with DT_INIT, relying on the zero bytes that follow (.bss / padding) as
    # the new terminator. See _add_dtinit_inplace.
    has_init = (binary.get(_tag("INIT")) is not None
                and binary.get(_tag("INIT")).value != 0)
    ia = binary.get(_tag("INIT_ARRAY"))
    has_init_array = ia is not None and len(list(ia.array)) > 0
    no_init = not has_init and not has_init_array

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
    if no_init:
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

    # --- 5. no-init path: overwrite the DT_NULL terminator with DT_INIT in place ---
    if no_init:
        _add_dtinit_inplace(out_path, entry_rva)

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
                 found_off, strategy)

    return InjectResult(abi=abi, text_rva=text_rva, text_size=text_size,
                        seg_rva=seg_rva, entry_rva=entry_rva,
                        strategy=strategy, cipher=cipher)


_DT_NULL, _DT_INIT, _SHT_DYNAMIC, _PT_DYNAMIC, _PT_LOAD = 0, 12, 6, 2, 1


def _add_dtinit_inplace(path: str, entry_rva: int) -> None:
    """Add a DT_INIT to a library that has no init hook, WITHOUT growing/moving
    .dynamic. We overwrite the existing DT_NULL terminator in place with DT_INIT and
    rely on the zero bytes that follow (.bss / padding, which read as DT_NULL at
    runtime) as the new terminator — then formally extend PT_DYNAMIC/.dynamic to
    include that new terminator so tools agree with the loader. Keeps .dynamic in its
    original (writable, mapped) segment, so no extra or mis-aligned segment is created.
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
                loads.append((p_off, p_filesz))
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

        # the slot AFTER the (to-be-overwritten) terminator becomes the new terminator;
        # it must be zero (reads as DT_NULL) and file-backed within a PT_LOAD (mapped).
        new_term_off = dyn_off + (term + 1) * DYN
        if new_term_off + DYN > len(buf):
            raise InjectError("no room after .dynamic for a new terminator")
        if bytes(buf[new_term_off:new_term_off + DYN]) != b"\x00" * DYN:
            raise InjectError("bytes after .dynamic terminator are non-zero; "
                              "cannot add DT_INIT in place (unsupported layout)")
        if not any(off <= new_term_off and new_term_off + DYN <= off + fsz
                   for off, fsz in loads):
            raise InjectError("new terminator slot is not inside a mapped PT_LOAD")

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
                 seg_rva, expected_decinfo_off, found_decinfo_off, strategy):
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
    if strategy.startswith("DT_INIT-"):
        init = out.get(_tag("INIT"))
        if init is None or int(init.value) != entry_rva:
            raise InjectError("DT_INIT does not point at the stub entry")
    elif strategy.startswith("DT_INIT_ARRAY"):
        arr = out.get(_tag("INIT_ARRAY"))
        if arr is None or not arr.array or int(arr.array[0]) != entry_rva:
            raise InjectError("DT_INIT_ARRAY[0] does not point at the stub entry")


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
