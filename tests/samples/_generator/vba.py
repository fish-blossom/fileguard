"""Minimal VBA project (vbaProject.bin) writer: MS-OVBA dir stream + compressed module source, packed with `gsf createole`.
Source text only; no p-code, nothing executable without Office + macros enabled."""
import os, struct, subprocess, tempfile, uuid

def ovba_compress(data: bytes) -> bytes:
    out = bytearray(b"\x01")
    for i in range(0, len(data), 4096):
        chunk = data[i:i + 4096]
        if len(chunk) == 4096:                 # raw (uncompressed) chunk
            out += struct.pack("<H", 0x3000 | 0x0FFF) + chunk
        else:                                  # literal-only compressed chunk
            body = bytearray()
            for j in range(0, len(chunk), 8):
                body += b"\x00" + chunk[j:j + 8]
            out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)

def _rec(rid, payload=b""):
    return struct.pack("<HI", rid, len(payload)) + payload

def dir_stream(modules):
    d = bytearray()
    d += _rec(0x01, struct.pack("<I", 1)) + _rec(0x02, struct.pack("<I", 0x409)) + _rec(0x14, struct.pack("<I", 0x409))
    d += _rec(0x03, struct.pack("<H", 1252)) + _rec(0x04, b"VBAProject")
    d += _rec(0x05) + _rec(0x40) + _rec(0x06) + _rec(0x3D)
    d += _rec(0x07, struct.pack("<I", 0)) + _rec(0x08, struct.pack("<I", 0))
    d += struct.pack("<HIIH", 0x09, 4, 1, 0)
    d += _rec(0x0C) + _rec(0x3C)
    d += _rec(0x0F, struct.pack("<H", len(modules))) + _rec(0x13, struct.pack("<H", 0xFFFF))
    for name, _src, doc in modules:
        n = name.encode()
        d += _rec(0x19, n) + _rec(0x47, name.encode("utf-16le"))
        d += _rec(0x1A, n) + _rec(0x32, name.encode("utf-16le"))
        d += _rec(0x1C) + _rec(0x48)
        d += _rec(0x31, struct.pack("<I", 0)) + _rec(0x1E, struct.pack("<I", 0)) + _rec(0x2C, struct.pack("<H", 0xFFFF))
        d += _rec(0x22 if doc else 0x21) + _rec(0x2B)
    d += _rec(0x10)
    return ovba_compress(bytes(d))

def build(modules, out_path):
    """modules: list of (name, source_text, is_document_module)"""
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(f"{t}/VBA")
        proj = [f'ID="{{{str(uuid.uuid4()).upper()}}}"']
        for name, src, doc in modules:
            proj.append(f"Document={name}/&H00000000" if doc else f"Module={name}")
            with open(f"{t}/VBA/{name}", "wb") as f:
                f.write(ovba_compress(f'Attribute VB_Name = "{name}"\r\n{src}'.replace("\r\n", "\n").replace("\n", "\r\n").encode("cp1252")))
        proj += ['Name="VBAProject"', 'HelpContextID="0"', 'VersionCompatible32="393222000"', 'CMG=""', 'DPB=""', 'GC=""', "", "[Host Extender Info]", "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000", ""]
        open(f"{t}/PROJECT", "wb").write("\r\n".join(proj).encode())
        open(f"{t}/PROJECTwm", "wb").write(b"".join(n.encode() + b"\0" + n.encode("utf-16le") + b"\0\0" for n, _, _ in modules) + b"\0\0")
        open(f"{t}/VBA/_VBA_PROJECT", "wb").write(b"\xcc\x61\xff\xff\x00\x00\x00")
        open(f"{t}/VBA/dir", "wb").write(dir_stream(modules))
        subprocess.run(["gsf", "createole", out_path, f"{t}/PROJECT", f"{t}/PROJECTwm", f"{t}/VBA"], check=True, capture_output=True)
