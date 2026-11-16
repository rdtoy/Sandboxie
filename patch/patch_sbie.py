#!/usr/bin/env python3
# patch_sbie.py - Patch SbieDrv.sys so the certificate is always considered active.
#
# Strategy (x64 only): resolve KphValidateCertificate (function) and
# Verify_CertInfo (global) from the PDB BY SYMBOL NAME, then overwrite the
# first 20 bytes of the function with a leaf stub:
#     mov rax, 0xFFFFFFFFF000F401   ; certified SCertInfo.State
#     mov qword [rip+disp], rax     ; Verify_CertInfo.State = value
#     xor eax, eax                  ; return STATUS_SUCCESS
#     ret
# We replace the whole prologue and return immediately, so the original
# signature/expiry/HWID logic never runs and no Certificate.dat is needed.
# Both anchors come from PDB names -> survives rebuilds as long as the names
# are unchanged and the driver stays x64.
#
# Usage:
#   python patch_sbie.py --sys SbieDrv.sys --pdb SbieDrv.pdb [--out OUT]
#   python patch_sbie.py --sys SbieDrv.sys --pdb SbieDrv.pdb --verify
#   python patch_sbie.py --sys SbieDrv.sys --pdb SbieDrv.pdb --state
import argparse, struct, os, sys
try:
    import pefile
except ImportError:
    sys.exit("ERROR: install pefile in the venv: uv pip install pefile")

# Eternal (type=4) is explicitly exempt from the mandatory cert-refresh check
# in both the UI (SettingsWindow.cpp CertRefreshRequired) and the driver
# (verify.c lock_req check). Developer would trigger the refresh popup on a
# Chinese (0x0804) system; its only perk (MyIsCallerSigned bypass) is already
# covered by test-signing mode, which is required to load this patched driver.
# Fields: active=1, type=4(Eternal), level=7(Max), opt_*=1, expirers=-1.
CERT_STATE = 0xFFFFFFFFF000E401
S_PUB32 = 0x110E
NEEDED = ("KphValidateCertificate", "Verify_CertInfo")
NUL = bytes([0])

class PDB:
    MAGIC = b"Microsoft C/C++ MSF 7.00" + bytes([13, 10, 26]) + b"DS" + bytes([0, 0, 0])
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        if d[:len(self.MAGIC)] != self.MAGIC:
            raise ValueError("Not an MSF 7.00 PDB")
        self.bs = struct.unpack_from("<I", d, 32)[0]
        self.num_dir_bytes = struct.unpack_from("<I", d, 44)[0]
        self.block_map = struct.unpack_from("<I", d, 52)[0]
        self.streams = self._read_streams()
    def _bo(self, b):
        return b * self.bs
    def _read_blocks(self, start_block, nbytes):
        nb = (nbytes + self.bs - 1) // self.bs
        bm = self.data[self._bo(self.block_map):self._bo(self.block_map) + nb * 4]
        blocks = struct.unpack_from("<%dI" % nb, bm, 0)
        return b"".join(self.data[self._bo(b):self._bo(b) + self.bs] for b in blocks)[:nbytes]
    def _read_streams(self):
        d = self._read_blocks(0, self.num_dir_bytes)
        ns = struct.unpack_from("<I", d, 0)[0]
        sizes = struct.unpack_from("<%dI" % ns, d, 4)
        pos = 4 + ns * 4
        streams = []
        for sz in sizes:
            if sz in (0, 0xFFFFFFFF):
                streams.append(b""); continue
            nb = (sz + self.bs - 1) // self.bs
            blks = struct.unpack_from("<%dI" % nb, d, pos)
            pos += nb * 4
            streams.append(b"".join(self.data[self._bo(b):self._bo(b) + self.bs] for b in blks)[:sz])
        return streams
    def dbi_stream(self):
        for s in self.streams:
            if len(s) >= 22 and struct.unpack_from("<I", s, 0)[0] == 0xFFFFFFFF:
                idx = struct.unpack_from("<H", s, 20)[0]
                if idx < len(self.streams) and len(self.streams[idx]) > 1000:
                    return self.streams[idx]
        raise ValueError("Could not locate DBI stream (unusual PDB layout?)")
    def public_symbols(self):
        s = self.dbi_stream(); out = []; p = 0
        while p + 4 <= len(s):
            rl, kind = struct.unpack_from("<HH", s, p)
            if rl < 2 or p + 2 + rl > len(s):
                p += 1; continue
            body = s[p + 4:p + 2 + rl]
            if kind == S_PUB32 and len(body) >= 10:
                off, seg = struct.unpack_from("<IH", body, 4)
                name = body[10:].split(NUL, 1)[0].decode("utf-8", "replace")
                out.append((name, seg, off))
            p += 2 + rl
        return out

def resolve(pdb_path, pe):
    syms = {}
    for name, seg, off in PDB(pdb_path).public_symbols():
        if name in NEEDED and seg > 0:
            syms[name] = pe.sections[seg - 1].VirtualAddress + off
    missing = [n for n in NEEDED if n not in syms]
    if missing:
        raise ValueError("Symbols not found in PDB: " + ", ".join(missing))
    return syms

def build_stub(fn_va, vc_va):
    stub = bytearray(bytes([0x48, 0xB8]) + struct.pack("<Q", CERT_STATE))
    instr_off, instr_len = len(stub), 7
    disp = vc_va - (fn_va + instr_off + instr_len)
    if not -(1 << 31) <= disp < (1 << 31):
        raise ValueError("RIP displacement out of 32-bit range")
    stub += bytes([0x48, 0x89, 0x05]) + struct.pack("<i", disp)
    stub += bytes([0x31, 0xC0])  # xor eax,eax
    stub += bytes([0xC3])        # ret
    return bytes(stub)

def looks_like_stub(b):
    # mov rax, imm64 ; mov [rip+disp], rax ; xor eax,eax ; ret
    return (len(b) == 20
            and b[0:2] == bytes([0x48, 0xB8])
            and b[10:13] == bytes([0x48, 0x89, 0x05])
            and b[17:20] == bytes([0x31, 0xC0, 0xC3]))


def embedded_state(b):
    return struct.unpack_from("<Q", b, 2)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sys", required=True)
    ap.add_argument("--pdb", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--state", action="store_true", help="only print resolved addresses/state")
    ap.add_argument("--force", action="store_true", help="re-patch even if already patched")
    args = ap.parse_args()

    # Read whole file first (bytes); feed pefile from memory so it never holds
    # an mmap/handle on the file. This makes in-place patching (--out == --sys)
    # safe on Windows, where truncating a still-mapped file fails with EINVAL.
    try:
        raw = open(args.sys, "rb").read()
    except OSError as e:
        sys.exit("ERROR: cannot read '%s': %s" % (args.sys, e))
    try:
        pe = pefile.PE(data=raw)
    except pefile.PEFormatError as e:
        sys.exit("ERROR: '%s' is not a valid PE file: %s" % (args.sys, e))
    if pe.OPTIONAL_HEADER.Magic != 0x20b:
        sys.exit("ERROR: only PE32+ (x64) drivers are supported")
    base = pe.OPTIONAL_HEADER.ImageBase
    try:
        syms = resolve(args.pdb, pe)
    except ValueError as e:
        sys.exit("ERROR: %s" % e)
    fn_rva, vc_rva = syms["KphValidateCertificate"], syms["Verify_CertInfo"]
    fn_va, vc_va = base + fn_rva, base + vc_rva
    stub = build_stub(fn_va, vc_va)
    fo = pe.get_offset_from_rva(fn_rva)
    print("KphValidateCertificate : RVA 0x%x  VA 0x%x  file 0x%x" % (fn_rva, fn_va, fo))
    print("Verify_CertInfo        : RVA 0x%x  VA 0x%x" % (vc_rva, vc_va))
    print("CERT_STATE             : 0x%016X" % CERT_STATE)
    print("stub (%d bytes)        : %s" % (len(stub), stub.hex(" ")))
    if args.state:
        return 0
    data = bytearray(raw)
    original = bytes(data[fo:fo + len(stub)])
    if args.verify:
        ok = original == stub
        print("VERIFY:", "PATCHED" if ok else "NOT PATCHED")
        print("  expected:", stub.hex(" "))
        print("  actual  :", original.hex(" "))
        return 0 if ok else 1
    # safety: target must lie inside .text and have room for the stub
    text = [s for s in pe.sections if s.Name.rstrip(NUL) == b".text"][0]
    if not (text.VirtualAddress <= fn_rva < text.VirtualAddress + text.Misc_VirtualSize):
        sys.exit("ERROR: function RVA not inside .text")
    if len(original) != len(stub):
        sys.exit("ERROR: truncated read at function entry")
    # ---- already-patched handling (friendly, no exception) ----
    if original == stub and not args.force:
        print("Already patched (certificate state 0x%016X); nothing to do." % CERT_STATE)
        return 0
    if original == stub:
        print("Already patched; --force: re-patching anyway ...")
    elif looks_like_stub(original):
        st = embedded_state(original)
        print("File is already patched (embedded certificate state 0x%016X)." % st)
        if not args.force:
            print("Nothing to do. Use --force to re-patch with 0x%016X." % CERT_STATE)
            return 0
        print("--force: re-patching with 0x%016X ..." % CERT_STATE)
    else:
        if original == bytes([0xCC]) * len(stub) or original == bytes([0]) * len(stub):
            sys.exit("ERROR: function entry is all padding/zeros -> wrong symbol?")
        print("original bytes         :", original.hex(" "))
        print("(replacing ENTIRE prologue; stub returns before original body)")
    data[fo:fo + len(stub)] = stub
    out = args.out or (os.path.splitext(args.sys)[0] + ".patched.sys")
    # atomic write: temp file then os.replace, so in-place overwrite works and a
    # partial/failed write never corrupts the driver.
    try:
        tmp = out + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, out)
    except OSError as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        sys.exit("ERROR: cannot write '%s': %s" % (out, e))
    print("Wrote:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
