#!/usr/bin/env python3
"""Build tests/fixtures/demo: an offline efivarfs tree + TCG event log + live
PCR directory describing a deliberately weak machine, used by docs/demo.svg.

  * PK is a "DO NOT TRUST" reference key (PKfail)
  * KEK carries a test key, db a distro CA, dbx only a handful of hashes
  * shim validation is disabled (MokSBStateRT = 1) and a DKMS MOK is enrolled
  * the event log replays cleanly except PCR4, which the "TPM" disagrees with

Certificates are throwaway self-signed keys generated with openssl.
Usage: python3 tools/make_fixture.py
"""
import hashlib
import os
import struct
import subprocess
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "demo"

EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMAGE_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"
X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
SHA256 = "c1c41626-504c-4092-aca9-41f936934328"
OWNER = "e2ec8b3a-0b53-4b5f-9b8b-6a1f0e5f9c11"

AUTH = 0x27  # NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE
RT = 0x06


def guid(s):
    return uuid.UUID(s).bytes_le


def cert(cn, days=3650):
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={cn}",
             "-days", str(days), "-keyout", f"{d}/k", "-outform", "DER", "-out", f"{d}/c"],
            check=True, capture_output=True)
        return Path(f"{d}/c").read_bytes()


def siglist(sig_type, items):
    size = 16 + len(items[0])
    body = b"".join(guid(OWNER) + i for i in items)
    return guid(sig_type) + struct.pack("<III", 28 + len(body), 0, size) + body


def certs(*ders):
    return b"".join(siglist(X509, [d]) for d in ders)


def var(name, g, attrs, data):
    (OUT / "efivars" / f"{name}-{g}").write_bytes(struct.pack("<I", attrs) + data)


def var_event(g, name, data):
    n = name.encode("utf-16-le")
    return guid(g) + struct.pack("<QQ", len(name), len(data)) + n + data


def image_event(*path_nodes):
    dp = b""
    for p in path_nodes:
        s = (p + "\0").encode("utf-16-le")
        dp += bytes([4, 4]) + struct.pack("<H", len(s) + 4) + s
    dp += bytes([0x7F, 0xFF, 4, 0])
    return struct.pack("<QQQQ", 0x7A000000, 0x1F000, 0, len(dp)) + dp


ALGS = [(0x0004, hashlib.sha1), (0x000B, hashlib.sha256)]


def event(pcr, etype, data, digest_of=None):
    d = data if digest_of is None else digest_of
    out = struct.pack("<III", pcr, etype, len(ALGS))
    for alg, h in ALGS:
        out += struct.pack("<H", alg) + h(d).digest()
    return out + struct.pack("<I", len(data)) + data


def spec_header():
    ev = b"Spec ID Event03\0" + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, len(ALGS))
    for alg, h in ALGS:
        ev += struct.pack("<HH", alg, h().digest_size)
    ev += b"\0"
    return struct.pack("<II", 0, 3) + b"\0" * 20 + struct.pack("<I", len(ev)) + ev


def main():
    (OUT / "efivars").mkdir(parents=True, exist_ok=True)
    pk = cert("DO NOT TRUST - AMI Test PK")
    kek_oem = cert("Contoso Platform KEK 2024")
    kek_test = cert("Contoso Test Key - firmware lab")
    db_os = cert("Northwind Linux Secure Boot CA")
    db_oem = cert("Contoso Platform db 2024")
    mok = cert("DKMS module signing key")

    var("SecureBoot", EFI_GLOBAL, RT, b"\x01")
    var("SetupMode", EFI_GLOBAL, RT, b"\x00")
    var("AuditMode", EFI_GLOBAL, RT, b"\x00")
    var("DeployedMode", EFI_GLOBAL, RT, b"\x00")
    var("PK", EFI_GLOBAL, AUTH, certs(pk))
    var("KEK", EFI_GLOBAL, AUTH, certs(kek_oem, kek_test))
    var("db", IMAGE_DB, AUTH, certs(db_oem, db_os))
    dbx = [hashlib.sha256(f"revoked-{i}".encode()).digest() for i in range(14)]
    var("dbx", IMAGE_DB, AUTH, siglist(SHA256, dbx))
    var("MokListRT", SHIM, RT, certs(mok))
    var("MokSBStateRT", SHIM, RT, b"\x01")

    log = spec_header()
    log += event(0, 0x8, "Contoso UEFI 2.9 v1.07".encode("utf-16-le"))
    log += event(0, 0x80000008, struct.pack("<QQ", 0xFFE00000, 0x200000))
    log += event(7, 0x80000001, var_event(EFI_GLOBAL, "SecureBoot", b"\x01"))
    for name, g, data in [("PK", EFI_GLOBAL, certs(pk)), ("KEK", EFI_GLOBAL, certs(kek_oem, kek_test)),
                          ("db", IMAGE_DB, certs(db_oem, db_os)), ("dbx", IMAGE_DB, siglist(SHA256, dbx))]:
        log += event(7, 0x80000001, var_event(g, name, data))
    for pcr in range(8):
        log += event(pcr, 0x4, b"\0\0\0\0")
    log += event(4, 0x80000007, b"Calling EFI Application from Boot Option")
    log += event(7, 0x800000E0, var_event(IMAGE_DB, "db", guid(OWNER) + db_os))
    log += event(4, 0x80000003, image_event("\\EFI\\BOOT\\BOOTX64.EFI"), digest_of=b"shim")
    log += event(4, 0x80000003, image_event("\\EFI\\distro", "grubx64.efi"), digest_of=b"grub")
    (OUT / "eventlog.bin").write_bytes(log)

    # "Live" PCRs: replay of the log, except PCR4 which something extended
    # outside the log.
    pcrs = {alg: [b"\0" * h().digest_size for _ in range(24)] for alg, h in ALGS}
    p = 0
    p += 4 + 4 + 20
    (n,) = struct.unpack_from("<I", log, p)
    p += 4 + n
    while p < len(log):
        pcr, et, cnt = struct.unpack_from("<III", log, p)
        p += 12
        for _ in range(cnt):
            (alg,) = struct.unpack_from("<H", log, p)
            h = dict(ALGS)[alg]
            d = log[p + 2:p + 2 + h().digest_size]
            p += 2 + h().digest_size
            if et != 3:
                pcrs[alg][pcr] = h(pcrs[alg][pcr] + d).digest()
        (n,) = struct.unpack_from("<I", log, p)
        p += 4 + n
    pcrs[0x000B][4] = hashlib.sha256(pcrs[0x000B][4] + b"unmeasured bootkit stage").digest()
    for alg, name in [(0x0004, "sha1"), (0x000B, "sha256")]:
        d = OUT / "tpm" / f"pcr-{name}"
        d.mkdir(parents=True, exist_ok=True)
        for i, v in enumerate(pcrs[alg]):
            (d / str(i)).write_text(v.hex().upper() + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    os.umask(0o022)
    main()
