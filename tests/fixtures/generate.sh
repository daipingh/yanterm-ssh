#!/usr/bin/env bash
# Generates host key fixtures with ssh-keygen and reference signatures with
# Python cryptography (OpenSSH private keys), so the parser and verifier are
# tested against real OpenSSH public blobs and real signatures over message.bin.
set -euo pipefail
cd "$(dirname "$0")"
rm -f id_* *.pub *.blob *.sig *.seed message.bin

head -c 100 /dev/urandom > message.bin
for t in ed25519 ecdsa rsa; do
    ssh-keygen -q -t "$t" -N '' -C "yanterm-ssh test" -f "id_$t"
done
# The second field of a .pub line is the base64 of the wire blob.
for t in ed25519 ecdsa rsa; do
    awk '{print $2}' "id_$t.pub" | base64 -d > "$t.blob"
done

python3 <<'PY'
from pathlib import Path
import base64
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    PrivateFormat,
    NoEncryption,
    Encoding,
    PublicFormat,
    load_ssh_private_key,
)

msg = Path("message.bin").read_bytes()


def ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def ssh_mpint(i: int) -> bytes:
    if i == 0:
        return ssh_string(b"")
    length = (i.bit_length() + 8) // 8
    raw = i.to_bytes(length, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return ssh_string(raw)


# ed25519: raw seed for Task 7 signing_key path + SSH signature blob
ed_priv = load_ssh_private_key(Path("id_ed25519").read_bytes(), password=None, backend=default_backend())
ed_sig = ed_priv.sign(msg)
assert len(ed_sig) == 64
ed_pub = ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
# OpenSSH stores seed||pub in the private key; cryptography exposes seed via
# private_bytes Raw.
ed_seed = ed_priv.private_bytes(
    encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
)
assert len(ed_seed) == 32
Path("ed25519.seed").write_bytes(ed_seed)
Path("ed25519.sig").write_bytes(ssh_string(b"ssh-ed25519") + ssh_string(ed_sig))
assert Path("ed25519.blob").read_bytes() == ssh_string(b"ssh-ed25519") + ssh_string(ed_pub)

# ecdsa-sha2-nistp256
ec_priv = load_ssh_private_key(Path("id_ecdsa").read_bytes(), password=None, backend=default_backend())
ec_der = ec_priv.sign(msg, ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(ec_der)
ec_inner = ssh_mpint(r) + ssh_mpint(s)
Path("ecdsa.sig").write_bytes(ssh_string(b"ecdsa-sha2-nistp256") + ssh_string(ec_inner))

# rsa-sha2-256 (pubkey blob name remains ssh-rsa)
rsa_priv = load_ssh_private_key(Path("id_rsa").read_bytes(), password=None, backend=default_backend())
rsa_sig = rsa_priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
Path("rsa.sig").write_bytes(ssh_string(b"rsa-sha2-256") + ssh_string(rsa_sig))

print("fixtures ok:",
      "ed25519", len(Path("ed25519.blob").read_bytes()),
      "ecdsa", len(Path("ecdsa.blob").read_bytes()),
      "rsa", len(Path("rsa.blob").read_bytes()))
PY
