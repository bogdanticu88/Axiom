"""Development identity helper. NOT an identity provider and never for production.

Production configuration refuses inline JWKS (see config.Settings), so keys and
tokens produced here cannot authenticate against a production installation.

  python -m axiom.devtools keygen --dir .var/dev-idp
  python -m axiom.devtools issuer-config --dir .var/dev-idp     # AXIOM_TRUSTED_ISSUERS_JSON value
  python -m axiom.devtools mint --dir .var/dev-idp --sub alice --ttl 3600
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

DEV_ISSUER = "https://dev-idp.axiom.invalid"
DEV_AUDIENCE = "axiom-api"
KID = "dev-1"


def keygen(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    path = directory / "private.pem"
    path.write_bytes(pem)
    path.chmod(0o600)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=KID, alg="RS256", use="sig")
    (directory / "jwks.json").write_text(json.dumps({"keys": [jwk]}))


def issuer_config(directory: Path) -> str:
    jwks = json.loads((directory / "jwks.json").read_text())
    return json.dumps([{"issuer": DEV_ISSUER, "audience": DEV_AUDIENCE, "jwks": jwks}])


def mint(directory: Path, subject: str, ttl: int) -> str:
    key = serialization.load_pem_private_key((directory / "private.pem").read_bytes(), password=None)
    now = int(time.time())
    return jwt.encode({"iss": DEV_ISSUER, "aud": DEV_AUDIENCE, "sub": subject, "iat": now, "exp": now + ttl},
                      key, algorithm="RS256", headers={"kid": KID})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("keygen", "issuer-config", "mint"):
        p = sub.add_parser(name)
        p.add_argument("--dir", type=Path, required=True)
        if name == "mint":
            p.add_argument("--sub", required=True)
            p.add_argument("--ttl", type=int, default=3600)
    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        keygen(args.dir)
    elif args.cmd == "issuer-config":
        print(issuer_config(args.dir))
    else:
        print(mint(args.dir, args.sub, args.ttl))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
