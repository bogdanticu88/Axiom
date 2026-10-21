"""AES-256-GCM PayloadCodec with a per-tenant key chosen from the serialization context.

Workflow IDs follow `axiom.<tenant_id>.<run_id>`. When the SDK gives the codec a serialization
context (workflow or activity), the tenant is parsed from the workflow ID and that tenant's key is
used. Payloads encoded without a context, or for a tenant without a key, use the "platform" key.
Every encrypted payload names its key id in metadata, so decoding never needs the context.

Keyring format (env SPIKE_CODEC_KEYS): "platform:<64 hex>,tenant-a:<64 hex>,..."
Removing a tenant's key from the keyring makes that tenant's payloads undecodable (crypto-shredding).
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.converter import (
    DataConverter,
    DefaultFailureConverter,
    DefaultFailureConverterWithEncodedAttributes,
    PayloadCodec,
    SerializationContext,
    WithSerializationContext,
)

ENCODING = b"binary/encrypted"
KEY_ID_META = "encryption-key-id"
PLATFORM_KEY = "platform"
KEYS_ENV = "SPIKE_CODEC_KEYS"
ENCODE_FAILURES_ENV = "SPIKE_ENCODE_FAILURES"


def workflow_id_for(tenant_id: str, run_id: str) -> str:
    return f"axiom.{tenant_id}.{run_id}"


def tenant_from_workflow_id(workflow_id: str | None) -> str | None:
    if workflow_id and workflow_id.startswith("axiom."):
        parts = workflow_id.split(".", 2)
        if len(parts) == 3:
            return parts[1]
    return None


def parse_keyring(spec: str) -> dict[str, bytes]:
    ring: dict[str, bytes] = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        kid, hexkey = item.split(":", 1)
        key = bytes.fromhex(hexkey)
        assert len(key) == 32, "AES-256 keys only"
        ring[kid] = key
    return ring


def keyring_spec(ring: dict[str, bytes]) -> str:
    return ",".join(f"{k}:{v.hex()}" for k, v in ring.items())


class TenantAesGcmCodec(PayloadCodec, WithSerializationContext):
    def __init__(self, keyring: dict[str, bytes], tenant: str | None = None, context_kind: str = "none"):
        self.keyring = keyring
        self.tenant = tenant
        self.context_kind = context_kind

    def with_context(self, context: SerializationContext) -> "TenantAesGcmCodec":
        wid = getattr(context, "workflow_id", None)
        return TenantAesGcmCodec(self.keyring, tenant_from_workflow_id(wid), type(context).__name__)

    def _encode_key_id(self) -> str:
        if self.tenant and self.tenant in self.keyring:
            return self.tenant
        return PLATFORM_KEY

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        kid = self._encode_key_id()
        aes = AESGCM(self.keyring[kid])
        out = []
        for p in payloads:
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, p.SerializeToString(), kid.encode())
            out.append(Payload(metadata={"encoding": ENCODING, KEY_ID_META: kid.encode()}, data=nonce + ct))
        return out

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") != ENCODING:
                out.append(p)  # not ours (e.g. written before the codec was enabled)
                continue
            kid = p.metadata[KEY_ID_META].decode()
            if kid not in self.keyring:
                raise KeyError(f"no key for key id {kid!r} (destroyed or never provisioned)")
            plain = AESGCM(self.keyring[kid]).decrypt(p.data[:12], p.data[12:], kid.encode())
            out.append(Payload.FromString(plain))
        return out


def data_converter(keyring: dict[str, bytes] | None, encode_failures: bool) -> DataConverter:
    """Build the converter used by clients and workers. keyring=None means no codec."""
    failure_cls = DefaultFailureConverterWithEncodedAttributes if encode_failures else DefaultFailureConverter
    return DataConverter(
        payload_codec=TenantAesGcmCodec(keyring) if keyring else None,
        failure_converter_class=failure_cls,
    )


def data_converter_from_env() -> DataConverter:
    spec = os.environ.get(KEYS_ENV, "")
    return data_converter(parse_keyring(spec) if spec else None, os.environ.get(ENCODE_FAILURES_ENV) == "1")
