"""Provider-neutral model gateway (INVS-07, INVS-11; ADR 0012).

* A run is bound to one approved route at creation (provider, model, endpoint origin, region, maximum data
  classification). The gateway only ever calls that binding. If the route is disabled, its destination is no longer
  registered, or the provider fails, the run ends incomplete or failed; it **never** falls back to another provider,
  model or region.
* The endpoint origin must be a registered destination of the installation (``AXIOM_MODEL_DESTINATIONS``). The fake
  provider is refused in production.
* Every prompt is redacted (``redaction.py``) and the number of redactions is recorded. Content above the route's
  classification never reaches the prompt (the runner withholds it and records the limitation).
* Usage is recorded per call (tokens as reported by the provider, or estimated and labelled so for the fake), with
  cost from the route's prices. Retries are bounded by the route and run budgets and recorded as separate steps.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from .providers import (AnthropicMessagesProvider, DeterministicFakeProvider, ModelRequest, ModelResponse,
                        ProviderError)
from .redaction import redact


class GatewayRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class CallResult:
    response: ModelResponse | None
    error: ProviderError | None
    latency_ms: int
    redactions: int
    cost_micros: int


class ModelGateway:
    def __init__(self, *, env: str, model_destinations: frozenset[str], secrets, transport: httpx.BaseTransport | None = None,
                 fake_sleep=time.sleep):
        self.env, self.destinations, self.secrets = env, model_destinations, secrets
        self.transport, self.fake_sleep = transport, fake_sleep
        self._fakes: dict[str, DeterministicFakeProvider] = {}

    def check_binding(self, binding: dict) -> None:
        if binding["provider"] == "deterministic_fake":
            if self.env == "production":
                raise GatewayRefused("fake_in_production", "the deterministic fake provider is not permitted in production")
            return
        if binding["endpoint"].rstrip("/") not in self.destinations:
            raise GatewayRefused("destination_not_registered",
                                 f"{binding['endpoint']} is not a registered model destination")

    def _provider(self, binding: dict, run_key: str):
        self.check_binding(binding)
        if binding["provider"] == "deterministic_fake":
            # one instance per run so scripted behaviours (e.g. malformed once) are per run
            if run_key not in self._fakes:
                self._fakes[run_key] = DeterministicFakeProvider(binding["model"], sleep=self.fake_sleep)
            return self._fakes[run_key]
        if binding["provider"] == "anthropic_messages":
            ref = binding.get("credential_ref")
            if not ref:
                raise GatewayRefused("no_credential", "route has no credential reference")
            return AnthropicMessagesProvider(binding["endpoint"], binding["model"], lambda: self.secrets.resolve(ref),
                                             transport=self.transport)
        raise GatewayRefused("unknown_provider", f"unknown provider {binding['provider']}")

    def call(self, binding: dict, *, run_key: str, system: str, user: str, timeout_seconds: float) -> CallResult:
        system_r, n1 = redact(system)
        user_r, n2 = redact(user)
        provider = self._provider(binding, run_key)
        started = time.monotonic()
        try:
            resp = provider.complete(ModelRequest(system=system_r, user=user_r,
                                                  max_output_tokens=binding["max_output_tokens"],
                                                  timeout_seconds=timeout_seconds))
            err = None
        except ProviderError as exc:
            resp, err = None, exc
        latency = int((time.monotonic() - started) * 1000)
        cost = 0
        if resp is not None:
            cost = (resp.input_tokens * binding["input_price_micros_per_mtok"]
                    + resp.output_tokens * binding["output_price_micros_per_mtok"]) // 1_000_000
        return CallResult(resp, err, latency, n1 + n2, cost)
