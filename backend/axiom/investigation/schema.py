"""The structured output a model must return each round (validated before anything is stored).

There are deliberately no fields for actions: the model can ask for read-only tool calls, state claims with member
references, and propose next checks. Unknown fields fail validation (``extra='forbid'``), so output such as
``{"dismiss": true}`` or ``{"priority": "low"}`` is malformed rather than ignored.

``model_stated_confidence`` is an uncalibrated label the model chose; it is stored as text and never used as a
probability or in any decision rule.
"""
from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

ATTRIBUTES = ("present_in_deployment", "absent_in_deployment", "affected_component", "severity_as_reported",
              "fix_available", "business_context", "exposure", "other")
MEMBER_KEY = r"^M[0-9]{3,5}$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolRequest(Strict):
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict = Field(default_factory=dict)


class Subject(Strict):
    vulnerability_ref: str | None = Field(default=None, max_length=100)
    asset_id: str | None = Field(default=None, max_length=64)
    asset_version_id: str | None = Field(default=None, max_length=64)   # the deployment, when it matters
    attribute: Literal[ATTRIBUTES]  # type: ignore[valid-type]


class Claim(Strict):
    question_id: str = Field(min_length=1, max_length=32)
    statement: str = Field(min_length=1, max_length=2000)
    subject: Subject
    conclusion: Literal["supported", "contradicted", "unknown"]
    supporting: list[str] = Field(default_factory=list, max_length=20)
    contradicting: list[str] = Field(default_factory=list, max_length=20)
    limitations: str | None = Field(default=None, max_length=2000)
    model_stated_confidence: Literal["low", "medium", "high"] | None = None


class NextCheck(Strict):
    description: str = Field(min_length=1, max_length=1000)
    tool: str | None = Field(default=None, max_length=64)


class RoundOutput(Strict):
    tool_requests: list[ToolRequest] = Field(default_factory=list, max_length=8)
    claims: list[Claim] = Field(default_factory=list, max_length=30)
    next_checks: list[NextCheck] = Field(default_factory=list, max_length=10)
    done: bool


SCHEMA_TEXT = json.dumps(RoundOutput.model_json_schema(), sort_keys=True)


class MalformedOutput(Exception):
    pass


def parse_round(text: str) -> RoundOutput:
    """Parse one model response. A single fenced or bare JSON object is accepted; anything else is malformed."""
    body = text.strip()
    m = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", body, re.S)
    if m:
        body = m.group(1)
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise MalformedOutput(f"not JSON: {exc.msg} at {exc.pos}") from exc
    if not isinstance(data, dict):
        raise MalformedOutput("top level must be an object")
    try:
        out = RoundOutput.model_validate(data)
    except ValidationError as exc:
        raise MalformedOutput("schema: " + "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
                                                     for e in exc.errors()[:5])) from exc
    return out      # references are checked by the claim validator, not here
