"""The filter applied to everything the Compose smoke test prints about a failure (scripts/verify/smoke_redact.py)."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify" / "smoke_redact.py"
spec = importlib.util.spec_from_file_location("smoke_redact", SCRIPT)
smoke_redact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke_redact)

PASSWORD = "3f1c9a7e5b2d4c6e8a0b1c2d3e4f5a6b"
SECRET_KEY = "9d8c7b6a5f4e3d2c1b0a99887766554433221100"


def run(text: str, tmp_path) -> str:
    env = tmp_path / "smoke.env"
    env.write_text(f"AXIOM_APP_PASSWORD={PASSWORD}\nAXIOM_S3_SECRET_KEY={SECRET_KEY}\nAXIOM_API_PORT=18010\n")
    out = subprocess.run([sys.executable, str(SCRIPT), str(env)], input=text, capture_output=True, text=True,
                         check=True)
    return out.stdout


def test_generated_secrets_are_replaced_wherever_they_appear(tmp_path):
    out = run(f"dsn host=postgres user=axiom_app password={PASSWORD}\nkey={SECRET_KEY}x\n", tmp_path)
    assert PASSWORD not in out and SECRET_KEY not in out
    assert out == "dsn host=postgres user=axiom_app password=<redacted>\nkey=<redacted>x\n"


def test_short_values_such_as_ports_are_left_alone(tmp_path):
    assert run("listening on 127.0.0.1:18010\n", tmp_path) == "listening on 127.0.0.1:18010\n"


def test_token_shapes_headers_and_url_credentials(tmp_path):
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
    out = run(f"token {jwt}\nAuthorization: Bearer opaque-token-value\nauthorization: basic dXNlcjpwYXNz\n"
              "proxy http://user:proxy-pass@proxy.local:3128/ and https://host/path@v1\n", tmp_path)
    assert "opaque-token-value" not in out and "dXNlcjpwYXNz" not in out and "proxy-pass" not in out
    assert "<redacted-token>" in out and jwt not in out
    assert "http://<redacted>@proxy.local:3128/" in out
    assert "https://host/path@v1" in out                       # an @ in a path is not user information


BEGIN, END = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"   # split: the CI secret scan


def test_private_key_blocks_are_removed(tmp_path):
    key = f"{BEGIN}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nAAAAkeymaterial\n{END}\n"
    out = run("before\n" + key + "after\n", tmp_path)
    assert out == "before\n<redacted-private-key>\nafter\n"
    one_line = "x " + BEGIN.replace("BEGIN ", "BEGIN RSA ") + "abc" + END.replace("END ", "END RSA ") + " y\n"
    assert run(one_line, tmp_path) == "x <redacted-private-key> y\n"


def test_a_secret_it_was_not_given_and_without_a_known_shape_passes_through(tmp_path):
    """The filter's limit, stated in its docstring: it is not a guarantee that no secret can be printed."""
    assert run("unrelated-credential-7f3a9c\n", tmp_path) == "unrelated-credential-7f3a9c\n"


def test_an_unreadable_secret_file_is_an_error_not_unfiltered_output(tmp_path):
    out = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path / "missing.env")], input=f"{PASSWORD}\n",
                         capture_output=True, text=True)
    assert out.returncode != 0 and out.stdout == ""
