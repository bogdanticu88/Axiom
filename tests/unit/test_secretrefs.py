"""Secret references (axiom.secretrefs): mounted files everywhere, environment variables outside production."""
from __future__ import annotations

import os

import pytest

from axiom.errors import ConfigurationError
from axiom.secretrefs import SecretRefResolver


@pytest.fixture()
def secrets_dir(tmp_path):
    d = tmp_path / "run-secrets"
    d.mkdir()
    (d / "oidc").write_text("s3cret-value\n")
    return d


def test_file_reference_resolves_in_production(secrets_dir):
    r = SecretRefResolver(env="production", file_dirs=(str(secrets_dir),))
    assert r.resolve(f"secretref:file{secrets_dir}/oidc") == "s3cret-value"


def test_kubernetes_style_symlinks_inside_the_directory_are_followed(secrets_dir):
    data = secrets_dir / "..2026_10_22"
    data.mkdir()
    (data / "client").write_text("v")
    (secrets_dir / "client").symlink_to(data / "client")
    assert SecretRefResolver(env="production", file_dirs=(str(secrets_dir),)).resolve(
        f"secretref:file{secrets_dir}/client") == "v"


@pytest.mark.parametrize("make,ref_suffix,message", [
    (lambda d: None, "/missing", "did not resolve"),
    (lambda d: (d / "empty").write_text("\n"), "/empty", "empty"),
    (lambda d: (d / "big").write_text("x" * 5000), "/big", "too large"),
    (lambda d: (d / "dir").mkdir(), "/dir", "regular file"),
])
def test_bad_secret_files_fail_closed(secrets_dir, make, ref_suffix, message):
    make(secrets_dir)
    with pytest.raises(ConfigurationError, match=message):
        SecretRefResolver(env="production", file_dirs=(str(secrets_dir),)).resolve(
            f"secretref:file{secrets_dir}{ref_suffix}")


def test_files_outside_the_allowed_directories_and_escaping_links_are_refused(secrets_dir, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.write_text("x")
    (secrets_dir / "escape").symlink_to(outside)
    r = SecretRefResolver(env="production", file_dirs=(str(secrets_dir),))
    for ref in (f"secretref:file{outside}", f"secretref:file{secrets_dir}/escape",
                f"secretref:file{secrets_dir}/../elsewhere", "secretref:filerelative/path"):
        with pytest.raises(ConfigurationError):
            r.resolve(ref)


def test_environment_references_only_outside_production(monkeypatch):
    monkeypatch.setenv("AXIOM_TEST_SECRET_X", "dev-value")
    assert SecretRefResolver(env="development").resolve("secretref:env/AXIOM_TEST_SECRET_X") == "dev-value"
    with pytest.raises(ConfigurationError, match="not permitted in production"):
        SecretRefResolver(env="production").resolve("secretref:env/AXIOM_TEST_SECRET_X")


def test_errors_never_contain_the_value(secrets_dir):
    (secrets_dir / "big").write_text("TOPSECRET" * 600)
    with pytest.raises(ConfigurationError) as err:
        SecretRefResolver(env="production", file_dirs=(str(secrets_dir),)).resolve(
            f"secretref:file{secrets_dir}/big")
    assert "TOPSECRET" not in str(err.value)
    _ = os
