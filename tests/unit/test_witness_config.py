"""Worker start-up refuses a missing or unusable restore witness (ADR 0010)."""
from __future__ import annotations

import pytest

from axiom.config import Settings
from axiom.errors import ConfigurationError
from axiom.workers.jobs import build_witness


def settings(**kw):
    return Settings(database_dsn="host=unused", **kw)


def test_production_without_witness_refuses():
    with pytest.raises(ConfigurationError, match="required in production"):
        build_witness(settings(env="production"), "w1")
    with pytest.raises(ConfigurationError, match="required in production"):
        build_witness(settings(env="production", restore_witness="   "), "w1")


def test_development_without_witness_is_allowed_and_explicit():
    assert build_witness(settings(env="development"), "w1") is None


@pytest.mark.parametrize("spec", ["ftp:/tmp/x", "dir:", "dir:   ", "s3:", "s3:/leading-slash", "witness", ":"])
def test_malformed_witness_refuses(spec):
    with pytest.raises(ConfigurationError):
        build_witness(settings(env="production", restore_witness=spec), "w1")


def test_unusable_directory_refuses(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    with pytest.raises(ConfigurationError, match="unusable"):
        build_witness(settings(env="production", restore_witness=f"dir:{blocker}/witness"), "w1")


def test_s3_witness_that_cannot_write_refuses():
    class Denied:
        def put_object(self, **kw):
            raise PermissionError("AccessDenied")
    with pytest.raises(ConfigurationError, match="unusable"):
        build_witness(settings(env="production", restore_witness="s3:bucket/prefix"), "w1", s3_client=Denied())


def test_usable_directory_is_accepted(tmp_path):
    w = build_witness(settings(env="production", restore_witness=f"dir:{tmp_path}/w"), "w1")
    w.advance(5)
    assert w.high_water() == 5
