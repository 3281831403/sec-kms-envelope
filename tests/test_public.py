import copy

import pytest

from envelope import (
    EnvelopeError,
    envelope_batch,
    open_sealed,
    seal,
    validate_header,
)

TENANT = "tenant-alpha"
PAYLOAD = b"wire-transfer=100.00;account=6222"


def master(root=PAYLOAD + b"-root", versions=("v1", "v2"), current="v1", retired=()):
    return {
        "root": root,
        "versions": list(versions),
        "current": current,
        "retired": list(retired),
    }


def test_seal_roundtrip_returns_plaintext():
    keys = master()

    first = seal(keys, PAYLOAD, TENANT, "v1")
    second = seal(keys, PAYLOAD, TENANT, "v1")

    assert open_sealed(keys, first, TENANT) == PAYLOAD
    assert open_sealed(keys, second, TENANT) == PAYLOAD
    assert first != second


def test_header_reports_version_and_rejects_out_of_range():
    keys = master()
    sealed = seal(keys, PAYLOAD, TENANT, "v1")
    header = sealed["header"]

    assert header["version"] == "v1"
    assert header["key_id"]
    assert validate_header(header) == []

    oversized = copy.deepcopy(header)
    oversized["version"] = "v" * 40
    assert validate_header(oversized)


def test_cross_tenant_open_is_rejected():
    keys = master()
    sealed = seal(keys, PAYLOAD, TENANT, "v1")

    with pytest.raises(EnvelopeError):
        open_sealed(keys, sealed, "tenant-beta")


def test_tampered_header_is_rejected():
    keys = master()
    sealed = seal(keys, PAYLOAD, TENANT, "v1")
    tampered = copy.deepcopy(sealed)
    tampered["header"]["key_id"] = "k-attacker"

    with pytest.raises(EnvelopeError):
        open_sealed(keys, tampered, TENANT)


def test_batch_items_are_independent():
    first_master = master(root=b"region-one-root-material")
    second_master = master(root=b"region-two-root-material")
    items = [
        {
            "id": "one",
            "master": first_master,
            "plaintext": b"first payload",
            "version": "v1",
        },
        {
            "id": "two",
            "master": second_master,
            "plaintext": b"second payload",
            "version": "v1",
        },
    ]

    batch = envelope_batch(items, TENANT)

    assert batch["errors"] == {}

    reopened = {}
    for name, keys in (("one", first_master), ("two", second_master)):
        try:
            reopened[name] = open_sealed(keys, batch["results"][name], TENANT)
        except EnvelopeError:
            reopened[name] = None

    assert reopened["one"] == b"first payload"
    assert reopened["two"] == b"second payload"