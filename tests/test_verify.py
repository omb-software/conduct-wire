"""The verify half, and above all the ORDER.

The load-bearing test here is `test_a_bad_signature_burns_no_nonce`. Everything else confirms the
happy path and the obvious refusals; that one encodes the reason this package exists, because Fix
shipped the other order (FIX-NONCE-ORDER-1) and a written-down rule with no test is a rule that
comes back.
"""

from __future__ import annotations

import time

import pytest
from orc_wire.signing import canonical_message, canonical_request_target, generate_keypair, sign

from conduct_wire import (
    NonceWindow,
    SignedRequest,
    WireVerificationError,
    verify_signed_request,
)

MACHINE = "fix"


@pytest.fixture
def keys():
    seed, public = generate_keypair()
    return seed, public


def _signed(seed: str, *, nonce="n-1", ts=None, method="GET", path="/fix/v1/outcomes",
            query="", body=b"") -> SignedRequest:
    ts = ts or str(int(time.time()))
    target = canonical_request_target(path, query)
    message = canonical_message(method, target, body.decode(), ts, nonce)
    return SignedRequest(
        method=method, target_path=path, query=query, body=body, machine_id=MACHINE,
        timestamp=ts, nonce=nonce, signature=sign(seed, message),
    )


def _verify(req, public, window, **kw):
    verify_signed_request(
        req, expected_machine_id=MACHINE, public_key=public, nonce_window=window, **kw
    )


def test_a_correctly_signed_request_verifies(keys):
    seed, public = keys
    _verify(_signed(seed), public, NonceWindow())  # no raise


def test_a_bad_signature_burns_no_nonce(keys):
    """THE ordering guard, and the reason this package exists.

    A request that fails signature verification must leave the nonce UNUSED — otherwise an attacker
    with no key denies service by flooding garbage signatures carrying the nonces a legitimate peer
    is about to use. Consume the nonce before verifying and this test goes red; that mutation is
    exactly the FIX-NONCE-ORDER-1 defect.
    """
    seed, public = keys
    window = NonceWindow()
    forged = _signed(seed, nonce="n-shared")
    forged = SignedRequest(**{**forged.__dict__, "signature": "A" * 86})

    with pytest.raises(WireVerificationError, match="bad signature"):
        _verify(forged, public, window)

    # The SAME nonce must still be usable by the real peer.
    _verify(_signed(seed, nonce="n-shared"), public, window)


def test_a_stale_request_burns_no_nonce_either(keys):
    """Freshness is checked before crypto AND before the nonce: a replayed week-old request should
    cost neither an Ed25519 verify nor a nonce."""
    seed, public = keys
    window = NonceWindow()
    old = _signed(seed, nonce="n-old", ts=str(int(time.time()) - 10_000))
    with pytest.raises(WireVerificationError, match="stale"):
        _verify(old, public, window)
    _verify(_signed(seed, nonce="n-old"), public, window)


def test_a_replayed_nonce_is_refused(keys):
    seed, public = keys
    window = NonceWindow()
    _verify(_signed(seed, nonce="dup"), public, window)
    with pytest.raises(WireVerificationError, match="replayed nonce"):
        _verify(_signed(seed, nonce="dup"), public, window)


def test_an_unknown_machine_is_refused(keys):
    seed, public = keys
    req = SignedRequest(**{**_signed(seed).__dict__, "machine_id": "someone-else"})
    with pytest.raises(WireVerificationError, match="unknown machine"):
        _verify(req, public, NonceWindow())


def test_malformed_headers_are_refused(keys):
    seed, public = keys
    for field, bad in (("timestamp", "not-a-number"), ("nonce", ""), ("signature", "")):
        req = SignedRequest(**{**_signed(seed).__dict__, field: bad})
        with pytest.raises(WireVerificationError, match="missing/malformed"):
            _verify(req, public, NonceWindow())


def test_the_query_string_is_signature_covered(keys):
    """The ORC feed GET signs its query; a cursor swapped in flight must not verify."""
    seed, public = keys
    req = _signed(seed, query="cursor=1")
    tampered = SignedRequest(**{**req.__dict__, "query": "cursor=999"})
    with pytest.raises(WireVerificationError, match="bad signature"):
        _verify(tampered, public, NonceWindow())


def test_the_nonce_window_prunes_so_it_cannot_grow_without_bound(keys):
    """A flood of distinct nonces must not be an unbounded memory write."""
    window = NonceWindow(window_seconds=10)
    for i in range(50):
        assert window.consume(f"n{i}", now=1000.0)
    assert len(window._seen) == 50
    window.consume("later", now=1000.0 + 100)
    assert len(window._seen) == 1, "everything outside the window should have been swept"


def test_nothing_in_this_package_imports_an_application(keys):
    """Fix reuses this for site→Fix intake and must never couple to CON's deploy. A stray
    `conduct.` import here would make that impossible, silently."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "conduct_wire"
    offenders = [
        p.name for p in src.rglob("*.py")
        if "import conduct." in p.read_text() or "from conduct." in p.read_text()
    ]
    assert offenders == [], f"application imports leaked into the package: {offenders}"
