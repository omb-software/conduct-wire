"""conduct-wire — inbound signed-request verification for the OMB estate.

ONE implementation of the verify half, so CON and Fix cannot drift. The drift already bit once:
Fix consumed nonces BEFORE verifying signatures (FIX-NONCE-ORDER-1), which is a denial-of-service
an attacker mounts with garbage signatures. This package exists so that ordering is decided in one
place and pinned by one mutant test.

Deliberately NOT part of `orc_wire`: that stays the estate's pure crypto/canonical-message
primitive. This is the *policy* layer above it — freshness, replay, ordering — and it delegates
every canonical-message and signature concern back to `orc_wire` rather than reimplementing any of
it. One canonical message, two layers, no second convention.

Deliberately free of any application import. Fix reuses this for site→Fix intake, which must never
couple to CON's deploy, so nothing here may know about Settings, principals, HTTP frameworks or
databases. The caller supplies the expected machine id and public key; the caller decides what a
failure means on the wire.
"""

from conduct_wire.verify import (
    MAX_CLOCK_SKEW_SECONDS,
    NonceWindow,
    SignedRequest,
    WireVerificationError,
    verify_signed_request,
)

__all__ = [
    "MAX_CLOCK_SKEW_SECONDS",
    "NonceWindow",
    "SignedRequest",
    "WireVerificationError",
    "verify_signed_request",
]
