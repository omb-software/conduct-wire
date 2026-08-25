"""The verify half: freshness → signature → nonce. In that order, and the order is the point.

WHY THE ORDER IS CANONICAL AND NOT A DETAIL. A nonce consumed before the signature is checked lets
an attacker burn nonces with garbage signatures — every burnt nonce is a legitimate request the
real peer can no longer make. Verification must therefore be free of side effects until the caller
is proven to hold the key. Fix shipped the other order once (FIX-NONCE-ORDER-1); this package
exists so the question is answered once, and `tests/test_verify.py` mutates the order to prove the
answer is actually guarded rather than merely written down.

Freshness is checked FIRST, before any crypto, because it is the cheap rejection: a replayed
request from last week costs an Ed25519 verify otherwise, and that is the asymmetry a flood wants.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# ±window. Matches the ORC verifier's freshness rule (ADR-0031) so the two ends of the estate do
# not disagree about what "recent" means.
MAX_CLOCK_SKEW_SECONDS = 300


class WireVerificationError(Exception):
    """The request did not verify.

    Callers must NOT return the detail to the requester — a signature oracle helps an attacker.
    Log it loudly instead: a rotated or mis-registered key has to reach an operator rather than be
    silently retried into."""


@dataclass(frozen=True)
class SignedRequest:
    """One inbound signed request, transport-agnostic on purpose.

    `target_path` is the DOCUMENTED canonical path (a constant the caller supplies), never the URL
    the server happened to receive — so a proxy or mount prefix cannot change what was signed and
    the two ends never have to agree on topology.
    """

    method: str
    target_path: str
    query: str
    body: bytes
    machine_id: str
    timestamp: str
    nonce: str
    signature: str


class NonceWindow:
    """Single-use nonces within the freshness window.

    In-memory and per-process by contract: it is only sound where the deployment enforces a single
    worker, because two workers would each hold half the window and neither would see the other's
    replays. A caller that may run multi-worker needs a shared store, and this class is the wrong
    tool — said here because an in-memory replay guard that silently fragments is worse than none.

    Bounded by pruning on access: entries older than the window are swept on every consume, so the
    dict cannot grow without limit under a flood of distinct nonces.
    """

    def __init__(self, skew_seconds: int = MAX_CLOCK_SKEW_SECONDS) -> None:
        self._skew = skew_seconds
        self._seen: dict[str, float] = {}

    def consume(self, nonce: str, now: float) -> bool:
        """True if `nonce` is unseen within the window (and records it); False if it is a replay."""
        # RETAINED FOR TWICE THE SKEW, and that factor is not slack. Freshness accepts a timestamp
        # anywhere in ±skew, so two requests bearing one nonce can legitimately arrive up to 2×skew
        # apart — a nonce forgotten after only `skew` would be replayable at the edges of exactly
        # the band the freshness check permits. (Carried over from Conduct's original, where the
        # factor was present but its reason was not written down; extracting it is what surfaced
        # the question.)
        cutoff = now - 2 * self._skew
        for seen_nonce, seen_at in list(self._seen.items()):
            if seen_at < cutoff:
                del self._seen[seen_nonce]
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def reset(self) -> None:
        """Forget every nonce. For tests and for a deliberate operator reset — never on the request
        path, where it would hand an attacker a replay window."""
        self._seen.clear()


def verify_signed_request(
    request: SignedRequest,
    *,
    expected_machine_id: str,
    public_key: str,
    nonce_window: NonceWindow,
    now: float | None = None,
    max_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> None:
    """Verify one inbound signed request, or raise `WireVerificationError`.

    Returns None: this answers a yes/no question and deliberately mints no identity. Who the caller
    becomes is the application's decision, and keeping it out of here is what lets Fix reuse this
    without importing anything of CON's.

    Canonical-message construction and signature verification delegate to `orc_wire` — the estate's
    one implementation — so a signature produced by either end verifies at the other by
    construction rather than by two implementations agreeing.
    """
    from orc_wire.signing import canonical_message, canonical_request_target, verify_signature

    if request.machine_id != expected_machine_id:
        raise WireVerificationError(f"unknown machine {request.machine_id!r}")
    if not (request.timestamp.isdigit() and request.nonce and request.signature):
        raise WireVerificationError("missing/malformed signature headers")

    current = time.time() if now is None else now
    if abs(current - int(request.timestamp)) > max_skew_seconds:
        raise WireVerificationError(f"stale timestamp {request.timestamp} (±{max_skew_seconds}s)")

    target = canonical_request_target(request.target_path, request.query)
    message = canonical_message(
        request.method, target, request.body.decode(), request.timestamp, request.nonce
    )
    if not verify_signature(public_key, message, request.signature):
        raise WireVerificationError(
            f"bad signature for machine {request.machine_id!r} on {request.method} {target}"
        )

    # NONCE LAST. Everything above is side-effect free, so a request that fails any check leaves no
    # trace and burns nothing. Moving this line above the signature check is the FIX-NONCE-ORDER-1
    # defect; `test_verify.py::test_a_bad_signature_burns_no_nonce` is the mutant that catches it.
    if not nonce_window.consume(request.nonce, current):
        raise WireVerificationError(f"replayed nonce on {request.method} {target}")
