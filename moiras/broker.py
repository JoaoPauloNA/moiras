"""M6 -- synthetic capability broker for shadow-mode candidates.

This broker never authorizes, executes, or supplies anything real. It
mints a single-use, short-TTL *synthetic* capability only in response to
a ``CouncilDecision`` whose verdict is already
``SHADOW_AUTOAPPROVE_CANDIDATE`` (``executed=False``, ``mode="shadow"``),
and it never turns that capability into an action: there is no field
for a payload, a command, or a secret anywhere in this module, and
consuming a capability returns a structured status code, never a value.

The broker is in-memory, thread-safe, and process-local. It does not
call a subprocess, a model, or the network, and it does not accept or
emit credentials.

Lifecycle
---------

1. ``mint(decision, ttl_s=...)`` -- only accepted when ``decision`` is a
   ``CouncilDecision`` with ``verdict == SHADOW_AUTOAPPROVE_CANDIDATE``,
   ``executed is False``, and ``mode == "shadow"``. ``ttl_s`` must be a
   real (non-bool), finite number with ``0 < ttl_s <= 60``. Anything
   else raises ``BrokerError`` -- minting is fail-closed.
2. ``consume(capability_id)`` -- looks up the id and returns a
   ``CapabilityReceipt`` whose ``status`` is exactly one of
   ``CONSUMED``, ``EXPIRED``, ``ALREADY_CONSUMED``, or ``UNKNOWN``.
   Consumption is atomic and single-use: a capability that has already
   been consumed or has expired can never transition back to
   ``CONSUMED`` on a later call (replay is fail-closed). An id that was
   never minted, or has been pruned, returns ``UNKNOWN``.
3. ``prune()`` -- removes only capabilities already in a terminal state
   recorded by a prior ``consume()`` call (``CONSUMED`` or ``EXPIRED``).
   It never removes an ``ISSUED`` (live) capability, even if its TTL has
   elapsed according to the injected clock -- expiry is only ever
   *recorded* by ``consume()``, so a capability nobody has tried to
   consume yet is not "finalized" and stays addressable (and correctly
   reported as ``EXPIRED`` rather than ``UNKNOWN``) until someone calls
   ``consume()`` on it.

Both the injectable monotonic clock and the injectable id factory make
the broker deterministic under test: pass a fake zero-argument clock
callable and a fake id factory instead of the real ``time.monotonic``
and ``uuid.uuid4().hex`` defaults.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from .contracts import SCHEMA_VERSION, ContractValidationError, CouncilDecision, Verdict
from .sanitize import SanitizationError, validate_id

__all__ = [
    "BrokerError",
    "ConsumeStatus",
    "SyntheticCapability",
    "CapabilityReceipt",
    "SyntheticCapabilityBroker",
]

_MIN_TTL_S = 0.0
_MAX_TTL_S = 60.0


class BrokerError(ValueError):
    """Raised when a mint or consume request is structurally invalid.

    Minting is fail-closed: any ambiguity about eligibility, TTL, or id
    uniqueness raises rather than silently producing a capability.
    """


class ConsumeStatus(Enum):
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    ALREADY_CONSUMED = "ALREADY_CONSUMED"
    UNKNOWN = "UNKNOWN"


def _require_ttl(ttl_s: object) -> float:
    if isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float)):
        raise BrokerError("ttl_s must be a real number")
    if not math.isfinite(ttl_s):
        raise BrokerError("ttl_s must be finite")
    if not (_MIN_TTL_S < ttl_s <= _MAX_TTL_S):
        raise BrokerError(f"ttl_s must be in ({_MIN_TTL_S}, {_MAX_TTL_S}]")
    return float(ttl_s)


def _read_clock(clock: Callable[[], float]) -> float:
    now = clock()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise BrokerError("clock() must return a number")
    if not math.isfinite(now) or now < 0:
        raise BrokerError("clock() must return a finite number >= 0")
    return float(now)


@dataclass(frozen=True)
class SyntheticCapability:
    """A single-use, short-TTL synthetic capability.

    Carries no payload, command, or secret -- only a sanitized id and
    bounded numeric/boolean metadata. ``synthetic`` and
    ``authorizes_real_action`` are fixed markers, not caller-settable
    policy: constructing one with the "wrong" values raises.
    """

    capability_id: str
    issued_at_monotonic: float
    expires_at_monotonic: float
    ttl_s: float
    synthetic: bool = True
    authorizes_real_action: bool = False
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_id(self.capability_id, field_name="capability_id")

        for field_name in ("issued_at_monotonic", "expires_at_monotonic", "ttl_s"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractValidationError(f"{field_name} must be a number")
            if not math.isfinite(value):
                raise ContractValidationError(f"{field_name} must be finite")
            if value < 0:
                raise ContractValidationError(f"{field_name} must be >= 0")

        if not (_MIN_TTL_S < self.ttl_s <= _MAX_TTL_S):
            raise ContractValidationError(f"ttl_s must be in ({_MIN_TTL_S}, {_MAX_TTL_S}]")
        if self.expires_at_monotonic != self.issued_at_monotonic + self.ttl_s:
            raise ContractValidationError(
                "expires_at_monotonic must equal issued_at_monotonic + ttl_s"
            )

        if self.synthetic is not True:
            raise ContractValidationError("synthetic must always be True")
        if self.authorizes_real_action is not False:
            raise ContractValidationError("authorizes_real_action must always be False")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "issued_at_monotonic": self.issued_at_monotonic,
            "expires_at_monotonic": self.expires_at_monotonic,
            "ttl_s": self.ttl_s,
            "synthetic": self.synthetic,
            "authorizes_real_action": self.authorizes_real_action,
        }


@dataclass(frozen=True)
class CapabilityReceipt:
    """The structured outcome of a ``consume()`` call. Never a value."""

    capability_id: str
    status: ConsumeStatus
    synthetic: bool = True
    authorizes_real_action: bool = False
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_id(self.capability_id, field_name="capability_id")
        if not isinstance(self.status, ConsumeStatus):
            raise ContractValidationError("status must be a ConsumeStatus")
        if self.synthetic is not True:
            raise ContractValidationError("synthetic must always be True")
        if self.authorizes_real_action is not False:
            raise ContractValidationError("authorizes_real_action must always be False")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "status": self.status.value,
            "synthetic": self.synthetic,
            "authorizes_real_action": self.authorizes_real_action,
        }


_ISSUED = "ISSUED"


class SyntheticCapabilityBroker:
    """In-memory, thread-safe broker for synthetic, single-use capabilities.

    Never calls a subprocess, model, or network. Never executes,
    authorizes, cancels, or supplies a credential. The only decisions it
    accepts as mint-eligible are shadow-mode ``SHADOW_AUTOAPPROVE_CANDIDATE``
    ``CouncilDecision`` instances.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        self._clock = clock
        self._id_factory = id_factory
        self._lock = threading.Lock()
        # capability_id -> (state, expires_at_monotonic)
        # state is one of "ISSUED", ConsumeStatus.CONSUMED, ConsumeStatus.EXPIRED
        self._store: dict[str, tuple[object, float]] = {}

    def mint(self, decision: CouncilDecision, *, ttl_s: float) -> SyntheticCapability:
        """Mint a synthetic capability for an already-shadow-approved decision.

        Raises ``BrokerError`` for anything that is not exactly an
        eligible, well-formed request -- there is no partial or implicit
        success path.
        """

        if not isinstance(decision, CouncilDecision):
            raise BrokerError("decision must be a CouncilDecision")
        if decision.verdict != Verdict.SHADOW_AUTOAPPROVE_CANDIDATE:
            raise BrokerError("only SHADOW_AUTOAPPROVE_CANDIDATE decisions may mint a capability")
        if decision.executed is not False or decision.mode != "shadow":
            raise BrokerError("decision must be executed=False, mode='shadow'")

        ttl = _require_ttl(ttl_s)

        try:
            capability_id = validate_id(self._id_factory(), field_name="capability_id")
        except SanitizationError:
            raise BrokerError("id_factory produced an invalid id") from None

        now = _read_clock(self._clock)
        expires_at = now + ttl
        if not math.isfinite(expires_at) or expires_at <= now:
            raise BrokerError("capability expiry must be finite and later than issuance")

        with self._lock:
            if capability_id in self._store:
                raise BrokerError("id_factory produced a colliding capability id")
            self._store[capability_id] = (_ISSUED, expires_at)

        return SyntheticCapability(
            capability_id=capability_id,
            issued_at_monotonic=now,
            expires_at_monotonic=expires_at,
            ttl_s=ttl,
        )

    def consume(self, capability_id: str) -> CapabilityReceipt:
        """Consume a capability exactly once. Returns a structured status.

        Never raises for an unknown, expired, or already-consumed id --
        those are ordinary, expected outcomes represented as data, not
        exceptions. Only a structurally invalid ``capability_id`` (wrong
        type or disallowed charset) raises, since that is a caller
        programming error rather than a broker-state outcome.
        """

        if not isinstance(capability_id, str):
            raise BrokerError("capability_id must be a string")
        validate_id(capability_id, field_name="capability_id")

        now = _read_clock(self._clock)

        with self._lock:
            entry = self._store.get(capability_id)
            if entry is None:
                return CapabilityReceipt(capability_id=capability_id, status=ConsumeStatus.UNKNOWN)

            state, expires_at = entry
            if state == ConsumeStatus.CONSUMED:
                return CapabilityReceipt(
                    capability_id=capability_id, status=ConsumeStatus.ALREADY_CONSUMED
                )
            if state == ConsumeStatus.EXPIRED:
                return CapabilityReceipt(capability_id=capability_id, status=ConsumeStatus.EXPIRED)

            # state is _ISSUED
            if now >= expires_at:
                self._store[capability_id] = (ConsumeStatus.EXPIRED, expires_at)
                return CapabilityReceipt(capability_id=capability_id, status=ConsumeStatus.EXPIRED)

            self._store[capability_id] = (ConsumeStatus.CONSUMED, expires_at)
            return CapabilityReceipt(capability_id=capability_id, status=ConsumeStatus.CONSUMED)

    def prune(self) -> int:
        """Remove only capabilities already finalized by a prior ``consume()``.

        Never removes an ``ISSUED`` entry, even a chronologically expired
        one -- expiry is recorded (and thus becomes "finalized") only via
        ``consume()``. Returns the number of entries removed.
        """

        with self._lock:
            finalized = [
                capability_id
                for capability_id, (state, _expires_at) in self._store.items()
                if state in (ConsumeStatus.CONSUMED, ConsumeStatus.EXPIRED)
            ]
            for capability_id in finalized:
                del self._store[capability_id]
            return len(finalized)
