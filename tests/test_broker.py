import threading

import pytest

from moiras.broker import (
    BrokerError,
    CapabilityReceipt,
    ConsumeStatus,
    SyntheticCapability,
    SyntheticCapabilityBroker,
)
from moiras.contracts import ContractValidationError, CouncilDecision, Verdict
from moiras.sanitize import SanitizationError, sanitize_value


class FakeClock:
    def __init__(self, start=0.0):
        self.value = start

    def __call__(self):
        return self.value

    def advance(self, delta):
        self.value += delta


def make_id_factory(*ids):
    iterator = iter(ids)

    def factory():
        return next(iterator)

    return factory


def make_decision(**overrides):
    fields = dict(
        verdict=Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        final_score=1.0,
        council_bypassed=False,
        reason_codes=(),
    )
    fields.update(overrides)
    return CouncilDecision(**fields)


def make_broker(clock=None, id_factory=None):
    kwargs = {}
    if clock is not None:
        kwargs["clock"] = clock
    if id_factory is not None:
        kwargs["id_factory"] = id_factory
    return SyntheticCapabilityBroker(**kwargs)


class TestMintEligibility:
    def test_shadow_autoapprove_candidate_mints(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        cap = broker.mint(make_decision(), ttl_s=10.0)
        assert isinstance(cap, SyntheticCapability)
        assert cap.synthetic is True
        assert cap.authorizes_real_action is False

    @pytest.mark.parametrize(
        "verdict",
        [
            Verdict.STOP_AND_HUMAN,
            Verdict.HUMAN_REQUIRED,
            Verdict.MITIGATE_AND_REASSESS,
        ],
    )
    def test_non_candidate_verdicts_never_mint(self, verdict):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        decision = make_decision(
            verdict=verdict,
            final_score=10.0 if verdict == Verdict.STOP_AND_HUMAN else 5.0,
            council_bypassed=(verdict == Verdict.STOP_AND_HUMAN),
        )
        with pytest.raises(BrokerError):
            broker.mint(decision, ttl_s=10.0)

    def test_rejects_non_council_decision(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        with pytest.raises(BrokerError):
            broker.mint("not-a-decision", ttl_s=10.0)

    def test_colliding_id_factory_output_fails_closed(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1", "cap-1"))
        broker.mint(make_decision(), ttl_s=10.0)
        with pytest.raises(BrokerError):
            broker.mint(make_decision(), ttl_s=10.0)


class TestTtlValidation:
    @pytest.mark.parametrize("bad_ttl", [0.0, -1.0, 60.1, 61, float("inf")])
    def test_rejects_out_of_range_ttl(self, bad_ttl):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        with pytest.raises(BrokerError):
            broker.mint(make_decision(), ttl_s=bad_ttl)

    def test_rejects_nan_ttl(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        with pytest.raises(BrokerError):
            broker.mint(make_decision(), ttl_s=float("nan"))

    def test_rejects_bool_ttl(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        with pytest.raises(BrokerError):
            broker.mint(make_decision(), ttl_s=True)

    def test_accepts_boundary_ttl_of_sixty(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        cap = broker.mint(make_decision(), ttl_s=60.0)
        assert cap.ttl_s == 60.0

    def test_accepts_small_positive_ttl(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        cap = broker.mint(make_decision(), ttl_s=0.001)
        assert cap.ttl_s == 0.001

    @pytest.mark.parametrize("bad_now", [-1.0, float("nan"), float("inf"), True])
    def test_invalid_clock_does_not_leave_a_capability(self, bad_now):
        broker = make_broker(clock=lambda: bad_now, id_factory=lambda: "cap-1")
        with pytest.raises(BrokerError):
            broker.mint(make_decision(), ttl_s=1.0)
        assert broker.prune() == 0

    def test_non_finite_expiry_does_not_leave_a_capability(self):
        broker = make_broker(clock=lambda: 1.79e308, id_factory=lambda: "cap-1")
        with pytest.raises(BrokerError):
            broker.mint(make_decision(), ttl_s=60.0)
        assert broker.prune() == 0


class TestExpiration:
    def test_expired_capability_cannot_be_consumed(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=5.0)
        clock.advance(5.0)
        receipt = broker.consume("cap-1")
        assert receipt.status == ConsumeStatus.EXPIRED

    def test_expired_then_consumed_again_stays_expired(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=5.0)
        clock.advance(10.0)
        first = broker.consume("cap-1")
        second = broker.consume("cap-1")
        assert first.status == ConsumeStatus.EXPIRED
        assert second.status == ConsumeStatus.EXPIRED

    def test_just_before_expiry_is_consumable(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=5.0)
        clock.advance(4.999)
        receipt = broker.consume("cap-1")
        assert receipt.status == ConsumeStatus.CONSUMED

    @pytest.mark.parametrize("bad_now", [-1.0, float("nan"), float("inf"), True])
    def test_invalid_clock_cannot_consume(self, bad_now):
        values = iter([0.0, bad_now])
        broker = make_broker(clock=lambda: next(values), id_factory=lambda: "cap-1")
        broker.mint(make_decision(), ttl_s=5.0)
        with pytest.raises(BrokerError):
            broker.consume("cap-1")


class TestSingleUseAndReplay:
    def test_second_consume_is_already_consumed(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=10.0)
        first = broker.consume("cap-1")
        second = broker.consume("cap-1")
        assert first.status == ConsumeStatus.CONSUMED
        assert second.status == ConsumeStatus.ALREADY_CONSUMED

    def test_replay_after_many_attempts_never_consumes_again(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=10.0)
        broker.consume("cap-1")
        results = [broker.consume("cap-1").status for _ in range(5)]
        assert all(status == ConsumeStatus.ALREADY_CONSUMED for status in results)


class TestUnknown:
    def test_never_minted_id_is_unknown(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        receipt = broker.consume("never-minted")
        assert receipt.status == ConsumeStatus.UNKNOWN

    def test_malformed_capability_id_raises(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        with pytest.raises(SanitizationError):
            broker.consume("bad id with spaces")

    def test_non_string_capability_id_raises(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        with pytest.raises(BrokerError):
            broker.consume(12345)


class TestPrune:
    def test_prune_removes_only_finalized_entries(self):
        clock = FakeClock(0.0)
        broker = make_broker(
            clock=clock, id_factory=make_id_factory("cap-consumed", "cap-live", "cap-expired")
        )
        broker.mint(make_decision(), ttl_s=10.0)
        broker.mint(make_decision(), ttl_s=10.0)
        broker.mint(make_decision(), ttl_s=1.0)
        broker.consume("cap-consumed")
        clock.advance(2.0)
        broker.consume("cap-expired")

        removed = broker.prune()
        assert removed == 2

        assert broker.consume("cap-consumed").status == ConsumeStatus.UNKNOWN
        assert broker.consume("cap-expired").status == ConsumeStatus.UNKNOWN
        # The still-live, never-consumed capability must survive prune.
        assert broker.consume("cap-live").status == ConsumeStatus.CONSUMED

    def test_prune_never_touches_live_issued_capability_even_past_ttl(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=1.0)
        clock.advance(100.0)
        removed = broker.prune()
        assert removed == 0
        # Because nobody called consume() yet, the broker still reports
        # the accurate EXPIRED status rather than UNKNOWN.
        assert broker.consume("cap-1").status == ConsumeStatus.EXPIRED


class TestConcurrency:
    def test_concurrent_consume_yields_exactly_one_winner(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=10.0)

        results = []
        results_lock = threading.Lock()

        def worker():
            receipt = broker.consume("cap-1")
            with results_lock:
                results.append(receipt.status)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(ConsumeStatus.CONSUMED) == 1
        assert results.count(ConsumeStatus.ALREADY_CONSUMED) == 15


class TestSerializationAndSanitization:
    def test_capability_to_dict_passes_sanitize_value(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        cap = broker.mint(make_decision(), ttl_s=10.0)
        serialized = cap.to_dict()
        assert sanitize_value(serialized) == serialized

    def test_receipt_to_dict_passes_sanitize_value(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=10.0)
        receipt = broker.consume("cap-1")
        serialized = receipt.to_dict()
        assert sanitize_value(serialized) == serialized

    def test_capability_has_no_secret_or_action_fields(self):
        broker = make_broker(clock=FakeClock(0.0), id_factory=make_id_factory("cap-1"))
        cap = broker.mint(make_decision(), ttl_s=10.0)
        field_names = set(cap.to_dict().keys())
        forbidden = {"payload", "action", "secret", "command", "credential", "value"}
        assert field_names.isdisjoint(forbidden)

    def test_receipt_never_carries_a_value_field(self):
        clock = FakeClock(0.0)
        broker = make_broker(clock=clock, id_factory=make_id_factory("cap-1"))
        broker.mint(make_decision(), ttl_s=10.0)
        receipt = broker.consume("cap-1")
        assert not hasattr(receipt, "value")
        assert not hasattr(receipt, "payload")
        assert set(receipt.to_dict().keys()) == {
            "schema_version",
            "capability_id",
            "status",
            "synthetic",
            "authorizes_real_action",
        }

    def test_capability_rejects_forged_synthetic_false(self):
        with pytest.raises(ContractValidationError):
            SyntheticCapability(
                capability_id="cap-1",
                issued_at_monotonic=0.0,
                expires_at_monotonic=5.0,
                ttl_s=5.0,
                synthetic=False,
            )

    def test_capability_rejects_forged_authorizes_real_action_true(self):
        with pytest.raises(ContractValidationError):
            SyntheticCapability(
                capability_id="cap-1",
                issued_at_monotonic=0.0,
                expires_at_monotonic=5.0,
                ttl_s=5.0,
                authorizes_real_action=True,
            )

    def test_receipt_rejects_bad_status_type(self):
        with pytest.raises(ContractValidationError):
            CapabilityReceipt(capability_id="cap-1", status="CONSUMED")
