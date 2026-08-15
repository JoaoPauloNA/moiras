import json

from moiras.__main__ import main
from moiras.harness import SCENARIOS, Scenario, run_gate
from moiras.sanitize import sanitize_value


def test_required_offline_scenarios_are_present():
    names = {scenario.name for scenario in SCENARIOS}
    assert names == {
        "low_disposable_action",
        "non_disposable_environment",
        "sudo_hard_stop",
        "database_drop_hard_stop",
        "broad_delete_hard_stop",
        "edge_panel_rejected",
        "council_veto",
        "council_divergence",
        "observable_progress",
        "probable_inactivity",
        "approval_wait",
        "protected_input_wait",
    }


def test_gate_passes_and_report_is_sanitized():
    result = run_gate()
    assert result.success is True
    assert result.failed == 0
    assert result.passed == result.total == len(SCENARIOS)
    assert sanitize_value(result.to_dict()) == result.to_dict()
    assert result.platform_family in {"POSIX", "WINDOWS", "OTHER"}


def test_failed_expectation_makes_gate_fail_without_exception_content():
    original = SCENARIOS[0]
    broken = Scenario(
        name="expected_failure",
        action=original.action,
        opinions=original.opinions,
        expected_verdict=SCENARIOS[1].expected_verdict,
        expected_recommendation=SCENARIOS[1].expected_recommendation,
    )
    result = run_gate((broken,))
    assert result.success is False
    assert result.failed == 1
    assert result.to_dict()["scenarios"] == [{"scenario": "expected_failure", "passed": False}]


def test_cli_stdout_contains_only_sanitized_json(capsys):
    assert main([]) == 0
    stdout, stderr = capsys.readouterr()
    payload = json.loads(stdout)
    assert payload["success"] is True
    assert sanitize_value(payload) == payload
    assert stderr == ""


def test_cli_json_file_does_not_disclose_destination(tmp_path, capsys):
    destination = tmp_path / "gate-result.json"
    assert main(["--json", str(destination)]) == 0
    stdout, stderr = capsys.readouterr()
    on_disk = json.loads(destination.read_text(encoding="utf-8"))
    assert on_disk == json.loads(stdout)
    assert str(destination) not in stdout
    assert stderr == ""
